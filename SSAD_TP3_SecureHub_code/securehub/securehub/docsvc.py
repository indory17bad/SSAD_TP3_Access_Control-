"""The document service. It does NOT trust callers: every call must carry a proof that only the gateway
can compute (HMAC over user, role, action, object and time with a secret shared with the gateway).
A direct call without proof is refused - this is what 'complete mediation' means in practice."""
import hashlib
import hmac

from . import rbac


class ProofError(Exception):
    pass


class DocumentService:
    def __init__(self, store, secret, clock):
        self.store, self.secret, self.clock = store, secret, clock
        self.vulnerable_bola = False        # lab switch: skip the object-level check to show the flaw

    def make_proof(self, sub, role, action, ref, ts):
        msg = "|".join([sub, role, action, str(ref), str(int(ts))]).encode()
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

    def check_proof(self, sub, role, action, ref, ts, proof):
        try:
            fresh = abs(self.clock() - int(ts)) <= 60
        except (TypeError, ValueError):
            fresh = False
        if not (proof and fresh and hmac.compare_digest(self.make_proof(sub, role, action, ref, ts), proof)):
            raise ProofError("no_gateway_proof")

    def call(self, action, sub, role, ref=None, payload=None, proof=None, ts=None):
        """-> (status, body, reason). Re-checks the object rule (second line of defence)."""
        self.check_proof(sub, role, action, ref, ts, proof)
        user = self.store.get_user(sub)
        pub = self.store.public_user(sub)
        if action == "list":
            docs = [d for d in self.store.docs.values()]
            vis = rbac.visible_documents(role, pub, docs)
            return 200, {"documents": [self._meta(d) for d in vis]}, "ok"
        if action in ("read", "delete"):
            try:
                doc = self.store.docs.get(int(ref))
            except (TypeError, ValueError):
                return 400, {"error": "bad_id"}, "bad_id"
            if doc is None:
                return 404, {"error": "not_found"}, "not_found"
            if action == "read":
                if not self.vulnerable_bola:
                    d = rbac.decide(role, pub, "doc:read", doc=doc)
                    if not d.allowed:
                        return 403, {"error": "forbidden", "reason": d.reason}, d.reason
                return 200, dict(doc), "ok"
            del self.store.docs[doc["id"]]
            return 200, {"deleted": doc["id"]}, "ok"
        if action == "create":
            d = rbac.decide(role, pub, "doc:create", course=payload["course"])
            if not d.allowed:
                return 403, {"error": "forbidden", "reason": d.reason}, d.reason
            return 201, self.store.add_doc(payload["title"], payload["course"], payload["kind"], sub, payload["body"]), "ok"
        return 400, {"error": "bad_action"}, "bad_action"

    @staticmethod
    def _meta(d):
        return {k: d[k] for k in ("id", "title", "course", "kind", "owner")}
