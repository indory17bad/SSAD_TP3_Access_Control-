"""In-memory users and documents (seeded). A real system would use a database."""
import copy

from . import passwords

DEMO_USERS = [
    # username, password, role, courses
    ("alice", "alice-pass-1", "student", ["SSAD", "NET"]),
    ("bob", "bob-pass-2", "student", ["SSAD"]),
    ("carol", "carol-pass-3", "teacher", ["SSAD"]),
    ("dave", "dave-pass-4", "teacher", ["NET"]),
    ("root", "root-pass-5", "administrator", []),
    ("dr_amine", "amine-pass-6", "doctor", []),        # service set below
    ("dr_sofia", "sofia-pass-7", "doctor", []),
    ("lina", "lina-pass-8", "analyst", []),
]
SERVICES = {"dr_amine": "cardiology", "dr_sofia": "oncology"}
PURPOSES = {"doctor": ["care"], "analyst": ["research", "statistics"], "administrator": ["maintenance"]}

DEMO_DOCS = [
    (1, "SSAD lecture 1 - Introduction", "SSAD", "lecture", "carol", "Security of information systems: goals and vocabulary."),
    (2, "SSAD lecture 5 - Access control", "SSAD", "lecture", "carol", "Reference monitor, RBAC, tokens and audit."),
    (3, "SSAD exam 2026 (draft)", "SSAD", "exam", "carol", "Question 1: explain complete mediation. (confidential)"),
    (4, "SSAD grades - alice", "SSAD", "grades", "alice", "alice: 16/20"),
    (5, "SSAD grades - bob", "SSAD", "grades", "bob", "bob: 12/20"),
    (6, "NET lecture 1 - Routing", "NET", "lecture", "dave", "Distance vector and link state."),
    (7, "NET exam 2026 (draft)", "NET", "exam", "dave", "Question 1: compare RIP and OSPF. (confidential)"),
    (8, "NET grades - alice", "NET", "grades", "alice", "alice: 14/20"),
    (9, "Admin: server policy", "-", "admin", "root", "Password policy and key rotation every 90 days."),
    (10, "Admin: backup schedule", "-", "admin", "root", "Nightly backup at 02:00."),
    (11, "SSAD lab sheet TP3", "SSAD", "lecture", "carol", "Build a web platform with access control."),
    (12, "NET lab sheet", "NET", "lecture", "dave", "Packet capture exercise."),
]


class Store:
    def __init__(self, iterations=passwords.ITERATIONS):
        self.iterations = iterations
        self.reset()

    def reset(self):
        self.users = {}
        for name, pw, role, courses in DEMO_USERS:
            self.users[name] = {"username": name, "role": role, "courses": list(courses),
                                "service": SERVICES.get(name), "purposes": list(PURPOSES.get(role, [])),
                                "hash": passwords.hash_password(pw, self.iterations)}
        self.docs = {}
        for i, title, course, kind, owner, body in DEMO_DOCS:
            self.docs[i] = {"id": i, "title": title, "course": course, "kind": kind, "owner": owner, "body": body}
        self.next_id = max(self.docs) + 1
        # verified against when the user does not exist, so both failures cost the same time
        self.dummy_hash = passwords.hash_password("not-a-real-password", self.iterations)

    def get_user(self, name):
        return self.users.get(name)

    def public_user(self, name):
        u = self.users[name]
        return {"username": u["username"], "role": u["role"], "courses": list(u["courses"]),
                "service": u.get("service"), "purposes": list(u.get("purposes", []))}

    def add_doc(self, title, course, kind, owner, body):
        d = {"id": self.next_id, "title": title, "course": course, "kind": kind, "owner": owner, "body": body}
        self.docs[self.next_id] = d
        self.next_id += 1
        return copy.deepcopy(d)
