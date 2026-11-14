"""Browser test: drives the real page with Playwright (headless Chromium). Skipped if Playwright is missing."""
import threading
import time
import unittest

from securehub.app import create_app

try:
    from playwright.sync_api import sync_playwright
    HAVE = True
except Exception:                      # pragma: no cover
    HAVE = False

PORT = 8793


@unittest.skipUnless(HAVE, "playwright not installed")
class TestPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app({"KEY_BITS": 512, "PBKDF2_ITER": 1000, "LAKE_ROWS": 3000})
        threading.Thread(target=lambda: cls.app.run(host="127.0.0.1", port=PORT, threaded=True), daemon=True).start()
        time.sleep(1.2)
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()

    def setUp(self):
        self.errors = []
        self.page = self.browser.new_page()
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.on("console", lambda m: self.errors.append(m.text) if m.type == "error" and not m.text.startswith("Failed to load resource") else None)
        self.page.goto("http://127.0.0.1:%d/" % PORT)

    def tearDown(self):
        self.page.close()
        self.assertEqual(self.errors, [])

    def sign_in(self, user):
        self.page.wait_for_selector("#demoUsers .chip")
        self.page.click("#demoUsers .chip:has-text('%s ·')" % user)
        self.page.click("#doLogin")
        self.page.wait_for_function("document.querySelector('#modal').hidden")

    def test_login_popup_opens_and_wrong_password_is_refused(self):
        p = self.page
        p.wait_for_selector("#modal:not([hidden])")
        p.fill("#lu", "alice")
        p.fill("#lp", "wrong")
        p.click("#doLogin")
        p.wait_for_selector("#loginMsg.bad")
        self.assertIn("Wrong username or password", p.inner_text("#loginMsg"))

    def test_navigation_is_role_aware(self):
        p = self.page
        self.sign_in("alice")
        self.assertEqual(p.get_attribute("#nav button:has-text('Dashboard')", "disabled"), "")
        self.assertEqual(p.get_attribute("#nav button:has-text('Attack lab')", "disabled"), "")
        self.assertIn("alice (student)", p.inner_text("#whoText"))

    def test_student_cannot_read_bobs_grades(self):
        p = self.page
        self.sign_in("alice")
        p.click("#nav button:has-text('Documents')")
        p.wait_for_selector("#tab-docs table")
        p.fill("#docId", "5")
        p.click("#tab-docs button:has-text('GET /api/documents')")
        p.wait_for_selector("#docView :text('not_owner')")
        self.assertIn("HTTP 403", p.inner_text("#docView"))

    def test_token_tab_tamper_is_refused(self):
        p = self.page
        self.sign_in("alice")
        p.click("#nav button:has-text('Token')")
        p.wait_for_selector("#tamperBox")
        p.click("#tab-token button:has-text('set role')")
        p.click("#tab-token button:has-text('Send edited')")
        p.wait_for_selector("#tamperOut :text('bad_signature')")
        self.assertIn("HTTP 401", p.inner_text("#tamperOut"))

    def test_doctor_lake_deny_overrides_is_explained(self):
        p = self.page
        self.sign_in("dr_amine")
        p.click("#nav button:has-text('Data lake')")
        p.wait_for_selector("#lkQuery")
        p.click("#tab-lake button:has-text('Ask for billing')")
        p.click("#tab-lake button:has-text('Run query')")
        p.wait_for_selector("#lkOut :text('column_denied')")
        txt = p.inner_text("#lkOut")
        self.assertIn("treatment_cost", txt)
        self.assertIn("deny-overrides", txt)

    def test_lake_shows_rewritten_sql_and_rows(self):
        p = self.page
        self.sign_in("lina")
        p.click("#nav button:has-text('Data lake')")
        p.wait_for_selector("#lkQuery")
        p.click("#tab-lake button:has-text('Statistics by diagnosis')")
        p.click("#tab-lake button:has-text('Run query')")
        p.wait_for_selector("#lkOut :text('The platform ran')")
        self.assertIn("HAVING COUNT(*) >= 5", p.inner_text("#lkOut"))
        self.assertIn("row(s)", p.inner_text("#lkOut"))

    def test_student_sees_data_lake_refused(self):
        p = self.page
        self.sign_in("bob")
        p.click("#nav button:has-text('Data lake')")
        p.wait_for_selector("#tab-lake :text('no permission')")

    def test_admin_runs_all_attacks_and_dashboard_shows_alerts(self):
        p = self.page
        self.sign_in("root")
        p.click("#nav button:has-text('Attack lab')")
        p.click("#tab-lab button:has-text('Run all')")
        p.wait_for_selector("#labSummary :text('12 / 12')", timeout=60000)
        p.click("#nav button:has-text('Dashboard')")
        p.wait_for_selector("#alerts .alert", timeout=10000)
        txt = p.inner_text("#alerts")
        for rule in ("brute_force", "token_tampering", "mass_access", "object_enumeration"):
            self.assertIn(rule, txt)
        p.click("#tab-dash button:has-text('Verify hash')")
        p.wait_for_selector("#chainOut :text('Chain valid')")
        p.click("#tab-dash button:has-text('Simulate log tampering')")
        p.wait_for_selector("#chainOut :text('Verification now fails')")

    def test_dashboard_is_live(self):
        p = self.page
        self.sign_in("root")
        p.click("#nav button:has-text('Dashboard')")
        p.wait_for_selector("#liveState:has-text('live')")
        import urllib.request
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/api/documents" % PORT)
        except Exception:
            pass                                                   # 401 raises: the point is that it is logged
        p.wait_for_selector("#feed :text('198.51.100') , #feed :text('127.0.0.1')", timeout=8000)

    def test_rsa_lab_matches_the_theory(self):
        p = self.page
        p.click("#closeLogin")
        p.click("#nav button:has-text('RSA lab')")
        p.click("#tab-rsa button:has-text('Compute')")
        p.wait_for_selector("#toyOut :text('588')")
        p.click("#tab-rsa button:has-text('Forge')")
        p.wait_for_selector("#forgeOut :text('verifies!')")
        p.click("#tab-rsa button:has-text('Factor')")
        p.wait_for_selector("#factorOut :text('53')")


if __name__ == "__main__":
    unittest.main()
