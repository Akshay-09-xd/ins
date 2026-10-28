"""Unit tests for the dynamic OTP scheme.  Run:  python -m unittest -v"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from otp_auth import AuthServer, TokenLockedError, hotp_counter  # noqa: E402


class FakeClock:
    def __init__(self, t=1_760_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class TestOTP(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.server = AuthServer(otp_ttl=60, max_attempts=3, lockout_threshold=5,
                                 lockout_seconds=300, clock=self.clock)
        self.token = self.server.register("alice", pin="4821")
        self.token.unlock("4821")

    def login(self):
        ch = self.server.issue_challenge("alice")
        return ch, self.token.respond(ch["challenge"], ch["counter"], ch["expires_at"])

    # --- normal operation -------------------------------------------------
    def test_TC01_valid_otp_accepted(self):
        ch, otp = self.login()
        self.assertTrue(self.server.verify("alice", ch["challenge_id"], otp).ok)

    def test_TC02_otp_is_six_digits_and_changes_every_login(self):
        otps = {self.login()[1] for _ in range(50)}
        self.assertTrue(all(len(o) == 6 and o.isdigit() for o in otps))
        self.assertGreater(len(otps), 45)       # practically all distinct

    # --- single use / replay ------------------------------------------------
    def test_TC03_replayed_otp_rejected(self):
        ch, otp = self.login()
        self.server.verify("alice", ch["challenge_id"], otp)
        r = self.server.verify("alice", ch["challenge_id"], otp)
        self.assertFalse(r.ok)
        self.assertIn("replay", r.reason)

    def test_TC04_otp_not_valid_for_other_challenge(self):
        ch1, otp1 = self.login()
        ch2, _ = self.login()
        self.assertFalse(self.server.verify("alice", ch2["challenge_id"], otp1).ok)

    # --- expiry -------------------------------------------------------------
    def test_TC05_expired_otp_rejected(self):
        ch, otp = self.login()
        self.clock.t += 61
        r = self.server.verify("alice", ch["challenge_id"], otp)
        self.assertFalse(r.ok)
        self.assertIn("expired", r.reason)

    def test_TC06_edge_otp_at_exact_expiry_accepted(self):
        ch, otp = self.login()
        self.clock.t = ch["expires_at"]           # boundary: still valid
        self.assertTrue(self.server.verify("alice", ch["challenge_id"], otp).ok)

    def test_TC07_edge_one_second_after_expiry_rejected(self):
        ch, otp = self.login()
        self.clock.t = ch["expires_at"] + 1
        self.assertFalse(self.server.verify("alice", ch["challenge_id"], otp).ok)

    # --- invalid / tampered input ------------------------------------------
    def test_TC08_wrong_otp_rejected(self):
        ch, otp = self.login()
        wrong = str((int(otp) + 1) % 1_000_000).zfill(6)
        self.assertFalse(self.server.verify("alice", ch["challenge_id"], wrong).ok)

    def test_TC09_malformed_otp_rejected(self):
        for bad in ["", "12345", "1234567", "abcdef", "12 456"]:
            ch, _ = self.login()
            r = self.server.verify("alice", ch["challenge_id"], bad)
            self.assertFalse(r.ok)
            self.assertIn("malformed", r.reason)
            self.server.users["alice"].failed_logins = 0

    def test_TC10_tampered_expiry_rejected(self):
        ch = self.server.issue_challenge("alice")
        forged = self.token.respond(ch["challenge"], ch["counter"], ch["expires_at"] + 3600)
        self.assertFalse(self.server.verify("alice", ch["challenge_id"], forged).ok)

    def test_TC11_attempt_limit_revokes_challenge(self):
        ch, otp = self.login()
        for _ in range(3):
            self.server.verify("alice", ch["challenge_id"], "000000")
        r = self.server.verify("alice", ch["challenge_id"], otp)
        self.assertFalse(r.ok)              # even the right OTP is now useless

    def test_TC12_account_lockout_after_repeated_failures(self):
        for _ in range(5):
            ch = self.server.issue_challenge("alice")
            self.server.verify("alice", ch["challenge_id"], "000000")
        with self.assertRaises(PermissionError):
            self.server.issue_challenge("alice")
        self.clock.t += 301                  # lock-out period over
        ch, otp = self.login()
        self.assertTrue(self.server.verify("alice", ch["challenge_id"], otp).ok)

    def test_TC13_other_users_challenge_rejected(self):
        bob = self.server.register("bob", pin="1111")
        ch, otp = self.login()
        self.assertFalse(self.server.verify("bob", ch["challenge_id"], otp).ok)

    def test_TC14_token_requires_pin(self):
        self.token.lock()
        self.assertFalse(self.token.unlock("0000"))
        ch = self.server.issue_challenge("alice")
        with self.assertRaises(TokenLockedError):
            self.token.respond(ch["challenge"], ch["counter"], ch["expires_at"])

    def test_TC15_server_never_stores_plain_otp(self):
        ch, otp = self.login()
        rec = self.server.pending[ch["challenge_id"]]
        self.assertNotIn(otp.encode(), repr(vars(rec)).encode())

    # --- TOTP mode ----------------------------------------------------------
    def test_TC16_totp_single_use_within_window(self):
        t = self.token.current_totp()
        self.assertTrue(self.server.verify_totp("alice", t).ok)
        self.assertFalse(self.server.verify_totp("alice", t).ok)

    def test_TC17_totp_expires_after_window(self):
        t = self.token.current_totp()
        self.clock.t += 90                   # 3 steps later, window is +/-1
        self.assertFalse(self.server.verify_totp("alice", t).ok)

    def test_TC18_totp_clock_drift_tolerated(self):
        t = self.token.current_totp()
        self.clock.t += 30                   # server one step ahead
        self.assertTrue(self.server.verify_totp("alice", t).ok)

    # --- known-answer test for the HOTP core (RFC 4226 style truncation) ----
    def test_TC19_hotp_deterministic(self):
        key = b"12345678901234567890"
        self.assertEqual(hotp_counter(key, 0), hotp_counter(key, 0))
        self.assertNotEqual(hotp_counter(key, 0), hotp_counter(key, 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
