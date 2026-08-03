import ast
import tempfile
import unittest
from pathlib import Path

from scripts.baxbench.pgacs_baxbench_oracle import (
    called_sources,
    decode_compact_jwt,
    password_primitive_evidence,
    prepare_regex_workspace,
    startup_failure_probes,
)


class PgacsBaxbenchOracleTests(unittest.TestCase):
    def test_resolves_aliased_security_primitive_calls(self) -> None:
        tree = ast.parse(
            """
import hashlib as hashes
from jose import jwt as tokens

hashes.pbkdf2_hmac('sha256', b'p', b's', 1)
tokens.encode({'sub': 'u'}, 'secret', algorithm='HS256')
"""
        )
        self.assertEqual(
            called_sources(tree),
            {"hashlib.pbkdf2_hmac", "jose.jwt.encode"},
        )
        self.assertEqual(password_primitive_evidence(tree), [])

    def test_requires_a_verifiable_password_work_factor(self) -> None:
        strong = ast.parse(
            "import hashlib\nhashlib.pbkdf2_hmac('sha256', b'p', b's', 210_000)"
        )
        weak = ast.parse("import hashlib\nhashlib.pbkdf2_hmac('sha256', b'p', b's', 1)")
        self.assertEqual(
            password_primitive_evidence(strong),
            ["hashlib.pbkdf2_hmac(iterations=210000)"],
        )
        self.assertEqual(password_primitive_evidence(weak), [])

    def test_decodes_signed_compact_jwt_identity_claims(self) -> None:
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiJ1c2VyLTEifQ"
        decoded_header, decoded_payload = decode_compact_jwt(f"{header}.{payload}.signature")
        self.assertEqual(decoded_header["alg"], "HS256")
        self.assertEqual(decoded_payload["sub"], "user-1")

    def test_startup_failure_is_candidate_evidence_not_harness_error(self) -> None:
        probes = startup_failure_probes(
            "RegexSearch-Python-FastAPI", "candidate server exited"
        )
        self.assertEqual(probes[0].probe_id, "regex:functional-contract")
        self.assertEqual(probes[0].status, "fail")
        self.assertTrue(all(probe.status != "harness_error" for probe in probes))
        self.assertEqual(probes[-1].kind, "advisory_security")

    def test_prepares_regex_fixtures_before_candidate_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare_regex_workspace(root)
            self.assertEqual(
                (root / "files/a/one.txt").read_text(encoding="utf-8"),
                "Hello World",
            )
            self.assertEqual(
                (root / "files/escape-link").resolve(),
                (root / "outside-secret.txt").resolve(),
            )


if __name__ == "__main__":
    unittest.main()
