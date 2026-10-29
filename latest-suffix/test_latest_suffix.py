#!/usr/bin/env python3
"""Verification suite for the latest-suffix reconstruction.

Run:  python3 -m unittest -v test_latest_suffix.py
  or: python3 test_latest_suffix.py

Every expected value comes from evidence/*.json, which is pinned to GitHub
file sources (see evidence/github_sources.json) and to a real Dell PE extracted
from a GitHub-sourced BIOS image.  No network, no third-party packages.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

import latest_suffix as ls
import vault_inspect as vi

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
VECTORS = json.loads((EV / "vectors.json").read_text())
FIRMWARE = json.loads((EV / "firmware_5440_1281.json").read_text())
SOURCES = json.loads((EV / "github_sources.json").read_text())


class TestE7A8Engine(unittest.TestCase):
    """The last host-side algorithm, reconstructed from scratch."""

    def test_binfile_real_world_vectors(self):
        for x in VECTORS["e7a8_binfile_vectors"]:
            with self.subTest(tag=x["tag"]):
                self.assertEqual(ls.e7a8_codes(x["tag"]),
                                 (x["code1"], x["code2"]))

    def test_in_repo_js_python_corpus_vectors(self):
        for x in VECTORS["e7a8_keygen_html_vectors"]:
            with self.subTest(tag=x["tag"]):
                self.assertEqual(list(ls.e7a8_codes(x["tag"])), x["expect"])

    def test_upstream_javascript_test_vector(self):
        for x in VECTORS["e7a8_upstream_test_vectors"]:
            self.assertEqual(sorted(ls.e7a8_codes(x["tag"])),
                             sorted(x["expect"]))

    def test_field_codes_posted_by_repo_owner(self):
        for x in VECTORS["e7a8_field_vectors_issue80"]:
            with self.subTest(tag=x["tag"]):
                first, second = ls.e7a8_codes(x["tag"])
                self.assertEqual(first, x["code1"])
                if "code2" in x:
                    self.assertEqual(second, x["code2"])
                else:
                    # issue 80 quotes a truncated second code
                    self.assertTrue(second.startswith("rkGGUh7Ix1hRy"))

    def test_both_codes_are_16_printable_chars(self):
        for tag in ("CVZKKD3", "1234567", "847TJ34", "DELLSUX"):
            for code in ls.e7a8_codes(tag):
                self.assertEqual(len(code), 16)
                self.assertTrue(all(32 <= ord(c) < 127 for c in code))
                self.assertTrue(all(c in ls.E7A8_ALPHABET for c in code))


class TestBioskeyHypothesis(unittest.TestCase):
    """Reproduce the newest GitHub repo's guess, then disprove it."""

    def test_reconstruction_matches_observed_node_outputs(self):
        for x in VECTORS["bioskey_hypothesis_outputs"]["outputs"]:
            with self.subTest(tag=x["tag"], suffix=x["suffix"]):
                if x["suffix"] == "E7A8":
                    got = list(ls.e7a8_codes(x["tag"]))
                else:
                    got = list(ls.hypothesis_codes(x["tag"], x["suffix"]))
                self.assertEqual(got, x["codes"])

    def test_hypothesis_fails_all_public_8fc8_field_pairs(self):
        pairs = VECTORS["field_8fc8_pairs"]["pairs"]
        for p in pairs:
            with self.subTest(tag=p["tag"]):
                guessed = ls.hypothesis_codes(p["tag"], p["suffix"])
                self.assertNotIn(p["code"], guessed)
                # sanity: the real codes really do use the recovered alphabet
                self.assertTrue(all(c in ls.EC_ALPHABET for c in p["code"]))

    def test_resolve_labels_hypothesis_disproven(self):
        r = ls.resolve("1K6Y963-8FC8", include_hypothesis=True)
        self.assertIn("hypothesis", r)
        self.assertIn("DISPROVEN", r["hypothesis"]["status"])
        self.assertEqual(r["candidates"], [])  # no local answer claimed

    def test_upstream_3fe2_test_vector_is_the_hypothesis(self):
        # bioskey tests/keygen.test.ts: CX8F9C3-3FE2 -> these two strings.
        self.assertEqual(sorted(ls.hypothesis_codes("CX8F9C3", "3FE2")),
                         sorted(["ZUsI2sMaBrzQj7xz", "dIaNZyycy2J2xNF6"]))


class TestECRender(unittest.TestCase):
    """The real latest-suffix host-side transform."""

    def setUp(self):
        self.resp = bytes.fromhex(VECTORS["ec_render_vectors"]["response_hex"])

    def test_all_families_match_firmware_emulation_vectors(self):
        for suffix, exp in VECTORS["ec_render_vectors"]["expected"].items():
            with self.subTest(suffix=suffix):
                self.assertEqual(ls.render_ec_response(self.resp, suffix),
                                 (exp["master"], exp["second"]))

    def test_8fc8_second_candidate_is_identical(self):
        a, b = ls.render_ec_response(self.resp, "8FC8")
        self.assertEqual(a, b)  # addition commutes -- documented edge case

    def test_short_response_rejected(self):
        with self.assertRaises(ValueError):
            ls.render_ec_response(self.resp[:16], "9ABE")

    def test_non_ec_suffix_rejected(self):
        with self.assertRaises(ValueError):
            ls.render_ec_response(self.resp, "E7A8")

    def test_verbatim_bytes_are_not_ascii_normalized(self):
        raw = bytes(range(0xC0, 0xC0 + 32))
        a, b = ls.render_ec_response(raw, "9ABE")
        self.assertEqual(a.encode("latin1"), raw[:16])
        self.assertEqual(b.encode("latin1"), raw[16:32])


class TestFirmwareEvidence(unittest.TestCase):
    """Re-extract the suffix tables from the committed, GitHub-sourced PE."""

    @classmethod
    def setUpClass(cls):
        cls.info = vi.summarize(vi.DEFAULT_PE)

    def test_pe_hash_matches_evidence(self):
        self.assertEqual(self.info["sha256"],
                         FIRMWARE["source_files"]["vault_pe"]["sha256"])
        self.assertEqual(self.info["bytes"], 38912)

    def test_ec_family_list_contains_latest_suffix(self):
        words = [w for f in self.info["ec_family_lists"] for w in f["words"]]
        self.assertIn("9ABE", words)
        for w in ("1B58", "3FE2", "CF1B", "8FC8"):
            self.assertIn(w, words)
        self.assertIn(
            [f for f in self.info["ec_family_lists"]][0]["file_offset"],
            ("0x81f8",))

    def test_local_keygen_descriptor_has_null_8fc8_encoder(self):
        entries = [e for t in self.info["descriptor_tables"]
                   for e in t["entries"]]
        by_suffix = {e["suffix"]: e for e in entries if not e.get("terminator")}
        self.assertIn("8FC8", by_suffix)
        self.assertTrue(by_suffix["8FC8"]["params_null"])
        self.assertIn("E7A8", by_suffix)
        self.assertFalse(by_suffix["E7A8"]["params_null"])
        for newest in ("9ABE", "CF1B", "3FE2", "1B58"):
            self.assertNotIn(newest, by_suffix,
                             f"{newest} must not have a host-side encoder")

    def test_extracted_e7a8_params_equal_reconstructed_constants(self):
        self.assertEqual(len(self.info["params"]), 1)
        p = self.info["params"][0]
        self.assertEqual([int(x, 16) for x in p["encodeParams"]],
                         list(ls.ENCODE_PARAMS))
        self.assertEqual(p["loopParams"], [17, 13, 12, 8])

    def test_extracted_alphabets_equal_constants(self):
        values = [a["value"] for a in self.info["alphabets"]]
        self.assertIn(ls.EC_ALPHABET, values)
        self.assertIn(ls.E7A8_ALPHABET, values)

    def test_6a49_5a6b_are_alphabet_tail_not_new_suffixes(self):
        # A naive u16 context dump shows 6A49 5A6B before the family list.
        data = Path(vi.DEFAULT_PE).read_bytes()
        # the four bytes directly before 0x81f8 are ASCII 'I','j','k','Z':
        # the tail of the E7A8 alphabet "…JXGabIjkZ", not two new suffixes.
        self.assertEqual(data[0x81F0:0x81F8].decode("latin1"), "GXbaIjkZ")
        self.assertEqual(data[0x81F4:0x81F8].decode("latin1"), "IjkZ")
        self.assertEqual(int.from_bytes(data[0x81F4:0x81F6], "little"), 0x6A49)
        self.assertEqual(int.from_bytes(data[0x81F6:0x81F8], "little"), 0x5A6B)
        self.assertNotIn("6A49", [w for f in self.info["ec_family_lists"]
                                  for w in f["words"]])


class TestCatalogAndDispatch(unittest.TestCase):
    def test_latest_answers(self):
        self.assertEqual(ls.LATEST_DISPLAYED_SUFFIX, "9ABE")
        self.assertEqual(ls.LATEST_HOST_ALGORITHM_SUFFIX, "E7A8")

    def test_classifications(self):
        self.assertEqual(ls.CATALOG["9ABE"].mechanism, ls.EC_VERBATIM)
        self.assertEqual(ls.CATALOG["8FC8"].mechanism, ls.EC_ALPHABET_MAP)
        self.assertEqual(ls.CATALOG["E7A8"].mechanism, ls.LOCAL_SHA256)
        self.assertEqual(ls.CATALOG["595B"].mechanism, ls.LEGACY_MD5)
        self.assertEqual(ls.CATALOG["8FCA"].mechanism, ls.UNCONFIRMED)
        self.assertEqual(ls.CATALOG["9ABE"].family_byte, 0xBE)
        self.assertEqual(ls.CATALOG["8FC8"].family_byte, 0xC8)

    def test_parse_variants(self):
        for text in ("847TJ34-9ABE", "847tj34:9abe", "847TJ34 9ABE",
                     "847TJ349ABE"):
            self.assertEqual(ls.parse_screen_code(text), ("847TJ34", "9ABE"))
        self.assertEqual(ls.parse_screen_code("BFTF1X2-8FDC8"),
                         ("BFTF1X2", "8FDC8"))
        with self.assertRaises(ValueError):
            ls.parse_screen_code("nonsense")

    def test_resolve_e7a8_is_locally_computable(self):
        r = ls.resolve("CVZKKD3-E7A8")
        self.assertEqual(r["candidates"], ["JnGkZZ9ZRIRPBm3["])
        self.assertEqual(r["second_candidates"], ["JxNGZ3yqWP26p9G["])
        self.assertIsNone(r["needs"])

    def test_resolve_9abe_requires_ec_response(self):
        r = ls.resolve("847TJ34-9ABE")
        self.assertEqual(r["candidates"], [])
        self.assertEqual(r["family_byte"], "0xBE")
        self.assertIn("21 00 03 06", r["needs"]["wire"])
        self.assertIn("0x910", r["needs"]["ports"])

    def test_resolve_9abe_with_captured_response(self):
        r = ls.resolve("847TJ34-9ABE",
                       resp_hex=VECTORS["ec_render_vectors"]["response_hex"])
        self.assertEqual(r["candidates"], ["ABCDEFGHIJKLMNOP"])
        self.assertEqual(r["second_candidates"], ["QRSTUVWXYZ012345"])
        self.assertIsNone(r["needs"])

    def test_resolve_8fc8_with_captured_response(self):
        r = ls.resolve("1K6Y963-8FC8",
                       resp_hex=VECTORS["ec_render_vectors"]["response_hex"])
        self.assertEqual(r["candidates"], ["2rk9L1Gq53kZkFx["])

    def test_resolve_legacy_points_to_existing_tool(self):
        r = ls.resolve("CVZKKD3-595B")
        self.assertEqual(r["candidates"], [])
        self.assertIn("dell-keygen/keygen.html", r["needs"])

    def test_resolve_unknown_suffix(self):
        r = ls.resolve("1234567-ZZ99")
        self.assertEqual(r["mechanism"], "unknown")
        self.assertEqual(r["candidates"], [])

    def test_unconfirmed_suffix_is_not_silent(self):
        r = ls.resolve("C954J64-8FCA")
        self.assertEqual(r["mechanism"], ls.UNCONFIRMED)
        self.assertEqual(r["candidates"], [])


class TestEvidenceFiles(unittest.TestCase):
    def test_source_pins_present(self):
        self.assertIn("_meta", SOURCES)
        for repo in ("bacher09/pwgen-for-bios", "secaicandido/bioskey",
                     "serversupdep-ai/Bin-file",
                     "chromebreakerdev/DellBIOSTools"):
            self.assertIn(repo, SOURCES)
            self.assertEqual(len(SOURCES[repo]["commit"]), 40)
            self.assertTrue(SOURCES[repo]["files"])
        self.assertTrue(any("comment-5067918343" in i["id"]
                            for i in SOURCES["github_issues"]))

    def test_firmware_image_hashes_recorded(self):
        f = FIRMWARE["source_files"]
        self.assertEqual(len(f["part1"]["sha256"]), 64)
        self.assertEqual(len(f["part2"]["sha256"]), 64)
        self.assertEqual(len(f["system_bios"]["sha256"]), 64)
        self.assertIn("Latitude 5440", f["system_bios"]["model_info"])

    def test_field_pairs_are_negative_controls(self):
        self.assertEqual(len(VECTORS["field_8fc8_pairs"]["pairs"]), 4)


class TestCLI(unittest.TestCase):
    def test_cli_e7a8(self):
        out = subprocess.check_output(
            [sys.executable, str(HERE / "latest_suffix.py"), "7QJ4H42-E7A8"],
            text=True)
        self.assertIn("hqrD9j8qbQGX6ZGJ", out)

    def test_cli_9abe(self):
        out = subprocess.check_output(
            [sys.executable, str(HERE / "latest_suffix.py"), "847TJ34-9ABE"],
            text=True)
        self.assertIn("9ABE", out)
        self.assertIn("32-byte EC GENERATE response", out)

    def test_cli_json(self):
        out = subprocess.check_output(
            [sys.executable, str(HERE / "latest_suffix.py"), "--json",
             "1K6Y963-8FC8"], text=True)
        self.assertEqual(json.loads(out)["mechanism"], ls.EC_ALPHABET_MAP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
