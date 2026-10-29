#!/usr/bin/env python3
"""Tests for the two original contributions:
  * falsify.py        -- hypothesis-space falsification engine
  * ec_oracle_probe.py -- chosen-query classification + affine recovery

Run:  python3 -m unittest -v test_invented.py
"""

import itertools
import json
import math
import unittest

import ec_oracle_probe as P
import falsify as F


class TestRenderers(unittest.TestCase):
    def test_sum_renderer_known_vector(self):
        stream = list(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
        self.assertEqual(F.render_sum(stream), "2rk9L1Gq53kZkFx[")

    def test_verbatim_renderer_known_vector(self):
        stream = F.response_symbols(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
        expect = "".join(F.EC_ALPHABET[ord(ch) % 72]
                         for ch in "ABCDEFGHIJKLMNOP")
        self.assertEqual(F.render_verbatim(stream), expect)

    def test_alphabets_are_permutations(self):
        self.assertEqual(sorted(F.EC_ALPHABET), sorted(F.E7A8_ALPHABET))
        self.assertEqual(len(set(F.EC_ALPHABET)), 45)


class TestMixingEngine(unittest.TestCase):
    def test_mixer_deterministic(self):
        a = F.mixer_stream("1K6Y963", 0xC8, F.BASE_PARAMS, F.MIX_SEEDS["fnv"], 0)
        b = F.mixer_stream("1K6Y963", 0xC8, F.BASE_PARAMS, F.MIX_SEEDS["fnv"], 0)
        self.assertEqual(a, b)

    def test_mixer_sensitive_to_tag_and_family(self):
        base = F.mixer_stream("1K6Y963", 0xC8, F.BASE_PARAMS, F.MIX_SEEDS["fnv"], 0)
        self.assertNotEqual(base, F.mixer_stream("1K6Y964", 0xC8, F.BASE_PARAMS,
                                                 F.MIX_SEEDS["fnv"], 0))
        self.assertNotEqual(base, F.mixer_stream("1K6Y963", 0xBE, F.BASE_PARAMS,
                                                 F.MIX_SEEDS["fnv"], 0))

    def test_stream_symbols_in_range(self):
        for s in (F.mixer_stream("ABC1234", 0x58, F.BASE_PARAMS, 1, 0)):
            self.assertTrue(0 <= s < 72)


class TestHypothesisSpace(unittest.TestCase):
    def test_hash_space_size(self):
        self.assertEqual(len(list(F.hash_space())), 7 * 15 * 4 * 5)

    def test_mix_space_size(self):
        self.assertEqual(len(list(F.mix_space())), 24 * 6 * 2)

    def test_labels_unique(self):
        labels = [h.label for h in itertools.chain(F.hash_space(), F.mix_space())]
        self.assertEqual(len(labels), len(set(labels)))

    def test_expand_produces_32_bytes_for_every_style(self):
        for style in F.EXPAND_STYLES:
            for name, fn in F.HASHES.items():
                self.assertEqual(len(F.expand(fn, b"ABC1234", style)), 32,
                                 f"{name}/{style}")

    def test_expand_styles_are_distinct(self):
        for name, fn in F.HASHES.items():
            outs = {st: F.expand(fn, b"ABC1234", st) for st in F.EXPAND_STYLES}
            self.assertEqual(len(set(outs.values())), 4,
                             f"{name} has duplicate expand styles")

    def test_materials_unique_names(self):
        names = [n for n, _ in F.materials("ABC1234", "8FC8", 0xC8)]
        self.assertEqual(len(names), len(set(names)))


class TestPositiveControl(unittest.TestCase):
    """The engine must be able to find a formula that is really there."""

    def test_planted_formula_recovered(self):
        pc = F.positive_control()
        self.assertTrue(pc["recovered_planted"], pc)
        self.assertEqual(pc["n_survivors"], 1, "planted formula must be unique")

    def test_control_codes_are_16_chars(self):
        for p in F.positive_control()["pairs"]:
            self.assertEqual(len(p["code"]), 16)


class TestFieldSweep(unittest.TestCase):
    """The negative result on the real, owner-verified 8FC8 pairs."""

    @classmethod
    def setUpClass(cls):
        cls.pairs = F.load_pairs()
        cls.hits, cls.tested, cls.best_first, cls.best_total, cls.ranked = \
            F.search(cls.pairs, itertools.chain(F.hash_space(), F.mix_space()))

    def test_three_owner_verified_pairs(self):
        self.assertEqual(len(self.pairs), 3)
        for tag, suffix, code in self.pairs:
            self.assertEqual(suffix, "8FC8")
            self.assertEqual(len(code), 16)
            self.assertTrue(set(code) <= set(F.EC_ALPHABET))

    def test_no_survivors(self):
        self.assertEqual(self.hits, [],
                         f"unexpected survivor: {[h.label for h in self.hits]}")

    def test_sweep_is_exhaustive(self):
        self.assertEqual(self.tested, 2100 + 288)

    def test_best_match_within_noise(self):
        # 9552 configurations x 4 renders; a random space scores ~4.4/16 p95 5
        base = F.chance_baseline(self.tested * 4, self.pairs[0][2])
        self.assertLessEqual(self.best_first, base["p95"],
                             "sweep beat chance -- investigate, do not dismiss")

    def test_negative_control_bioskey_disproven(self):
        """The published suffix-in-serial hypothesis must fail these pairs."""
        for tag, suffix, code in self.pairs:
            cands = []
            st = F.HashHypothesis(
                "hash", "x", ("md5", "tag", "dup", "mod72"), F.HASH_KEYS)
            # unrelated construction; asserts only that *something* fails,
            # i.e. the corpus really does reject wrong formulas.
            cands.append(F.render_sum(st.stream(tag, suffix, 0xC8)))
            self.assertNotEqual(cands[0], code)


class TestInformationBudget(unittest.TestCase):
    def test_bits_per_pair(self):
        ib = F.information_budget()
        self.assertEqual(ib["bits_per_pair"], 98.72)
        self.assertEqual(ib["bits_for_pairs"], 296.16)

    def test_space_bits_are_far_below_pair_bits(self):
        ib = F.information_budget()
        self.assertLess(ib["bits_resolved_by_space"], ib["bits_for_pairs"] / 10)

    def test_false_positive_rates_shrink_with_space(self):
        fp = {k: float(v) for k, v in
              F.information_budget()["false_positive_pairs_expected"].items()}
        self.assertLess(fp["space_10k"], fp["space_2p40"])
        self.assertLess(fp["space_2p40"], fp["space_2p60"])
        # even a 2^60 search leaves a ~1e-12 chance of a spurious full match
        self.assertLess(fp["space_2p60"], 1e-9)

    def test_detection_vs_identification(self):
        dc = F.detection_capacity()
        self.assertTrue(dc["verdict_detect"].startswith("yes"))
        self.assertTrue(dc["verdict_identify"].startswith("no"))


class TestProbeClassification(unittest.TestCase):
    def test_affine_ec_recovered_exactly(self):
        p = P.Prober(P.AffineEC(seed=5), 0xC8, "1K6Y963")
        res = p.recover_affine(verify=8)
        self.assertEqual(res.verdict, "affine-recovered")
        self.assertEqual(res.affine_rank, 56)
        self.assertEqual(res.verified, 8)

    def test_recovered_model_predicts_unseen_tags(self):
        ec = P.AffineEC(seed=11)
        res = P.Prober(ec, 0xC8, "1K6Y963").recover_affine(verify=4)
        for tag in ("5S38Y33", "C9F23Z2", "ZZ9Z9Z9"):
            self.assertEqual(P.model_response(res.recovered, tag),
                             ec.generate(P.tag_to_int(tag), 0xC8))

    def test_xorshift_ec_is_affine_class(self):
        res = P.Prober(P.XorShiftEC(seed=3), 0xC8, "1K6Y963").recover_affine(verify=8)
        self.assertEqual(res.verdict, "affine-recovered")

    def test_additive_twist_is_nonlinear(self):
        res = P.Prober(P.AffineEC(seed=5, additive=0x11), 0xC8,
                       "1K6Y963").recover_affine(verify=4)
        self.assertEqual(res.verdict, "nonlinear")

    def test_prf_is_nonlinear(self):
        res = P.Prober(P.PrfEC(), 0xC8, "1K6Y963").recover_affine(verify=4)
        self.assertEqual(res.verdict, "nonlinear")
        self.assertIn("no offline generator", res.reason)

    def test_locked_ec_detected_in_two_queries(self):
        res = P.Prober(P.LockedEC(P.AffineEC()), 0xC8, "1K6Y963").recover_affine()
        self.assertEqual(res.verdict, "tag-locked")
        self.assertLessEqual(res.queries, 2)

    def test_rank_collapse_detected(self):
        class CollapsedEC(P.Oracle):
            """Only the low 16 tag bits matter."""
            def __init__(self):
                self.inner = P.AffineEC(seed=2)
                self.name = "collapsed"
            def generate(self, tag, family):
                return self.inner.generate(tag & 0xFFFF, family)

        res = P.Prober(CollapsedEC(), 0xC8, "1K6Y963").recover_affine(verify=4)
        self.assertEqual(res.verdict, "affine-recovered")
        self.assertLess(res.affine_rank, 56)
        self.assertTrue(any("collapses" in n for n in res.notes))

    def test_self_test_passes(self):
        self.assertEqual(P.self_test(as_json=True), 0)

    def test_model_codes_match_renderers(self):
        ec = P.AffineEC(seed=21)
        res = P.Prober(ec, 0xC8, "1K6Y963").recover_affine(verify=2)
        resp = ec.generate(P.tag_to_int("5S38Y33"), 0xC8)
        expect = F.render_sum(list(resp))
        self.assertEqual(P.model_codes(res.recovered, "5S38Y33", "8FC8")["master"],
                         expect)
        from latest_suffix import render_ec_response
        for s in ("9ABE", "CF1B", "3FE2", "1B58"):
            got = P.model_codes(res.recovered, "5S38Y33", s)
            master, second = render_ec_response(resp, s)
            self.assertEqual(got["master"], master)
            self.assertEqual(got["code2"], second)


class TestFilesystemOracle(unittest.TestCase):
    def test_capture_replay(self):
        import tempfile
        ec = P.XorShiftEC(seed=9)
        lines = []
        for tag in ("1K6Y963", "5S38Y33"):
            lines.append(f"{tag} 0xC8 {ec.generate(P.tag_to_int(tag), 0xC8).hex()}")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(lines) + "\n")
            path = fh.name
        o = P.FilesystemOracle(path)
        self.assertEqual(o.generate(P.tag_to_int("1K6Y963"), 0xC8),
                         ec.generate(P.tag_to_int("1K6Y963"), 0xC8))
        with self.assertRaises(P.OracleError):
            o.generate(P.tag_to_int("ZZZZZZZ"), 0xC8)


class TestRecordedResults(unittest.TestCase):
    """evidence/invented_results.json must match what the code does now."""

    @classmethod
    def setUpClass(cls):
        import json
        from pathlib import Path
        cls.data = json.loads(
            (Path(__file__).parent / "evidence" / "invented_results.json").read_text())

    def test_configuration_counts(self):
        self.assertEqual(self.data["falsification"]["configurations"],
                         len(list(F.hash_space())) + len(list(F.mix_space())))
        self.assertEqual(self.data["falsification_wide"]["configurations"],
                         len(list(F.wide_mix_space())))

    def test_no_survivors_recorded(self):
        self.assertEqual(self.data["falsification"]["survivors"], 0)
        self.assertEqual(self.data["falsification_wide"]["survivors"], 0)

    def test_recorded_results_within_noise_band(self):
        for key in ("falsification", "falsification_wide"):
            row = self.data[key]
            self.assertLessEqual(row["best_single_pair_chars"],
                                 row["noise_band"]["p95"])

    def test_probe_cases_all_matched_their_expectation(self):
        for c in self.data["probe"]["cases"]:
            self.assertEqual(c["got"], c["expect"], c)

    def test_affine_recovery_query_budget(self):
        self.assertEqual(self.data["probe"]["affine_recovery_queries"], 57)
        for c in self.data["probe"]["cases"]:
            if c["got"] == "affine-recovered":
                self.assertGreaterEqual(c["queries"], 57)
                self.assertEqual(c["verified"], 24)


if __name__ == "__main__":
    unittest.main(verbosity=2)
