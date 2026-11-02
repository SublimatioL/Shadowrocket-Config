import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import update_rules as rules


class RuleTests(unittest.TestCase):
    def test_shared_suffixes_are_filtered(self):
        rows = [("DOMAIN-SUFFIX", root) for root in rules.SHARED_ROOTS]
        rows.append(("DOMAIN-SUFFIX", "cn"))
        self.assertEqual(rules.filter_rules(rows), [])

    def test_specific_endpoints_survive(self):
        rows = [
            ("DOMAIN", "www.aliyun.com"),
            ("DOMAIN-SUFFIX", "oss-cn-hangzhou.aliyuncs.com"),
            ("DOMAIN-SUFFIX", "cos.ap-guangzhou.myqcloud.com"),
            ("DOMAIN-SUFFIX", "obs.cn-north-4.myhuaweicloud.com"),
            ("DOMAIN-SUFFIX", "qq.com"),
        ]
        self.assertEqual(rules.filter_rules(rows), rows)
        self.assertEqual(rules.filter_rules(rules.filter_rules(rows)), rows)

    def test_suffix_matching_has_label_boundaries(self):
        self.assertTrue(rules.matches("DOMAIN-SUFFIX", "qq.com", "img.qq.com"))
        self.assertFalse(rules.matches("DOMAIN-SUFFIX", "qq.com", "notqq.com"))
        self.assertFalse(rules.matches("DOMAIN-SUFFIX", "qq.com", "qq.com.example"))


class ProfileTests(unittest.TestCase):
    def check_rejected_profile(self, original, modified, message):
        self.assertNotEqual(original, modified)
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "profile.conf"
            profile.write_text(modified, encoding="utf-8")
            with patch.object(rules, "PROFILE", profile):
                with self.assertRaisesRegex(AssertionError, message):
                    rules.check_profile("")

    def test_rejects_forced_client_resolution(self):
        original = rules.PROFILE.read_text(encoding="utf-8")
        self.assertIn("always-ip-address = false", original)
        self.check_rejected_profile(original, original.replace(
            "always-ip-address = false", "always-ip-address = true", 1,
        ), "always-ip-address")

    def test_requires_ipv6_enabled(self):
        original = rules.PROFILE.read_text(encoding="utf-8")
        self.check_rejected_profile(original, original.replace(
            "ipv6 = true", "ipv6 = false", 1,
        ), "ipv6")

    def test_rejects_blanket_ipv6_block(self):
        original = rules.PROFILE.read_text(encoding="utf-8")
        self.check_rejected_profile(original, original.replace(
            "DST-PORT,853,REJECT\n",
            "DST-PORT,853,REJECT\nIP-CIDR6,::/0,REJECT,no-resolve\n", 1,
        ), "IPv6 catch-all rejection")

    def test_requires_ipv6_preference_off(self):
        original = rules.PROFILE.read_text(encoding="utf-8")
        self.check_rejected_profile(original, original.replace(
            "prefer-ipv6 = false", "prefer-ipv6 = true", 1,
        ), "prefer-ipv6")


class SnapshotTests(unittest.TestCase):
    upstream = "a" * 40
    snapshot = "b" * 40

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.direct = root / "direct.list"
        self.profile = root / "profile.conf"
        self.text = (
            f"# Source: https://raw.githubusercontent.com/{rules.UPSTREAM}/"
            f"{self.upstream}/ruleset/direct.txt\nDOMAIN-SUFFIX,qq.com\n"
        )
        self.direct.write_text(self.text, encoding="utf-8")
        for name, value in (("DIRECT_PATH", self.direct), ("PROFILE", self.profile)):
            handle = patch.object(rules, name, value)
            handle.start()
            self.addCleanup(handle.stop)
        self.git = patch.object(rules.subprocess, "check_output", return_value=self.text.encode())
        self.git_mock = self.git.start()
        self.addCleanup(self.git.stop)

    def test_rejects_floating_ref(self):
        with self.assertRaises(AssertionError):
            rules.snapshot_urls("main")
        self.git_mock.assert_not_called()

    def test_rejects_different_committed_content(self):
        self.git_mock.return_value = b"DOMAIN-SUFFIX,other.example\n"
        with self.assertRaises(AssertionError):
            rules.snapshot_urls(self.snapshot)

    def test_pins_all_sources_and_preserves_settings(self):
        original = (
            "[General]\nipv6 = false\n[Rule]\nDOMAIN-SUFFIX,qq.com,DIRECT\n"
            "RULE-SET,https://example.org/release/proxy.txt,PROXY\n"
            "RULE-SET,https://example.org/main/direct.list,DIRECT\n"
            "RULE-SET,https://example.org/release/telegramcidr.txt,PROXY,no-resolve\n"
            "FINAL,PROXY\n"
        )
        self.profile.write_text(original, encoding="utf-8")
        rules.pin_profile(self.snapshot)
        pinned = self.profile.read_text(encoding="utf-8")
        self.assertIn("[General]\nipv6 = false\n", pinned)
        self.assertIn("DOMAIN-SUFFIX,qq.com,DIRECT\n", pinned)
        self.assertTrue(pinned.endswith("FINAL,PROXY\n"))
        self.assertIn(f"/{self.snapshot}/rules/direct.list,DIRECT", pinned)
        self.assertIn(f"/{self.upstream}/ruleset/proxy.txt,PROXY", pinned)
        self.assertIn(f"/{self.upstream}/ruleset/telegramcidr.txt,PROXY,no-resolve", pinned)
        rules.pin_profile(self.snapshot)
        self.assertEqual(self.profile.read_text(encoding="utf-8"), pinned)


if __name__ == "__main__":
    unittest.main()
