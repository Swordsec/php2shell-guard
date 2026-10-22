#!/usr/bin/env python3
"""Unit tests for php2shell-guard (stdlib unittest, no dependencies).

Run:  python3 -m unittest discover -s tests -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC = importlib.util.spec_from_file_location("guard", os.path.join(ROOT, "php2shell-guard.py"))
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class VersionClassification(unittest.TestCase):
    def test_fixed_releases_are_patched(self):
        for v in ("8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.2.36", "8.5.13", "8.6.0", "8.7.1", "9.0.0"):
            self.assertEqual(guard.classify_version(v)[0], "patched", v)

    def test_prior_releases_are_vulnerable(self):
        for v in ("8.2.34", "8.3.35", "8.4.26", "8.5.11", "8.2.0", "8.4.3", "8.5.0"):
            self.assertEqual(guard.classify_version(v)[0], "vulnerable", v)

    def test_prerelease_of_fixed_version_is_vulnerable(self):
        self.assertEqual(guard.classify_version("8.4.27RC1")[0], "vulnerable")
        self.assertEqual(guard.classify_version("8.5.12-dev")[0], "vulnerable")

    def test_eol_branches(self):
        for v in ("8.1.33", "8.0.30", "7.4.33", "5.6.40"):
            self.assertEqual(guard.classify_version(v)[0], "eol", v)

    def test_86_prereleases(self):
        self.assertEqual(guard.classify_version("8.6.0RC3")[0], "vulnerable")
        self.assertEqual(guard.classify_version("8.6.0RC4")[0], "patched")
        self.assertEqual(guard.classify_version("8.6.0RC5")[0], "patched")
        self.assertEqual(guard.classify_version("8.6.0-dev")[0], "vulnerable")

    def test_garbage(self):
        self.assertEqual(guard.classify_version("")[0], "unknown")
        self.assertEqual(guard.classify_version("banana")[0], "unknown")

    def test_parse_version_with_suffixes(self):
        self.assertEqual(guard.parse_version("PHP 8.3.6 (cli)")[:3], (8, 3, 6))
        self.assertEqual(guard.parse_version("8.5.4-0ubuntu1.5")[:3], (8, 5, 4))
        self.assertEqual(guard.parse_version("8.6.0RC4")[3:], ("rc", 4))


class DebianVersions(unittest.TestCase):
    def test_basic_ordering(self):
        self.assertLess(guard.deb_cmp("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13"), 0)
        self.assertEqual(guard.deb_cmp("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13"), 0)
        self.assertGreater(guard.deb_cmp("8.3.6-0ubuntu0.24.04.14", "8.3.6-0ubuntu0.24.04.13"), 0)

    def test_tilde_sorts_before_everything(self):
        self.assertLess(guard.deb_cmp("8.4.27-1~deb13u1", "8.4.27-1"), 0)
        self.assertGreater(guard.deb_cmp("8.4.27-1~deb13u1", "8.4.24-1~deb13u1"), 0)
        self.assertLess(guard.deb_cmp("8.2.35~rc1-1", "8.2.35-1"), 0)

    def test_epoch_and_plus(self):
        self.assertGreater(guard.deb_cmp("1:7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29+esm5"), 0)
        self.assertGreater(guard.deb_cmp("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29+esm4"), 0)
        self.assertGreater(guard.deb_cmp("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29"), 0)
        self.assertGreater(guard.deb_cmp("5.5.9+dfsg-1ubuntu4.29+esm18", "5.5.9+dfsg-1ubuntu4.29+esm9"), 0)

    def test_numeric_not_lexical(self):
        self.assertGreater(guard.deb_cmp("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.9"), 0)
        self.assertLess(guard.deb_cmp("8.1.2-1ubuntu2.27", "8.1.2-1ubuntu2.28"), 0)


class RpmVersions(unittest.TestCase):
    def test_vercmp(self):
        self.assertLess(guard.rpm_vercmp("7", "8"), 0)
        self.assertLess(guard.rpm_vercmp("8.el9_7", "8.el9_8"), 0)
        self.assertGreater(guard.rpm_vercmp("1.el10_2.alma.1", "1.el10_2"), 0)
        self.assertLess(guard.rpm_vercmp("1.el9~rc", "1.el9"), 0)
        self.assertEqual(guard.rpm_vercmp("8.3.33", "8.3.33"), 0)
        self.assertLess(guard.rpm_vercmp("8.3.9", "8.3.33"), 0)

    def test_evr(self):
        self.assertLess(guard.rpm_evr_cmp("8.0.30-7.el9_8", "8.0.30-8.el9_8.alma.1"), 0)
        self.assertGreater(guard.rpm_evr_cmp("1:8.0.30-1.el9", "8.0.30-9.el9"), 0)

    def test_module_build_match(self):
        self.assertIsNotNone(guard.rpm_matches_fixed("7.4.33-8.module_el8.10.0+4321+cf5fd4bb"))
        self.assertIsNotNone(guard.rpm_matches_fixed("7.4.33-8.module_el8.10.0+4400+aaaaaaaa"))
        self.assertIsNone(guard.rpm_matches_fixed("7.4.33-7.module_el8.10.0+4100+bbbbbbbb"))
        self.assertIsNone(guard.rpm_matches_fixed("7.4.33-8.module_el9.4.0+100+cccccccc"))
        self.assertIsNotNone(guard.rpm_matches_fixed("8.3.33-1.el10_2.alma.1"))
        self.assertIsNotNone(guard.rpm_matches_fixed("8.3.33-2.el10_2"))
        self.assertIsNone(guard.rpm_matches_fixed("8.3.33-1.el10_1"))
        self.assertIsNone(guard.rpm_matches_fixed("8.3.30-1.el10_2"))


class IniParsing(unittest.TestCase):
    def test_ini_bool_and_bytes(self):
        self.assertIs(guard.ini_bool("On"), True)
        self.assertIs(guard.ini_bool("off"), False)
        self.assertIs(guard.ini_bool("0"), False)
        self.assertIs(guard.ini_bool("no value"), None)
        self.assertEqual(guard.ini_bytes("8M"), 8 * 1024 ** 2)
        self.assertEqual(guard.ini_bytes("32M"), 32 * 1024 ** 2)
        self.assertEqual(guard.ini_bytes("-1"), -1)
        self.assertEqual(guard.ini_bytes("2G"), 2 * 1024 ** 3)
        self.assertIsNone(guard.ini_bytes("lots"))

    def test_phpinfo_text(self):
        text = (
            "Loaded Configuration File => /etc/php/8.3/fpm/php.ini\n"
            "Scan this dir for additional .ini files => /etc/php/8.3/fpm/conf.d\n"
            "Additional .ini files parsed => /etc/php/8.3/fpm/conf.d/10-opcache.ini,\n"
            "memory_limit => 128M => 128M\n"
            "session.upload_progress.enabled => On => On\n"
            "post_max_size => 8M => 8M\n"
            "irrelevant => x => y\n"
        )
        conf, info = guard.parse_phpinfo_text(text)
        self.assertEqual(conf["memory_limit"], ("128M", "128M"))
        self.assertEqual(conf["session.upload_progress.enabled"][0], "On")
        self.assertNotIn("irrelevant", conf)
        self.assertEqual(info["ini_file"], "/etc/php/8.3/fpm/php.ini")
        self.assertEqual(info["scan_dir"], "/etc/php/8.3/fpm/conf.d")
        self.assertEqual(info["additional"], ["/etc/php/8.3/fpm/conf.d/10-opcache.ini"])

    def test_static_resolver_order(self):
        with tempfile.TemporaryDirectory() as d:
            ini = os.path.join(d, "php.ini")
            scan = os.path.join(d, "conf.d")
            os.mkdir(scan)
            with open(ini, "w") as fh:
                fh.write("[PHP]\nmemory_limit = 128M\nsession.upload_progress.enabled = On ; comment\n")
            with open(os.path.join(scan, "10-a.ini"), "w") as fh:
                fh.write("memory_limit = 256M\n")
            with open(os.path.join(scan, "zz-php2shell-guard.ini"), "w") as fh:
                fh.write("session.upload_progress.enabled = 0\nmemory_limit=-1\n")
            conf, files = guard.resolve_static_ini(ini, scan)
            self.assertEqual(conf["memory_limit"][0], "-1")
            self.assertEqual(conf["session.upload_progress.enabled"][0], "0")
            self.assertEqual(len(files), 3)


class ConfigFindings(unittest.TestCase):
    def test_unpatched_defaults(self):
        conf = {"session.upload_progress.enabled": "On", "memory_limit": "128M", "post_max_size": "64M",
                "max_input_nesting_level": "64"}
        sevs = [f[0] for f in guard.config_findings(conf, "ctx", "VULNERABLE")]
        self.assertIn("HIGH", sevs)
        self.assertIn("MEDIUM", sevs)
        self.assertEqual(len(sevs), 4)

    def test_patched_lowers_severity(self):
        conf = {"session.upload_progress.enabled": "On", "memory_limit": "128M", "memory_hard_limit_percent": "150"}
        findings = guard.config_findings(conf, "ctx", "PATCHED")
        sevs = [f[0] for f in findings]
        self.assertNotIn("HIGH", sevs)
        self.assertIn("LOW", sevs)
        self.assertIn("OK", sevs)

    def test_mitigated(self):
        conf = {"session.upload_progress.enabled": "Off", "memory_limit": "-1", "post_max_size": "8M",
                "max_input_nesting_level": "32"}
        self.assertEqual(guard.config_findings(conf, "ctx", "VULNERABLE"), [])


class FpmPoolEditing(unittest.TestCase):
    POOL = "[global]\npid = /run/php-fpm.pid\n\n[www]\nuser = www-data\npm = dynamic\n\n[api]\nuser = api\n"

    def test_insert_under_each_pool(self):
        block = [guard.MARK_BEGIN, "php_admin_flag[session.upload_progress.enabled] = off", guard.MARK_END]
        out = guard.insert_fpm_block(self.POOL, block)
        self.assertEqual(out.count(guard.MARK_BEGIN), 2)
        self.assertLess(out.index("[www]"), out.index(guard.MARK_BEGIN))
        self.assertNotIn("[global]\n" + guard.MARK_BEGIN, out)

    def test_idempotent_and_rollback(self):
        block = [guard.MARK_BEGIN, "x = 1", guard.MARK_END]
        once = guard.insert_fpm_block(self.POOL, block)
        twice = guard.insert_fpm_block(once, block)
        self.assertEqual(once, twice)
        stripped = guard.insert_fpm_block(once, [])
        self.assertNotIn(guard.MARK_BEGIN, stripped)
        self.assertNotIn("x = 1", stripped)
        self.assertEqual(stripped.strip(), self.POOL.strip())

    def test_no_pool_sections_unchanged(self):
        self.assertEqual(guard.insert_fpm_block("[global]\npid = x\n", ["a"]), "[global]\npid = x\n")


class FpmDumpParsing(unittest.TestCase):
    def test_tt_output(self):
        text = (
            "[22-Oct-2026 10:00:00] NOTICE: [General]\n"
            "[22-Oct-2026 10:00:00] NOTICE: \tpid = /run/php/php8.3-fpm.pid\n"
            "[22-Oct-2026 10:00:00] NOTICE: [www]\n"
            "[22-Oct-2026 10:00:00] NOTICE: \tpm.max_requests = 500\n"
            "[22-Oct-2026 10:00:00] NOTICE: \tphp_admin_flag[session.upload_progress.enabled] = off\n"
            "[22-Oct-2026 10:00:00] NOTICE: \tphp_value[memory_limit] = 256M\n"
            "[22-Oct-2026 10:00:00] NOTICE: configuration file /etc/php/8.3/fpm/php-fpm.conf test is successful\n"
        )
        real_run = guard.run
        guard.run = lambda cmd, timeout=20, **kw: (0, "", text)
        try:
            pools, ok, _ = guard.fpm_pool_overrides("/usr/sbin/php-fpm8.3")
        finally:
            guard.run = real_run
        self.assertTrue(ok)
        self.assertEqual(pools["www"]["pm.max_requests"], ("setting", "500"))
        self.assertEqual(pools["www"]["session.upload_progress.enabled"], ("php_admin_flag", "off"))
        self.assertEqual(pools["www"]["memory_limit"], ("php_value", "256M"))


class RemoteParsing(unittest.TestCase):
    def test_banner_regex(self):
        self.assertEqual(guard.PHP_BANNER_RE.search("PHP/8.4.26").group(1), "8.4.26")
        self.assertEqual(guard.PHP_BANNER_RE.search("Apache/2.4 PHP/8.3").group(1), "8.3")
        self.assertEqual(guard.PHP_BANNER_RE.search("PHP/8.6.0RC4").group(1), "8.6.0RC4")
        self.assertIsNone(guard.PHP_BANNER_RE.search("WordPress/6.5"))

    def test_remote_verdicts(self):
        real = guard.http_request

        def fake(url, method="GET", **kw):
            hdr = {"x-powered-by": "PHP/8.3.35", "server": "cloudflare", "cf-ray": "x", "set-cookie": "PHPSESSID=abc; path=/"}
            if "branch" in url:
                hdr["x-powered-by"] = "PHP/8.1"
            if "none" in url:
                hdr = {"server": "nginx"}
            return 200, hdr, b"", None
        guard.http_request = fake
        try:
            r = guard.remote_check("https://a.example/")
            self.assertEqual(r["verdict"], "likely_vulnerable")
            self.assertIn("cloudflare", r["edge"])
            self.assertTrue(r["session_cookie"])
            self.assertEqual(guard.remote_check("https://branch.example/")["verdict"], "eol_branch")
            self.assertEqual(guard.remote_check("https://none.example/")["verdict"], "no_banner")
        finally:
            guard.http_request = real


class PatchMarkers(unittest.TestCase):
    def test_marker_search(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x7fELF" + b"\x00" * 100 + b"X-Powered-By: PHP/8.3.36\x00memory_hard_limit_percent\x00")
            name = fh.name
        try:
            self.assertEqual(guard.read_marker_hits(name), {"memory_hard_limit_percent"})
            self.assertEqual(guard.version_from_bytes(name), "8.3.36")
        finally:
            os.unlink(name)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x7fELF" + b"X-Powered-By: PHP/8.1.2\x00zend_mm_safe_error_ex\x00")
            name = fh.name
        try:
            self.assertEqual(guard.read_marker_hits(name), {"zend_mm_safe_error_ex"})
        finally:
            os.unlink(name)


class Rules(unittest.TestCase):
    def test_rule_files_in_sync_with_repo(self):
        rules_dir = os.path.join(ROOT, "rules")
        if not os.path.isdir(rules_dir):
            self.skipTest("rules/ directory not present")
        ext = {"modsecurity": "conf", "nginx": "conf", "apache": "conf", "haproxy": "cfg", "suricata": "rules", "caddy": "Caddyfile"}
        for name, text in guard.RULES.items():
            path = os.path.join(rules_dir, "php2shell-%s.%s" % (name, ext[name]))
            self.assertTrue(os.path.isfile(path), path)
            with open(path) as fh:
                self.assertEqual(fh.read(), text, "%s differs from the embedded copy; run `php2shell-guard.py rules --out rules`" % path)

    def test_unique_ids(self):
        import re
        ids = re.findall(r"id:(\d+)", guard.RULES["modsecurity"])
        self.assertEqual(len(ids), len(set(ids)))
        sids = re.findall(r"sid:(\d+)", guard.RULES["suricata"])
        self.assertEqual(len(sids), len(set(sids)))


class BinaryNames(unittest.TestCase):
    def test_names(self):
        for n in ("php", "php8.3", "php83", "php-fpm", "php-fpm8.3", "php8.3-fpm", "php-cgi", "lsphp", "lsphp83", "frankenphp", "php.exe", "php-cgi.exe"):
            self.assertTrue(guard.BIN_NAME_RE.match(n), n)
        for n in ("phpunit", "php-config", "phpize", "php-cs-fixer", "phpmyadmin", "composer"):
            self.assertFalse(guard.BIN_NAME_RE.match(n), n)

    def test_kinds(self):
        self.assertEqual(guard.binary_kind("/usr/sbin/php-fpm8.3"), "fpm")
        self.assertEqual(guard.binary_kind("/usr/lib/apache2/modules/libphp8.3.so"), "module")
        self.assertEqual(guard.binary_kind("/usr/local/lsws/lsphp83/bin/lsphp"), "lsapi")
        self.assertEqual(guard.binary_kind("/usr/bin/php-cgi"), "cgi")
        self.assertEqual(guard.binary_kind("/usr/bin/php"), "cli")


if __name__ == "__main__":
    unittest.main()
