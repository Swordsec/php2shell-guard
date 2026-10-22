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


class WebshellPatterns(unittest.TestCase):
    def hits(self, data):
        return [rx for rx in guard.WEBSHELL_PATTERNS if rx.search(data)]

    def test_kit_names_still_match(self):
        for s in (b"<?php // c99shell v.1.0", b"$FilesMan = 1;", b"WSO 2.5", b"wso_version", b"b374k shell", b"echo `uname -a;`"):
            self.assertTrue(self.hits(s), s)

    def test_no_false_positives_on_application_code(self):
        for s in (b"$this->shouldShowSocialIds($request)", b"'COFFEE1919_378ddc9925f4.png'",
                  b"<?php /* 5b0832cb98e7c99029709ebfc90452dc */", b"newSorting(); rowSort();"):
            self.assertEqual(self.hits(s), [], s)


def inspect_info(mounts=(), labels=None, name="/php83"):
    return {"Id": "124429377f67" + "0" * 52, "Name": name, "State": {"Running": True},
            "Config": {"Image": "docker-multi-php-php83", "Labels": labels or {}},
            "Mounts": [dict(m) for m in mounts]}


class DockerContainer(unittest.TestCase):
    def test_host_path_longest_bind_mount_wins(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "sites", "app"))
            os.makedirs(os.path.join(d, "logs"))
            ct = guard.Container(inspect_info([
                {"Type": "bind", "Source": os.path.join(d, "sites"), "Destination": "/var/www/html"},
                {"Type": "bind", "Source": os.path.join(d, "logs"), "Destination": "/var/www/html/app/logs"},
                {"Type": "volume", "Source": "/var/lib/docker/volumes/x/_data", "Destination": "/data"},
            ]))
            self.assertEqual(ct.host_path("/var/www/html/app/index.php"), os.path.join(d, "sites", "app", "index.php"))
            self.assertEqual(ct.host_path("/var/www/html/app/logs/error.log"), os.path.join(d, "logs", "error.log"))
            self.assertEqual(ct.host_path("/var/www/html"), os.path.join(d, "sites"))
            self.assertIsNone(ct.host_path("/var/www/htmlx/a.php"))
            self.assertIsNone(ct.host_path("/data/x"))
            self.assertIsNone(ct.host_path("/usr/local/etc/php/conf.d/x.ini"))

    def test_host_path_refuses_symlink_escape_and_missing_source(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "sites")
            os.mkdir(src)
            os.symlink("/etc", os.path.join(src, "evil"))
            ct = guard.Container(inspect_info([
                {"Type": "bind", "Source": src, "Destination": "/var/www/html"},
                {"Type": "bind", "Source": os.path.join(d, "nope"), "Destination": "/srv"},
            ]))
            self.assertIsNone(ct.host_path("/var/www/html/evil/passwd"))
            self.assertIsNone(ct.host_path("/srv/a.php"))

    def test_compose_needs_container_labels(self):
        image_only = {"com.docker.compose.project": "docker-multi-php", "com.docker.compose.service": "php83"}
        self.assertIsNone(guard.Container(inspect_info(labels=image_only)).compose)
        full = dict(image_only, **{"com.docker.compose.config-hash": "abc",
                                   "com.docker.compose.project.working_dir": "/srv/stack",
                                   "com.docker.compose.project.config_files": "/srv/stack/docker-compose.yml"})
        ct = guard.Container(inspect_info(labels=full))
        self.assertEqual(ct.compose["service"], "php83")
        self.assertEqual(ct.name, "php83")
        self.assertEqual(ct.id, "124429377f67")

    def test_proc_snapshot(self):
        us = "\x1f"
        text = "\n".join([
            "P" + us + "1 (php-fpm) S 0 1 1 0 -1 4194560" + us + "/usr/local/sbin/php-fpm" + us + "php-fpm: master process (/usr/local/etc/php-fpm.conf) ",
            "P" + us + "7 (php-fpm) S 1 1 1 0 -1" + us + "/usr/local/sbin/php-fpm (deleted)" + us + "php-fpm: pool www",
            "P" + us + "9 (sh) S 7 1 1 0" + us + "/bin/dash" + us + "sh -c id",
            "P" + us + "12 (weird) name) S 1 1" + us + "" + us + "",
            "P" + us + "20 (apache2) S 1 20" + us + "/usr/sbin/apache2" + us + "apache2 -DFOREGROUND",
            "M" + us + "20" + us + "/usr/lib/apache2/modules/libphp.so (deleted)",
            "garbage line",
        ])
        procs = {p["pid"]: p for p in guard.parse_proc_snapshot(text)}
        self.assertEqual(procs[1]["ppid"], 0)
        self.assertIn("master process", procs[1]["cmdline"])
        self.assertTrue(procs[7]["deleted"])
        self.assertEqual(procs[7]["exe"], "/usr/local/sbin/php-fpm")
        self.assertEqual(procs[12]["comm"], "weird) name")
        self.assertIsNone(procs[12]["exe"])
        self.assertEqual(procs[20]["php_modules"], ["/usr/lib/apache2/modules/libphp.so"])
        self.assertTrue(procs[20]["module_deleted"])
        shells = guard.find_shell_children(list(procs.values()))
        self.assertEqual([(s["pid"], s["parent"]) for s in shells], [(9, "php-fpm[7]")])

    def test_shell_children_debian_fpm_names(self):
        procs = [{"pid": 2, "ppid": 1, "comm": "php-fpm8.3"}, {"pid": 3, "ppid": 2, "comm": "bash"},
                 {"pid": 4, "ppid": 1, "comm": "cron"}, {"pid": 5, "ppid": 4, "comm": "sh"}]
        self.assertEqual([s["pid"] for s in guard.find_shell_children(procs)], [3])

    def test_layer_changes(self):
        lines = ["C /etc", "A /etc/cron.d", "A /etc/cron.d/x", "C /var/www/html/index.php", "A /tmp/sess_abc",
                 "A /var/www/html/up/a.php.jpg", "D /var/www/html/old.php", "A /usr/local/etc/php/conf.d/zz-php2shell-guard.ini",
                 "A /root/.ssh/authorized_keys", "C /etc/passwd"]
        php, persist = guard.classify_layer_changes(lines)
        self.assertEqual(php, ["/var/www/html/index.php", "/var/www/html/up/a.php.jpg"])
        self.assertEqual(persist, ["/etc/cron.d", "/etc/cron.d/x", "/root/.ssh/authorized_keys", "/etc/passwd"])

    def test_apache_directive_lines(self):
        self.assertEqual(guard.apache_directive("  php_admin_flag session.upload_progress.enabled off"),
                         ("php_admin_flag", "session.upload_progress.enabled", "off"))
        self.assertEqual(guard.apache_directive("RLimitMEM 268435456")[0], "rlimitmem")
        self.assertIsNone(guard.apache_directive("# php_value memory_limit 1G"))
        self.assertIsNone(guard.apache_directive("php_value include_path ."))

    def test_container_fix_hints(self):
        comp = {"project": "docker-multi-php", "service": "php74", "working_dir": "/s",
                "config_files": "/s/docker-compose.yml"}
        d = {"image": "docker-multi-php-php74", "compose": comp}
        fix = guard.container_fix(d, {"version": "7.4.33", "kind": "fpm"})
        self.assertIn("PHP 8.2+", fix)
        self.assertIn("update FROM", fix)
        self.assertIn("docker compose -f /s/docker-compose.yml build --pull php74", fix)
        fix = guard.container_fix({"image": "php:8.3.20-fpm", "compose": None}, {"version": "8.3.20", "kind": "fpm"})
        self.assertIn("PHP 8.3.36+", fix)
        self.assertIn("php:8.3-fpm", fix)
        self.assertNotIn("FROM", fix)


class FakeContainer(object):
    """In-memory stand-in for guard.Container (no docker needed)."""
    join = staticmethod(guard.posixpath.join)

    def __init__(self, files, dirs, phpinfo, version="PHP 8.3.20 (cli)"):
        self.files, self.dirs, self.phpinfo, self.version = dict(files), set(dirs), phpinfo, version
        self.name = "fake"

    def run(self, cmd, timeout=20, stdin_data=None, binary=False):
        if cmd[-1] == "-i":
            return 0, self.phpinfo, ""
        if cmd[-2:] == ["-n", "-v"]:
            return 0, self.version, ""
        return 1, "", "unsupported"

    def which(self, name):
        return None

    def isfile(self, path):
        return path in self.files

    def isdir(self, path):
        return path in self.dirs

    def exists(self, path):
        return path in self.files or path in self.dirs

    def existing(self, patterns, kind="f"):
        import fnmatch
        pool = self.dirs if kind == "d" else self.files
        return sorted(set(p for p in pool for pat in patterns if fnmatch.fnmatchcase(p, pat)))

    def glob(self, pattern):
        return self.existing([pattern], "f") + self.existing([pattern], "d")

    def read_text(self, path):
        return self.files.get(path)

    def write_text(self, path, text, mode=None):
        self.files[path] = text

    def backup(self, path, bak):
        self.files.setdefault(bak, self.files[path])

    def remove(self, path):
        self.files.pop(path, None)

    def markers(self, path):
        return set()

    def bytes_version(self, path):
        return None

    def where(self, path):
        return "fake:" + path


class ProtectOnContainer(unittest.TestCase):
    POOL = "[www]\nuser = www-data\npm = dynamic\n"
    INFO = ("Loaded Configuration File => (none)\n"
            "Scan this dir for additional .ini files => /usr/local/etc/php/conf.d\n")

    def args(self, **kw):
        import argparse
        base = dict(post_max=None, upload_max=None, memory_unlimited=False, nesting=32, no_fpm_pools=False, no_apache=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_apply_then_rollback_restores_files(self):
        import contextlib
        import io
        ct = FakeContainer({"/usr/local/etc/php-fpm.d/www.conf": self.POOL, "/usr/local/sbin/php-fpm": "ELF"},
                           {"/usr/local/etc/php/conf.d", "/usr/local/etc/php-fpm.d"}, self.INFO)
        bins = [{"path": "/usr/local/sbin/php-fpm", "sources": {"PATH"}}]
        with contextlib.redirect_stdout(io.StringIO()):
            planned, changes = guard.protect_target(self.args(post_max="32M", upload_max="30M"), ct, bins, apply_=True)
        dropin = "/usr/local/etc/php/conf.d/" + guard.DROPIN_NAME
        self.assertEqual(sorted(changes), sorted([dropin, "/usr/local/etc/php-fpm.d/www.conf"]))
        self.assertIn("session.upload_progress.enabled = 0", ct.files[dropin])
        self.assertIn("post_max_size = 32M", ct.files[dropin])
        pool = ct.files["/usr/local/etc/php-fpm.d/www.conf"]
        self.assertIn("php_admin_flag[session.upload_progress.enabled] = off", pool)
        self.assertNotIn("fatal_error_backtraces", pool)  # 8.3 build
        self.assertEqual(ct.files["/usr/local/etc/php-fpm.d/www.conf.php2shell-guard.bak"], self.POOL)
        with contextlib.redirect_stdout(io.StringIO()):
            n = guard.rollback_target(ct, bins, apply_=True)
        self.assertEqual(n, 2)
        self.assertNotIn(dropin, ct.files)
        self.assertEqual(ct.files["/usr/local/etc/php-fpm.d/www.conf"].strip(), self.POOL.strip())

    def test_dry_run_writes_nothing(self):
        import contextlib
        import io
        ct = FakeContainer({"/usr/local/etc/php-fpm.d/www.conf": self.POOL}, {"/usr/local/etc/php/conf.d"}, self.INFO,
                           version="PHP 8.5.3 (cli)")
        before = dict(ct.files)
        bins = [{"path": "/usr/local/sbin/php-fpm", "sources": {"PATH"}}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            planned, changes = guard.protect_target(self.args(), ct, bins, apply_=False)
        self.assertEqual(changes, [])
        self.assertEqual(ct.files, before)
        self.assertIn("/usr/local/etc/php/conf.d/" + guard.DROPIN_NAME, planned)
        self.assertIn("no Apache config dir found", out.getvalue())

    def test_php85_container_pool_gets_backtraces_flag(self):
        import contextlib
        import io
        ct = FakeContainer({"/usr/local/etc/php-fpm.d/www.conf": self.POOL}, {"/usr/local/etc/php/conf.d"}, self.INFO,
                           version="PHP 8.5.3 (cli)")
        with contextlib.redirect_stdout(io.StringIO()):
            guard.protect_target(self.args(), ct, [{"path": "/usr/local/sbin/php-fpm", "sources": {"PATH"}}], apply_=True)
        self.assertIn("php_admin_flag[fatal_error_backtraces] = off", ct.files["/usr/local/etc/php-fpm.d/www.conf"])


if __name__ == "__main__":
    unittest.main()
