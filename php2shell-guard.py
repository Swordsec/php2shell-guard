#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell-guard - scanner, hardening and hunting tool for php2shell
(CVE-2026-109618 "RCE via OOM corruption" / CVE-2026-109619 "RCE via stale
global state").

    scan     audit this host: every PHP binary, running worker, package and
             effective configuration, with a per-install verdict
    protect  apply (or roll back) the php.net-advised mitigations as drop-ins
    hunt     look for exploitation traces (logs, session files, webroots,
             web-worker child processes, cron)
    remote   passive banner scan of your own hosts, optional WAF coverage check
    rules    print ModSecurity / nginx / Apache / HAProxy / Suricata snippets

Python 3.8+, standard library only. No exploit code is included and nothing
in this tool attempts to trigger either vulnerability.

https://github.com/Swordsec/php2shell-guard
"""

from __future__ import print_function

import argparse
import concurrent.futures
import datetime
import glob
import gzip
import hashlib
import io
import json
import mmap
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"
TOOL = "php2shell-guard"
CVES = ("CVE-2026-109618", "CVE-2026-109619")
ADVISORY_URL = "https://www.php.net/archive/2026.php#2026-10-21-5"

# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------

# Upstream fixed releases (php.net, 2026-10-21).
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
# PHP 8.6 pre-releases: RC4 and later carry the fix.
FIXED_86_RC = 4

# Strings that only exist in patched builds.
#   memory_hard_limit_percent  new INI directive added by the full fix (8.2+)
#   zend_mm_safe_error_ex      exported symbol added by the minimal 7.4/8.0/8.1
#                              backports (and used by distro backports)
PATCH_MARKERS = (b"memory_hard_limit_percent", b"zend_mm_safe_error_ex")

# Known fixed Debian/Ubuntu package versions (source package -> versions).
# Backports keep the upstream version string, so these must be compared with
# dpkg semantics against the *package* version, never against `php -v`.
DEB_FIXED = {
    "php8.5": ["8.5.4-0ubuntu1.5", "8.5.9-0ubuntu2.1"],
    "php8.4": ["8.4.27-1~deb13u1", "8.4.27-1"],
    "php8.3": ["8.3.6-0ubuntu0.24.04.13"],
    "php8.2": ["8.2.35-1~deb12u1"],
    "php8.1": ["8.1.2-1ubuntu2.28"],
    "php7.4": ["7.4.3-4ubuntu2.29+esm5"],
    "php7.2": ["7.2.24-0ubuntu0.18.04.17+esm14"],
    "php7.0": ["7.0.33-0ubuntu0.16.04.16+esm22"],
    "php5": ["5.5.9+dfsg-1ubuntu4.29+esm18"],
}

# Known fixed RPM builds (version-release). Module builds are matched on
# upstream version + el major + module build id, plain builds on
# version-release with rpm semantics. Changelog CVE references win over this.
RPM_FIXED = [
    # AlmaLinux 8
    "7.2.24-1.module_el8.10.0+4315+7b734bf3.alma.1",
    "7.3.20-1.module_el8.10.0+4316+90ea5fe5.alma.1",
    "7.4.33-8.module_el8.10.0+4321+cf5fd4bb",
    "8.0.30-1.module_el8.10.0+4319+26f10322.alma.1",
    "8.2.33-1.module_el8.10.0+4320+c30d6dbb.alma.1",
    # AlmaLinux 9
    "8.0.30-8.el9_8.alma.1",
    "8.1.32-1.module_el9.8.0+326+528679fc.alma.1",
    "8.2.33-1.module_el9.8.0+327+37dfd4b4.alma.1",
    "8.3.33-1.module_el9.8.0+328+1fdeb728.alma.1",
    # AlmaLinux 10
    "8.3.33-1.el10_2.alma.1",
    "8.4.24-1.el10_2.alma.1",
]

INI_KEYS = [
    "session.upload_progress.enabled",
    "fatal_error_backtraces",
    "memory_limit",
    "memory_hard_limit_percent",
    "post_max_size",
    "upload_max_filesize",
    "file_uploads",
    "max_file_uploads",
    "max_input_nesting_level",
    "max_input_vars",
    "session.save_path",
    "session.save_handler",
    "session.use_only_cookies",
    "session.use_strict_mode",
    "opcache.enable",
]

BIN_NAME_RE = re.compile(
    r"^(php|lsphp)(\d{1,2}(\.\d)?)?(-fpm|-cgi|-cli)?(\d{1,2}(\.\d)?)?(\.exe)?$|^frankenphp(\.exe)?$"
)

BIN_GLOBS = [
    # Linux distro layouts
    "/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/sbin/php*-fpm", "/usr/lib/cgi-bin/php*",
    "/usr/local/bin/php*", "/usr/local/sbin/php-fpm*", "/usr/local/bin/frankenphp",
    # Remi / SCL
    "/opt/remi/php*/root/usr/bin/php*", "/opt/remi/php*/root/usr/sbin/php-fpm",
    "/opt/rh/rh-php*/root/usr/bin/php*", "/opt/rh/rh-php*/root/usr/sbin/php-fpm",
    # cPanel EasyApache 4
    "/opt/cpanel/ea-php*/root/usr/bin/php*", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
    "/opt/cpanel/ea-php*/root/usr/bin/lsphp",
    # Plesk
    "/opt/plesk/php/*/bin/php*", "/opt/plesk/php/*/sbin/php-fpm",
    # LiteSpeed / OpenLiteSpeed / CyberPanel
    "/usr/local/lsws/lsphp*/bin/lsphp", "/usr/local/lsws/lsphp*/bin/php*",
    "/usr/local/lsws/fcgi-bin/lsphp*",
    # DirectAdmin
    "/usr/local/php*/bin/php*", "/usr/local/php*/sbin/php-fpm*",
    # ISPConfig / custom source builds
    "/opt/php-*/bin/php*", "/opt/php*/sbin/php-fpm*", "/opt/php/*/bin/php*",
    # macOS Homebrew / MacPorts / MAMP / XAMPP
    "/opt/homebrew/opt/php*/bin/php*", "/opt/homebrew/opt/php*/sbin/php-fpm",
    "/usr/local/opt/php*/bin/php*", "/usr/local/opt/php*/sbin/php-fpm",
    "/opt/local/bin/php*", "/Applications/MAMP/bin/php/php*/bin/php*",
    "/Applications/XAMPP/xamppfiles/bin/php*", "/Applications/ServBay/package/php/*/*/bin/php*",
    # Docker official images
    "/usr/local/bin/php", "/usr/local/sbin/php-fpm",
    # FreeBSD
    "/usr/local/bin/php-cgi",
]
WIN_BIN_GLOBS = [
    r"C:\php*\php.exe", r"C:\php*\php-cgi.exe", r"C:\xampp\php\php.exe",
    r"C:\laragon\bin\php\*\php.exe", r"C:\MAMP\bin\php\*\php.exe",
    r"C:\Program Files\PHP\*\php.exe", r"C:\Program Files (x86)\PHP\*\php.exe",
    r"C:\wamp*\bin\php\*\php.exe", r"C:\tools\php*\php.exe",
    r"C:\inetpub\PHP\*\php-cgi.exe",
]
MODULE_GLOBS = [
    "/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
    "/usr/lib/httpd/modules/libphp*.so", "/etc/httpd/modules/libphp*.so",
    "/usr/local/apache/modules/libphp*.so", "/opt/cpanel/ea-php*/root/usr/lib64/apache2/modules/libphp*.so",
    "/usr/local/libexec/apache24/libphp*.so", "/opt/homebrew/opt/php*/lib/httpd/modules/libphp.so",
    "/usr/local/opt/php*/lib/httpd/modules/libphp.so", "/Applications/XAMPP/xamppfiles/modules/libphp*.so",
]

CONFD_GLOBS = [
    "/etc/php/*/*/conf.d",                      # Debian/Ubuntu per-SAPI
    "/etc/php.d",                               # RHEL family
    "/etc/php*/conf.d", "/etc/php*/*/conf.d",   # openSUSE, Alpine (/etc/php83/conf.d)
    "/etc/opt/remi/php*/php.d",                 # Remi SCL
    "/opt/cpanel/ea-php*/root/etc/php.d",       # cPanel EA4
    "/opt/plesk/php/*/etc/php.d",               # Plesk
    "/usr/local/lsws/lsphp*/etc/php.d",         # LiteSpeed (RPM)
    "/usr/local/lsws/lsphp*/etc/php/*/litespeed/conf.d",  # LiteSpeed (DEB)
    "/usr/local/etc/php/conf.d",                # Docker official images
    "/usr/local/php*/lib/php.conf.d",           # DirectAdmin
    "/usr/local/etc/php/conf.d",                # FreeBSD
    "/opt/homebrew/etc/php/*/conf.d", "/usr/local/etc/php/*/conf.d",  # Homebrew
]
FPM_POOL_GLOBS = [
    "/etc/php/*/fpm/pool.d/*.conf", "/etc/php-fpm.d/*.conf", "/etc/php*/php-fpm.d/*.conf",
    "/etc/opt/remi/php*/php-fpm.d/*.conf", "/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
    "/opt/plesk/php/*/etc/php-fpm.d/*.conf", "/usr/local/etc/php-fpm.d/*.conf",
    "/usr/local/php*/etc/php-fpm.d/*.conf", "/opt/homebrew/etc/php/*/php-fpm.d/*.conf",
    "/usr/local/etc/php/*/php-fpm.d/*.conf",
]
APACHE_CONF_DIRS = [
    "/etc/apache2", "/etc/httpd", "/usr/local/apache/conf", "/usr/local/etc/apache24",
    "/etc/apache24", "/opt/homebrew/etc/httpd", "/usr/local/etc/httpd", "/etc/httpd24",
]
SESSION_DIR_CANDIDATES = [
    "/var/lib/php/sessions", "/var/lib/php/session", "/var/lib/php*/sessions",
    "/var/lib/php*/session", "/var/lib/php/*/sessions", "/var/opt/remi/php*/lib/php/session",
    "/var/cpanel/php/sessions/ea-php*", "/opt/plesk/php/*/var/lib/php/session",
    "/var/lib/php/sessions/*", "/tmp", "/var/tmp",
]
ERROR_LOG_GLOBS = [
    "/var/log/apache2/error.log*", "/var/log/apache2/*error*.log*", "/var/log/httpd/error_log*",
    "/var/log/httpd/*error_log*", "/var/log/php*-fpm.log*", "/var/log/php-fpm/*.log*",
    "/var/log/php/*.log*", "/var/log/php_errors.log*", "/var/log/php*.log*",
    "/var/log/nginx/error.log*", "/var/log/lsws/error.log*", "/usr/local/lsws/logs/error.log*",
    "/usr/local/apache/logs/error_log*", "/var/www/vhosts/system/*/logs/error_log*",
    "/var/opt/remi/php*/log/php-fpm/error.log*", "/opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log*",
    "/var/log/messages*", "/var/log/syslog*",
]

WEB_WORKER_NAMES = ("apache2", "httpd", "php-fpm", "php-cgi", "lsphp", "litespeed", "lshttpd",
                    "frankenphp", "nginx", "caddy", "sw-engine-fpm")
SHELL_NAMES = ("sh", "bash", "dash", "zsh", "ksh", "ash", "perl", "python", "python3", "nc",
               "ncat", "netcat", "socat", "curl", "wget", "telnet", "ruby", "lua")

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.name != "nt"


def c(text, color):
    if not USE_COLOR:
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
             "cyan": "36", "bold": "1", "dim": "2", "white": "37"}
    return "\033[%sm%s\033[0m" % (codes[color], text)


SEV_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim", "OK": "green"}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}


def sev(label):
    return c("[%-8s]" % label, SEV_COLOR.get(label, "white"))


def banner(title):
    print(c("== %s ==" % title, "bold"))


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def run(cmd, timeout=20, env_extra=None, stdin_data=None):
    """Run a command, return (rc, stdout, stderr). Never raises."""
    env = dict(os.environ)
    env.setdefault("LC_ALL", "C")
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           env=env, input=stdin_data)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def which(name):
    return shutil.which(name)


def expand_globs(patterns):
    out = []
    for p in patterns:
        out.extend(glob.glob(p))
    return out


# --------------------------------------------------------------------------
# Version logic
# --------------------------------------------------------------------------

VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:[-~+.]?(RC|rc|alpha|beta|dev)[-.]?(\d*))?")


def parse_version(s):
    """Return (major, minor, patch, pre_tag, pre_num) or None."""
    m = VERSION_RE.search(s or "")
    if not m:
        return None
    tag = (m.group(4) or "").lower() or None
    num = int(m.group(5)) if m.group(5) else 0
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), tag, num)


def classify_version(vstr):
    """Classify a PHP version string by the upstream fixed-release table.

    Returns (status, reason). status in: patched, vulnerable, eol, unknown.
    'eol' means the branch has no upstream release and needs a vendor
    backport (which the package/fingerprint checks may still confirm).
    """
    v = parse_version(vstr)
    if not v:
        return "unknown", "could not parse version"
    major, minor, patch, tag, num = v
    branch = (major, minor)
    if (major, minor) < (8, 2):
        return "eol", "branch %d.%d has no upstream fix (vendor backport required)" % (major, minor)
    if branch in FIXED:
        fixed = FIXED[branch]
        if (major, minor, patch) > fixed:
            return "patched", "%d.%d.%d > %s" % (major, minor, patch, ".".join(map(str, fixed)))
        if (major, minor, patch) == fixed:
            if tag:
                return "vulnerable", "pre-release %s of fixed version %s" % (vstr, ".".join(map(str, fixed)))
            return "patched", "fixed release"
        return "vulnerable", "%d.%d.%d < %s" % (major, minor, patch, ".".join(map(str, fixed)))
    if branch == (8, 6):
        if tag in ("rc",) and num >= FIXED_86_RC:
            return "patched", "8.6.0RC%d or later carries the fix" % FIXED_86_RC
        if tag is None and patch >= 0:
            return "patched", "8.6 GA includes the fix"
        return "vulnerable", "8.6 pre-release before RC4"
    if (major, minor) > (8, 6):
        return "patched", "released after the fix"
    return "unknown", "unhandled branch"


# Debian version comparison (dpkg algorithm, pure python so it is testable).

def _deb_order(ch):
    if ch == "~":
        return -1
    if ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _deb_cmp_fragment(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i]) if (i < len(a) and not a[i].isdigit()) else 0
            bc = _deb_order(b[j]) if (j < len(b) and not b[j].isdigit()) else 0
            if ac != bc:
                return ac - bc
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        na = nb = ""
        while i < len(a) and a[i].isdigit():
            na += a[i]
            i += 1
        while j < len(b) and b[j].isdigit():
            nb += b[j]
            j += 1
        da, db = int(na or "0"), int(nb or "0")
        if da != db:
            return da - db
    return 0


def _deb_split(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def deb_cmp(a, b):
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return ea - eb
    r = _deb_cmp_fragment(ua, ub)
    if r:
        return r
    return _deb_cmp_fragment(ra, rb)


# RPM version comparison (rpmvercmp semantics, simplified but order-correct).

def _rpm_segs(s):
    return re.findall(r"[0-9]+|[a-zA-Z]+|~|\^", s or "")


def rpm_vercmp(a, b):
    sa, sb = _rpm_segs(a), _rpm_segs(b)
    for x, y in zip(sa, sb):
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x == "^" or y == "^":
            if x != y:
                return -1 if x == "^" else 1
            continue
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            if int(x) != int(y):
                return 1 if int(x) > int(y) else -1
        elif xd != yd:
            return 1 if xd else -1
        else:
            if x != y:
                return 1 if x > y else -1
    if len(sa) == len(sb):
        return 0
    longer_is_a = len(sa) > len(sb)
    rest = sa[len(sb):] if longer_is_a else sb[len(sa):]
    if rest[0] == "~":
        return -1 if longer_is_a else 1
    return 1 if longer_is_a else -1


def rpm_evr_cmp(a, b):
    def split(v):
        epoch = "0"
        if ":" in v:
            epoch, v = v.split(":", 1)
        if "-" in v:
            ver, rel = v.rsplit("-", 1)
        else:
            ver, rel = v, ""
        return int(epoch or "0"), ver, rel
    ea, va, ra = split(a)
    eb, vb, rb = split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    r = rpm_vercmp(va, vb)
    if r:
        return r
    return rpm_vercmp(ra, rb)


MODULE_REL_RE = re.compile(r"module\+?_?el(\d+)\.\d+\.\d+\+(\d+)\+")


def rpm_matches_fixed(vr):
    """Heuristic match of an installed version-release against RPM_FIXED."""
    up = vr.split("-", 1)[0]
    for fixed in RPM_FIXED:
        fup = fixed.split("-", 1)[0]
        if fup != up:
            continue
        m_inst, m_fix = MODULE_REL_RE.search(vr), MODULE_REL_RE.search(fixed)
        if m_fix:
            if not m_inst or m_inst.group(1) != m_fix.group(1):
                continue
            if int(m_inst.group(2)) >= int(m_fix.group(2)):
                return fixed
            continue
        el_inst = re.search(r"\.el(\d+)", vr)
        el_fix = re.search(r"\.el(\d+)", fixed)
        if el_inst and el_fix and el_inst.group(1) != el_fix.group(1):
            continue
        if rpm_evr_cmp(vr, fixed) >= 0:
            return fixed
    return None


# --------------------------------------------------------------------------
# Binary discovery and inspection
# --------------------------------------------------------------------------

def read_marker_hits(path, limit=400 * 1024 * 1024):
    """Return the set of PATCH_MARKERS found in a binary (by byte search)."""
    hits = set()
    try:
        size = os.path.getsize(path)
        if size == 0 or size > limit:
            return hits
        with open(path, "rb") as fh:
            try:
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except (ValueError, OSError):
                data = fh.read()
                for m in PATCH_MARKERS:
                    if m in data:
                        hits.add(m.decode())
                return hits
            try:
                for m in PATCH_MARKERS:
                    if mm.find(m) != -1:
                        hits.add(m.decode())
            finally:
                mm.close()
    except OSError:
        pass
    return hits


def version_from_bytes(path):
    """Fallback: find the compile-time 'X-Powered-By: PHP/x.y.z' literal."""
    try:
        with open(path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                m = re.search(rb"X-Powered-By: PHP/(\d+\.\d+\.\d+(?:[-~]?(?:RC|rc|alpha|beta|dev)\d*)?)", mm)
                if m:
                    return m.group(1).decode()
                m = re.search(rb"PHP/(\d+\.\d+\.\d+)", mm)
                return m.group(1).decode() if m else None
            finally:
                mm.close()
    except (OSError, ValueError):
        return None


def binary_kind(path):
    base = os.path.basename(path).lower()
    if base.endswith(".so") or base.endswith(".dll"):
        return "module"
    if "fpm" in base:
        return "fpm"
    if "cgi" in base:
        return "cgi"
    if base.startswith("lsphp"):
        return "lsapi"
    if base.startswith("frankenphp"):
        return "frankenphp"
    return "cli"


def php_version_of(path, kind):
    if kind == "module":
        return version_from_bytes(path), "bytes"
    if kind == "frankenphp":
        rc, out, err = run([path, "version"], timeout=15)
        m = re.search(r"PHP (\d+\.\d+\.\d+\S*)", out + err)
        if m:
            return m.group(1), "frankenphp version"
    rc, out, err = run([path, "-n", "-v"], timeout=15)
    m = re.search(r"PHP (\d+\.\d+\.\d+[^\s]*)", out + err)
    if m:
        return m.group(1).rstrip(","), "-v"
    v = version_from_bytes(path)
    return v, "bytes" if v else "none"


def find_php_binaries():
    """Discover PHP executables and Apache PHP modules on this host."""
    found = {}

    def add(p, source):
        try:
            rp = os.path.realpath(p)
            if not os.path.isfile(rp):
                return
            if rp in found:
                found[rp]["sources"].add(source)
                return
            if not os.access(rp, os.R_OK):
                found[rp] = {"path": rp, "sources": {source}, "unreadable": True}
                return
            found[rp] = {"path": rp, "sources": {source}}
        except OSError:
            pass

    for d in os.environ.get("PATH", "").split(os.pathsep):
        try:
            for n in os.listdir(d):
                if BIN_NAME_RE.match(n):
                    add(os.path.join(d, n), "PATH")
        except OSError:
            continue
    globs = WIN_BIN_GLOBS if os.name == "nt" else BIN_GLOBS
    for p in expand_globs(globs):
        if BIN_NAME_RE.match(os.path.basename(p)) and not os.path.isdir(p):
            add(p, "path-glob")
    for p in expand_globs(MODULE_GLOBS):
        add(p, "module-glob")
    # Apache LoadModule lines
    for conf in iter_conf_files(APACHE_CONF_DIRS):
        try:
            with open(conf, "r", errors="replace") as fh:
                for line in fh:
                    m = re.match(r"\s*LoadModule\s+php\w*_module\s+\"?([^\s\"]+)", line)
                    if m:
                        mp = m.group(1)
                        if not os.path.isabs(mp):
                            for root in APACHE_CONF_DIRS:
                                cand = os.path.join(root, mp)
                                if os.path.exists(cand):
                                    mp = cand
                                    break
                        add(mp, "LoadModule:" + conf)
        except OSError:
            continue
    for proc in running_processes():
        if proc["exe"] and (BIN_NAME_RE.match(os.path.basename(proc["exe"])) or
                            re.search(r"(libphp|mod_php)", proc["exe"])):
            add(proc["exe"], "process")
        for mod in proc.get("php_modules", []):
            add(mod, "process-maps")
    return list(found.values())


def iter_conf_files(dirs, exts=(".conf", ".htaccess", ".ini")):
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for f in files:
                if f.endswith(exts) or f == ".htaccess":
                    yield os.path.join(root, f)


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------

_PROC_CACHE = None


def running_processes():
    """List processes of interest with exe path, deleted-binary flag and
    loaded PHP modules (Linux /proc; ps fallback elsewhere)."""
    global _PROC_CACHE
    if _PROC_CACHE is not None:
        return _PROC_CACHE
    procs = []
    if os.path.isdir("/proc") and platform.system() == "Linux":
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            base = "/proc/" + pid
            try:
                with open(base + "/comm", "r", errors="replace") as fh:
                    comm = fh.read().strip()
            except OSError:
                continue
            interesting = (BIN_NAME_RE.match(comm) or comm in WEB_WORKER_NAMES or
                           comm.startswith(("php", "lsphp", "apache", "httpd", "frankenphp")))
            if not interesting:
                continue
            exe, deleted = None, False
            try:
                exe = os.readlink(base + "/exe")
                if exe.endswith(" (deleted)"):
                    deleted = True
                    exe = exe[:-10]
            except OSError:
                pass
            ppid, cmdline = None, ""
            try:
                with open(base + "/stat", "r") as fh:
                    st = fh.read()
                ppid = int(st.rsplit(")", 1)[1].split()[1])
                with open(base + "/cmdline", "rb") as fh:
                    cmdline = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            except (OSError, IndexError, ValueError):
                pass
            php_modules, module_deleted = [], False
            if comm in ("apache2", "httpd", "litespeed", "lshttpd", "nginx", "caddy") or comm.startswith("apache"):
                try:
                    with open(base + "/maps", "r", errors="replace") as fh:
                        for line in fh:
                            if re.search(r"(libphp[^/\s]*\.so|mod_php[^/\s]*\.so)", line):
                                mp = line.split(None, 5)[-1].strip()
                                if mp.endswith(" (deleted)"):
                                    module_deleted = True
                                    mp = mp[:-10]
                                if mp not in php_modules:
                                    php_modules.append(mp)
                except OSError:
                    pass
            user = None
            try:
                st_ = os.stat(base)
                user = str(st_.st_uid)
                try:
                    import pwd
                    user = pwd.getpwuid(st_.st_uid).pw_name
                except (ImportError, KeyError):
                    pass
            except OSError:
                pass
            procs.append({"pid": int(pid), "ppid": ppid, "comm": comm, "exe": exe, "deleted": deleted,
                          "cmdline": cmdline, "php_modules": php_modules,
                          "module_deleted": module_deleted, "user": user})
    else:
        rc, out, _ = run(["ps", "-axo", "pid=,ppid=,user=,comm=,args="], timeout=15)
        if rc == 0:
            for line in out.splitlines():
                parts = line.split(None, 4)
                if len(parts) < 4:
                    continue
                pid, ppid, user, comm = parts[0], parts[1], parts[2], parts[3]
                args = parts[4] if len(parts) > 4 else ""
                name = os.path.basename(comm)
                if not (BIN_NAME_RE.match(name) or name in WEB_WORKER_NAMES or
                        name.startswith(("php", "lsphp", "httpd", "apache"))):
                    continue
                exe = comm if os.path.isabs(comm) else which(name)
                procs.append({"pid": int(pid), "ppid": int(ppid), "comm": name, "exe": exe, "deleted": False,
                              "cmdline": args, "php_modules": [], "module_deleted": False, "user": user})
    _PROC_CACHE = procs
    return procs


# --------------------------------------------------------------------------
# Package managers
# --------------------------------------------------------------------------

def changelog_mentions_cve(paths):
    for p in paths:
        try:
            opener = gzip.open if p.endswith(".gz") else open
            with opener(p, "rb") as fh:
                data = fh.read(400000)
            if re.search(rb"CVE-2026-10961[89]|php2shell", data, re.I):
                return p
        except OSError:
            continue
    return None


def check_dpkg():
    if not which("dpkg-query"):
        return []
    rc, out, _ = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Status}\t${Source}\n", "php*",
                      "libapache2-mod-php*"], timeout=30)
    if rc != 0:
        return []
    results = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or parts[2] != "installed":
            continue
        pkg, ver = parts[0], parts[1]
        src = (parts[3] or "").split(" ")[0] if len(parts) > 3 else ""
        m = re.match(r"^(?:libapache2-mod-)?(php\d(?:\.\d)?)(?:-(?:fpm|cli|cgi|common|phpdbg|dev))?$", pkg)
        if not m:
            continue
        srcpkg = src or m.group(1)
        if srcpkg == "php":
            # Debian meta-package; the real version comes from phpX.Y
            continue
        status, how = "unknown", "package version not in the known-fixed table"
        up = _deb_split(ver)[1]
        up_base = re.match(r"\d+\.\d+\.\d+", up)
        for fixed in DEB_FIXED.get(srcpkg, []):
            fup = _deb_split(fixed)[1]
            if up.split("+")[0] == fup.split("+")[0] or (up_base and fup.startswith(up_base.group(0))):
                status = "patched" if deb_cmp(ver, fixed) >= 0 else "vulnerable"
                how = "%s %s %s (dpkg)" % (ver, ">=" if status == "patched" else "<", fixed)
                break
        if status == "unknown":
            vs, _ = classify_version(up)
            if vs == "patched":
                status, how = "patched", "upstream version %s is a fixed release" % up
            elif vs == "vulnerable":
                status, how = "vulnerable", "upstream version %s predates the fix and no known backport matches" % up
        if status != "patched":
            cl = changelog_mentions_cve(["/usr/share/doc/%s/changelog.Debian.gz" % pkg,
                                         "/usr/share/doc/%s/changelog.gz" % pkg])
            if cl:
                status, how = "patched", "changelog references the CVE (%s)" % cl
        results.append({"manager": "dpkg", "package": pkg, "version": ver, "status": status, "detail": how})
    return results


def check_rpm():
    if not which("rpm"):
        return []
    rc, out, _ = run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\n",
                      "php*", "*-php", "*-php-common", "*-php-fpm", "*-php-cli", "plesk-php*", "ea-php*"], timeout=40)
    if rc != 0:
        return []
    results, seen = [], set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        name, epoch, vr = parts
        if not re.match(r"^(php|php\d\d|php\d\.\d|rh-php\d\d-php|ea-php\d\d-php|plesk-php\d\d(-cli|-fpm|-cgi)?|php\d\d-php)(-common|-fpm|-cli|-cgi)?$", name):
            continue
        key = (name, vr)
        if key in seen:
            continue
        seen.add(key)
        status, how = "unknown", "build not in the known-fixed table"
        rc2, cl, _ = run(["rpm", "-q", "--changelog", name], timeout=30)
        if rc2 == 0 and re.search(r"CVE-2026-10961[89]|php2shell", cl, re.I):
            status, how = "patched", "rpm changelog references the CVE"
        else:
            fixed = rpm_matches_fixed(vr)
            if fixed:
                status, how = "patched", "matches known fixed build %s" % fixed
            else:
                vs, why = classify_version(vr.split("-", 1)[0])
                if vs == "patched":
                    status, how = "patched", "upstream version is a fixed release"
                elif vs == "vulnerable":
                    status, how = "vulnerable", why
                elif vs == "eol":
                    status, how = "unknown", "EOL branch; no CVE reference in changelog and no known fixed build matched"
        results.append({"manager": "rpm", "package": name, "version": vr if epoch in ("(none)", "0", "") else "%s:%s" % (epoch, vr),
                        "status": status, "detail": how})
    return results


def check_apk():
    if not which("apk"):
        return []
    rc, out, _ = run(["apk", "info", "-v"], timeout=30)
    results = []
    for line in out.splitlines():
        m = re.match(r"^(php\d\d(?:-(?:fpm|cgi|common|phpdbg))?)-(\d+\.\d+\.\d+)(-r\d+)$", line.strip())
        if not m:
            continue
        vs, why = classify_version(m.group(2))
        status = "patched" if vs == "patched" else ("vulnerable" if vs == "vulnerable" else "unknown")
        results.append({"manager": "apk", "package": m.group(1), "version": m.group(2) + m.group(3),
                        "status": status, "detail": why})
    return results


def check_pacman():
    if not which("pacman"):
        return []
    rc, out, _ = run(["pacman", "-Q"], timeout=30)
    results = []
    for line in out.splitlines():
        m = re.match(r"^(php(?:-legacy|\d\d)?(?:-fpm|-cgi)?)\s+(\S+)$", line.strip())
        if not m:
            continue
        vs, why = classify_version(m.group(2))
        status = "patched" if vs == "patched" else ("vulnerable" if vs == "vulnerable" else "unknown")
        results.append({"manager": "pacman", "package": m.group(1), "version": m.group(2), "status": status, "detail": why})
    return results


def check_brew():
    if not which("brew"):
        return []
    rc, out, _ = run(["brew", "list", "--versions"], timeout=60)
    results = []
    for line in out.splitlines():
        m = re.match(r"^(php(?:@\d\.\d)?)\s+(\S+)", line.strip())
        if not m:
            continue
        vs, why = classify_version(m.group(2))
        status = "patched" if vs == "patched" else ("vulnerable" if vs == "vulnerable" else "unknown")
        results.append({"manager": "brew", "package": m.group(1), "version": m.group(2), "status": status, "detail": why})
    return results


def check_packages():
    out = []
    for fn in (check_dpkg, check_rpm, check_apk, check_pacman, check_brew):
        try:
            out.extend(fn())
        except Exception as e:  # pragma: no cover - defensive
            out.append({"manager": fn.__name__, "package": "?", "version": "?", "status": "unknown", "detail": "error: %s" % e})
    return out


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def ini_bool(v):
    if v is None:
        return None
    s = str(v).strip().strip('"').lower()
    if s in ("1", "on", "true", "yes"):
        return True
    if s in ("0", "off", "false", "no", "", "none"):
        return False
    return None


def ini_bytes(v):
    if v is None:
        return None
    s = str(v).strip().strip('"').lower()
    m = re.match(r"^(-?\d+)\s*([kmg]?)$", s)
    if not m:
        return None
    n = int(m.group(1))
    return n * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2)]


def parse_phpinfo_text(text):
    """Parse `php -i` style output into {directive: (local, master)} plus
    ini file info."""
    conf = {}
    info = {"ini_file": None, "scan_dir": None, "additional": []}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^([\w.]+) => (.*?) => (.*)$", line)
        if m and m.group(1) in INI_KEYS:
            conf[m.group(1)] = (m.group(2).strip(), m.group(3).strip())
            continue
        m = re.match(r"^([\w .]+?) => (.*)$", line)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if k == "Loaded Configuration File":
                info["ini_file"] = None if v == "(none)" else v
            elif k == "Scan this dir for additional .ini files":
                info["scan_dir"] = None if v == "(none)" else v
            elif k == "Additional .ini files parsed":
                info["additional"] = [] if v == "(none)" else [x.strip() for x in v.split(",") if x.strip()]
            elif k in INI_KEYS:
                conf[k] = (v, v)
    return conf, info


def effective_ini_from_binary(path, kind):
    """Ask the binary itself for its effective configuration (`-i`)."""
    if kind == "module":
        return None, None, "module (no executable)"
    if kind == "frankenphp":
        rc, out, err = run([path, "php-cli", "-i"], timeout=20)
    else:
        rc, out, err = run([path, "-i"], timeout=20)
    if rc != 0 and "=>" not in out:
        return None, None, (err.strip().splitlines() or ["-i failed"])[-1]
    conf, info = parse_phpinfo_text(out)
    return conf, info, None


def parse_ini_file(path):
    vals = {}
    try:
        with open(path, "r", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line[0] in ";#[":
                    continue
                m = re.match(r"^([\w.]+)\s*=\s*(.*?)\s*(?:;.*)?$", line)
                if m:
                    vals[m.group(1)] = m.group(2).strip().strip('"')
    except OSError:
        pass
    return vals


def resolve_static_ini(ini_file, scan_dir):
    """Resolve php.ini + scan dir drop-ins the way PHP does (alphabetical)."""
    vals, files = {}, []
    if ini_file and os.path.isfile(ini_file):
        vals.update(parse_ini_file(ini_file))
        files.append(ini_file)
    if scan_dir and os.path.isdir(scan_dir):
        for f in sorted(glob.glob(os.path.join(scan_dir, "*.ini"))):
            vals.update(parse_ini_file(f))
            files.append(f)
    conf = {k: (v, v) for k, v in vals.items() if k in INI_KEYS}
    return conf, files


def sapi_ini_dirs_for(path):
    """For a binary, guess sibling per-SAPI ini dirs (Debian layout)."""
    out = []
    m = re.search(r"/etc/php/(\d\.\d)/", path)
    if m:
        for s in ("apache2", "fpm", "cgi", "litespeed", "embed"):
            d = "/etc/php/%s/%s" % (m.group(1), s)
            if os.path.isdir(d):
                out.append((s, os.path.join(d, "php.ini"), os.path.join(d, "conf.d")))
    return out


def fpm_pool_overrides(fpm_bin):
    """Dump FPM config with -tt and collect per-pool overrides."""
    rc, out, err = run([fpm_bin, "-tt"], timeout=20)
    text = out + err
    pools, cur = {}, None
    for line in text.splitlines():
        m = re.search(r"NOTICE: \[([^\]]+)\]\s*$", line)
        if m:
            cur = m.group(1)
            pools.setdefault(cur, {})
            continue
        if cur is None:
            continue
        m = re.search(r"NOTICE:\s+(php_(?:admin_)?(?:value|flag))\[([^\]]+)\]\s*=\s*(.*)$", line)
        if m:
            pools[cur][m.group(2)] = (m.group(1), m.group(3).strip())
            continue
        m = re.search(r"NOTICE:\s+(pm\.max_requests|pm|pm\.max_children|listen|user)\s*=\s*(.*)$", line)
        if m:
            pools[cur][m.group(1)] = ("setting", m.group(2).strip())
    ok = rc == 0 and ("test is successful" in text or pools)
    return pools, ok, (text.strip().splitlines() or [""])[-1]


def scan_apache_configs():
    findings, seen_files, seen_keys = [], set(), set()
    for conf in iter_conf_files(APACHE_CONF_DIRS, exts=(".conf", ".htaccess")):
        real = os.path.realpath(conf)
        if real in seen_files:
            continue
        seen_files.add(real)
        try:
            with open(conf, "r", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    m = re.match(r"(php_(?:admin_)?(?:value|flag))\s+(session\.upload_progress\.enabled|memory_limit|post_max_size|upload_max_filesize|fatal_error_backtraces|max_input_nesting_level)\s+(\S+)", s, re.I)
                    if m:
                        key = (real, m.group(1).lower(), m.group(2).lower(), m.group(3).lower())
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        findings.append({"file": conf, "line": n, "kind": m.group(1).lower(), "key": m.group(2).lower(), "value": m.group(3)})
                    m = re.match(r"(RLimitMEM)\s+(.*)", s, re.I)
                    if m:
                        findings.append({"file": conf, "line": n, "kind": "rlimitmem", "key": "RLimitMEM", "value": m.group(2)})
                    m = re.match(r"(LimitRequestBody)\s+(\d+)", s, re.I)
                    if m:
                        findings.append({"file": conf, "line": n, "kind": "limitrequestbody", "key": "LimitRequestBody", "value": m.group(2)})
        except OSError:
            continue
    return findings


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def assess_install(entry, procs, pkgs, no_config=False):
    path = entry["path"]
    kind = binary_kind(path)
    res = {"path": path, "kind": kind, "sources": sorted(entry["sources"]), "version": None,
           "version_source": None, "version_status": None, "version_reason": None,
           "fingerprint": [], "running": [], "stale_running": False, "config": None, "config_note": None,
           "sapi_configs": [], "fpm_pools": None, "findings": [], "verdict": None}
    if entry.get("unreadable"):
        res["verdict"] = "UNKNOWN"
        res["findings"].append(("INFO", "binary not readable (run as root for a full check)", ""))
        return res
    ver, how = php_version_of(path, kind)
    res["version"], res["version_source"] = ver, how
    st, why = classify_version(ver or "")
    res["version_status"], res["version_reason"] = st, why
    res["fingerprint"] = sorted(read_marker_hits(path))

    for p in procs:
        if p["exe"] == path or path in p.get("php_modules", []):
            res["running"].append(p["pid"])
            if p["deleted"] or (path in p.get("php_modules", []) and p["module_deleted"]):
                res["stale_running"] = True

    # effective config
    if not no_config:
        conf, info, note = effective_ini_from_binary(path, kind)
        res["config_note"] = note
        if conf is not None:
            res["config"] = {k: v[0] for k, v in conf.items()}
            res["config_files"] = info
        elif kind == "module":
            # Debian: /etc/php/X.Y/apache2 ; RHEL: shared /etc/php.ini
            cands = []
            m = re.search(r"libphp(\d\.\d)", path)
            if m:
                cands.append(("apache2", "/etc/php/%s/apache2/php.ini" % m.group(1), "/etc/php/%s/apache2/conf.d" % m.group(1)))
            for pat in ("/etc/php/*/apache2",):
                for d in glob.glob(pat):
                    cands.append(("apache2", d + "/php.ini", d + "/conf.d"))
            if os.path.isfile("/etc/php.ini"):
                cands.append(("apache2", "/etc/php.ini", "/etc/php.d"))
            for sapi, ini, scan in cands:
                c_, files = resolve_static_ini(ini, scan)
                if files:
                    res["config"] = {k: v[0] for k, v in c_.items()}
                    # PHP defaults for directives the ini files leave commented out
                    res["config"].setdefault("session.upload_progress.enabled", "On (default)")
                    res["config_files"] = {"ini_file": ini, "scan_dir": scan, "additional": files[1:]}
                    res["config_note"] = "static parse of %s (+%d drop-ins)" % (ini, len(files) - 1)
                    break
        if kind == "cli":
            for sapi, ini, scan in sapi_ini_dirs_for(res.get("config_files", {}).get("ini_file") or ""):
                c_, files = resolve_static_ini(ini, scan)
                if files:
                    res["sapi_configs"].append({"sapi": sapi, "ini_file": ini, "config": {k: v[0] for k, v in c_.items()}})
        if kind == "fpm":
            pools, ok, last = fpm_pool_overrides(path)
            res["fpm_pools"] = {"pools": pools, "ok": ok, "note": last}

    # verdict
    patched_build = bool(res["fingerprint"])
    if patched_build:
        res["verdict"] = "PATCHED"
    elif st == "patched":
        res["verdict"] = "PATCHED"
        res["findings"].append(("LOW", "version is a fixed release but neither patch marker was found in the binary",
                                "unusual for an upstream build; verify the package origin"))
    elif st == "vulnerable":
        res["verdict"] = "VULNERABLE"
    elif st == "eol":
        # maybe a vendor backport: look at package results for this branch
        res["verdict"] = "VULNERABLE"
        v = parse_version(ver or "")
        if v:
            for pk in pkgs:
                if pk["status"] == "patched" and re.search(r"%d\.?%d" % (v[0], v[1]), pk["package"] + pk["version"]):
                    res["verdict"] = "PATCHED"
                    res["findings"].append(("INFO", "vendor backport confirmed by package check (%s %s)" % (pk["package"], pk["version"]), ""))
                    break
        if res["verdict"] == "VULNERABLE":
            res["findings"].append(("CRITICAL", "EOL branch without a confirmed vendor backport",
                                    "upgrade to PHP 8.2+ or obtain an LTS backport; the minimal upstream backport branches exist for 7.4/8.0/8.1"))
    else:
        res["verdict"] = "UNKNOWN"

    if res["stale_running"]:
        res["findings"].append(("HIGH", "running worker still uses a replaced (deleted) binary or module",
                                "restart the service so every worker loads the new runtime"))
    return res


def config_findings(conf, context, verdict):
    """Produce findings for one effective configuration mapping."""
    out = []
    if not conf:
        return out
    unpatched = verdict != "PATCHED"
    up = ini_bool(conf.get("session.upload_progress.enabled"))
    if up is not False:
        out.append(("HIGH" if unpatched else "LOW",
                    "%s: session.upload_progress.enabled is On" % context,
                    "set session.upload_progress.enabled=0 administratively (php.ini / FPM php_admin_flag / Apache php_admin_flag) and restart workers"))
    feb = conf.get("fatal_error_backtraces")
    if feb is not None and ini_bool(feb) is not False:
        out.append(("HIGH" if unpatched else "LOW",
                    "%s: fatal_error_backtraces is On (PHP 8.5)" % context,
                    "set fatal_error_backtraces=0 and restart workers"))
    ml = conf.get("memory_limit")
    if unpatched and ml is not None and ml.strip() != "-1":
        out.append(("MEDIUM", "%s: finite memory_limit=%s on an unpatched build" % (context, ml),
                    "php.net interim advice: memory_limit=-1 via php_admin_value plus request-size limits at the proxy and a cgroup/container memory boundary"))
    pms = ini_bytes(conf.get("post_max_size"))
    if unpatched and pms is not None and pms > 32 * 1024 ** 2:
        out.append(("MEDIUM", "%s: post_max_size=%s is above the advised 32M ceiling" % (context, conf.get("post_max_size")),
                    "lower post_max_size (8M without uploads, 32M with uploads) and keep upload_max_filesize below it"))
    nest = conf.get("max_input_nesting_level")
    if unpatched and nest and nest.strip().isdigit() and int(nest) >= 64:
        out.append(("LOW", "%s: max_input_nesting_level=%s (default)" % (context, nest),
                    "consider lowering it; nested field names multiply parsing work"))
    if conf.get("memory_hard_limit_percent") is not None:
        out.append(("OK", "%s: memory_hard_limit_percent present (patched runtime)" % context, ""))
    return out


def cmd_scan(args):
    t0 = time.time()
    report = {"tool": TOOL, "version": __version__, "host": socket.gethostname(), "time": datetime.datetime.now().isoformat(),
              "platform": platform.platform(), "root": is_root(), "installs": [], "packages": [], "apache": [],
              "docker": [], "findings": [], "verdict": None}
    procs = running_processes()
    pkgs = check_packages()
    report["packages"] = pkgs
    bins = find_php_binaries()
    for b in bins:
        report["installs"].append(assess_install(b, procs, pkgs, no_config=args.no_config))

    # Apache directives
    report["apache"] = scan_apache_configs()
    if args.docker:
        report["docker"] = scan_docker()

    # aggregate findings
    findings = []
    for inst in report["installs"]:
        ctx = "%s (%s)" % (inst["path"], inst["kind"])
        for f in inst["findings"]:
            findings.append((f[0], ctx + ": " + f[1], f[2]))
        if inst["verdict"] == "VULNERABLE":
            findings.append(("CRITICAL", "%s is unpatched (PHP %s, %s)" % (ctx, inst["version"], inst["version_reason"]),
                             "update to the fixed release for the branch and restart every worker"))
        elif inst["verdict"] == "UNKNOWN":
            findings.append(("MEDIUM", "%s: could not determine patch status" % ctx, "check manually"))
        findings.extend(config_findings(inst.get("config"), ctx, inst["verdict"]))
        for sc in inst.get("sapi_configs", []):
            findings.extend(config_findings(sc["config"], "%s [%s sapi: %s]" % (inst["path"], sc["sapi"], sc["ini_file"]), inst["verdict"]))
        fp = inst.get("fpm_pools")
        if fp and fp["pools"]:
            for pool, vals in fp["pools"].items():
                if pool.lower() in ("general", "global"):
                    continue
                v = vals.get("session.upload_progress.enabled")
                if v and ini_bool(v[1]) is False:
                    findings.append(("OK", "FPM pool [%s] enforces session.upload_progress.enabled=off via %s" % (pool, v[0]), ""))
                mlv = vals.get("memory_limit")
                if mlv and inst["verdict"] != "PATCHED" and mlv[1].strip() != "-1":
                    findings.append(("LOW", "FPM pool [%s] sets memory_limit=%s (%s)" % (pool, mlv[1], mlv[0]),
                                     "a pool-level finite limit overrides any php.ini memory_limit=-1 mitigation"))
                mr = vals.get("pm.max_requests")
                if mr and inst["verdict"] != "PATCHED" and mr[1].strip() == "0":
                    findings.append(("LOW", "FPM pool [%s] pm.max_requests=0 (workers never recycle)" % pool,
                                     "a low pm.max_requests shortens how long stale state can persist in a worker"))
        elif fp and not fp["ok"]:
            findings.append(("INFO", "%s: could not dump FPM pools (%s)" % (inst["path"], fp["note"]), "run as root"))
    for pk in pkgs:
        if pk["status"] == "vulnerable":
            findings.append(("CRITICAL", "package %s %s is unpatched (%s)" % (pk["package"], pk["version"], pk["detail"]),
                             "apply the vendor update"))
        elif pk["status"] == "unknown":
            findings.append(("MEDIUM", "package %s %s: patch status not confirmed (%s)" % (pk["package"], pk["version"], pk["detail"]),
                             "compare with your vendor advisory"))
    for a in report["apache"]:
        if a["kind"] == "rlimitmem":
            findings.append(("MEDIUM", "Apache RLimitMEM in %s:%d" % (a["file"], a["line"]),
                             "php.net advises against RLIMIT_AS/RLIMIT_DATA style limits: they can cause the allocation failure the bug depends on"))
        elif a["key"] == "session.upload_progress.enabled" and ini_bool(a["value"]) is False:
            findings.append(("OK", "Apache %s disables session.upload_progress in %s:%d" % (a["kind"], a["file"], a["line"]), ""))
        elif a["key"] == "session.upload_progress.enabled":
            findings.append(("HIGH", "Apache %s re-enables session.upload_progress in %s:%d" % (a["kind"], a["file"], a["line"]), "remove it"))
        elif a["key"] == "memory_limit" and a["kind"] in ("php_value", "php_admin_value"):
            if a["value"].strip() == "-1":
                findings.append(("OK", "Apache %s memory_limit -1 in %s:%d" % (a["kind"], a["file"], a["line"]), ""))
            else:
                findings.append(("INFO", "Apache %s memory_limit %s in %s:%d" % (a["kind"], a["value"], a["file"], a["line"]),
                                 "per-directory limits override a global memory_limit=-1 mitigation"))
    for d in report["docker"]:
        if d["verdict"] == "VULNERABLE":
            findings.append(("CRITICAL", "container %s (%s) runs unpatched PHP %s" % (d["name"], d["image"], d["version"]),
                             "rebuild with a fixed base image and recreate the container"))
        elif d["verdict"] == "UNKNOWN":
            findings.append(("MEDIUM", "container %s (%s): PHP patch status unknown" % (d["name"], d["image"]), ""))
    if not report["installs"] and not report["docker"]:
        findings.append(("INFO", "no PHP binaries or Apache PHP modules found on this host", ""))

    findings.sort(key=lambda f: SEV_RANK.get(f[0], 9))
    report["findings"] = [{"severity": s, "title": t, "fix": x} for s, t, x in findings]
    if any(i["verdict"] == "VULNERABLE" for i in report["installs"]) or any(d["verdict"] == "VULNERABLE" for d in report["docker"]) \
            or any(p["status"] == "vulnerable" for p in pkgs):
        report["verdict"] = "VULNERABLE"
    elif any(i["verdict"] == "UNKNOWN" for i in report["installs"]) or any(p["status"] == "unknown" for p in pkgs):
        report["verdict"] = "PATCHED" if (report["installs"] and all(i["verdict"] == "PATCHED" for i in report["installs"])) else "UNKNOWN"
    elif report["installs"] or report["docker"]:
        report["verdict"] = "PATCHED"
    else:
        report["verdict"] = "NO_PHP"
    report["elapsed"] = round(time.time() - t0, 2)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_scan_report(report)
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
    return {"VULNERABLE": 1, "UNKNOWN": 2, "PATCHED": 0, "NO_PHP": 0}[report["verdict"]]


def print_scan_report(r):
    banner("%s %s - local audit of %s" % (TOOL, __version__, r["host"]))
    print("  %s | root=%s | %s" % (r["platform"], r["root"], r["time"]))
    if not r["root"]:
        print(c("  not running as root: process maps, FPM pool dumps and some binaries may be unreadable", "yellow"))
    print()
    banner("PHP runtimes (%d)" % len(r["installs"]))
    for i in r["installs"]:
        col = {"PATCHED": "green", "VULNERABLE": "red"}.get(i["verdict"], "yellow")
        fp = ",".join(i["fingerprint"]) if i["fingerprint"] else "none"
        running = ("running pid " + ",".join(map(str, i["running"][:6])) + (" ..." if len(i["running"]) > 6 else "")) if i["running"] else "not running"
        if i["stale_running"]:
            running += c(" STALE BINARY", "red")
        print("  %s %s" % (c("%-10s" % i["verdict"], col), i["path"]))
        if i["verdict"] == "PATCHED" and i["version_status"] in ("vulnerable", "eol") and i["fingerprint"]:
            status_line = "status=backported (version string predates the fix; patch markers confirm the build)"
        else:
            status_line = "status=%s: %s" % (i["version_status"], i["version_reason"])
        print("      kind=%s  version=%s (%s)  %s" % (i["kind"], i["version"], i["version_source"], status_line))
        print("      patch-markers=%s  %s  found-via=%s" % (fp, running, ",".join(i["sources"])))
        conf = i.get("config")
        if conf:
            keys = [("session.upload_progress.enabled", "upload_progress"), ("fatal_error_backtraces", "fatal_error_backtraces"),
                    ("memory_limit", "memory_limit"), ("memory_hard_limit_percent", "hard_limit%"), ("post_max_size", "post_max_size"),
                    ("upload_max_filesize", "upload_max_filesize"), ("max_input_nesting_level", "nesting")]
            print("      ini: " + "  ".join("%s=%s" % (label, conf[k]) for k, label in keys if k in conf and conf[k] != "no value"))
            cf = i.get("config_files") or {}
            if cf.get("ini_file") or cf.get("scan_dir"):
                print("      ini-files: %s  scan-dir: %s" % (cf.get("ini_file"), cf.get("scan_dir")))
        elif i.get("config_note"):
            print("      ini: %s" % i["config_note"])
        for sc in i.get("sapi_configs", []):
            print("      [%s sapi] upload_progress=%s memory_limit=%s post_max_size=%s (%s)" % (
                sc["sapi"], sc["config"].get("session.upload_progress.enabled", "?"), sc["config"].get("memory_limit", "?"),
                sc["config"].get("post_max_size", "?"), sc["ini_file"]))
        fp_ = i.get("fpm_pools")
        if fp_ and fp_["pools"]:
            for pool, vals in fp_["pools"].items():
                if pool.lower() in ("general", "global"):
                    continue
                ov = ["%s[%s]=%s" % (v[0], k, v[1]) for k, v in vals.items() if v[0] != "setting"]
                pm = vals.get("pm.max_requests", ("", "?"))[1]
                print("      fpm pool [%s]: pm.max_requests=%s %s" % (pool, pm, " ".join(ov) if ov else "(no php_* overrides)"))
    if r["packages"]:
        print()
        banner("Packages (%d)" % len(r["packages"]))
        for p in r["packages"]:
            col = {"patched": "green", "vulnerable": "red"}.get(p["status"], "yellow")
            print("  %s %-6s %-28s %-40s %s" % (c("%-10s" % p["status"].upper(), col), p["manager"], p["package"], p["version"], p["detail"]))
    if r["docker"]:
        print()
        banner("Docker containers (%d)" % len(r["docker"]))
        for d in r["docker"]:
            col = {"PATCHED": "green", "VULNERABLE": "red"}.get(d["verdict"], "yellow")
            print("  %s %-24s %-40s php=%s markers=%s %s" % (c("%-10s" % d["verdict"], col), d["name"][:24], d["image"][:40], d["version"], d["fingerprint"], d["note"]))
    print()
    banner("Findings (%d)" % len(r["findings"]))
    if not r["findings"]:
        print("  none")
    for f in r["findings"]:
        print("  %s %s" % (sev(f["severity"]), f["title"]))
        if f["fix"]:
            print("             -> %s" % f["fix"])
    print()
    col = {"PATCHED": "green", "VULNERABLE": "red", "NO_PHP": "dim"}.get(r["verdict"], "yellow")
    print(c("HOST VERDICT: %s" % r["verdict"], col) + "   (%.1fs)" % r["elapsed"])
    if r["verdict"] == "VULNERABLE":
        print("  Update PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or your vendor backport) and restart every worker.")
        print("  Until then: `%s protect --apply` applies the php.net interim mitigations. See %s" % (sys.argv[0], ADVISORY_URL))


def scan_docker():
    if not which("docker"):
        return []
    rc, out, err = run(["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"], timeout=30)
    if rc != 0:
        return [{"name": "-", "image": "-", "version": None, "fingerprint": None, "verdict": "UNKNOWN", "note": "docker ps failed: %s" % err.strip()[:120]}]
    results = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        cid, name, image = parts
        rc, bins, _ = run(["docker", "exec", cid, "sh", "-c",
                           "for b in php php-fpm php-cgi frankenphp; do command -v $b 2>/dev/null; done; ls /usr/local/sbin/php-fpm /usr/sbin/php-fpm* 2>/dev/null"], timeout=20)
        bins = sorted(set(b.strip() for b in bins.splitlines() if b.strip()))
        if not bins:
            continue
        version, markers, note = None, 0, ""
        for b in bins:
            rc, v, e = run(["docker", "exec", cid, b, "-n", "-v"], timeout=20)
            m = re.search(r"PHP (\d+\.\d+\.\d+\S*)", v + e)
            if m:
                version = m.group(1)
            rc, g, _ = run(["docker", "exec", cid, "sh", "-c",
                            "grep -c -a -e memory_hard_limit_percent -e zend_mm_safe_error_ex %s 2>/dev/null || (tr -c '[:print:]' '\\n' < %s | grep -c -e memory_hard_limit_percent -e zend_mm_safe_error_ex)" % (b, b)], timeout=30)
            try:
                markers = max(markers, int(g.strip().splitlines()[-1]))
            except (ValueError, IndexError):
                pass
            if version:
                break
        st, why = classify_version(version or "")
        if markers > 0 or st == "patched":
            verdict = "PATCHED"
        elif st in ("vulnerable", "eol"):
            verdict = "VULNERABLE"
            note = why
        else:
            verdict = "UNKNOWN"
            note = why
        results.append({"id": cid, "name": name, "image": image, "version": version, "fingerprint": markers > 0,
                        "verdict": verdict, "note": note, "binaries": bins})
    return results


# --------------------------------------------------------------------------
# protect
# --------------------------------------------------------------------------

DROPIN_NAME = "zz-php2shell-guard.ini"
MARK_BEGIN = "; BEGIN php2shell-guard (CVE-2026-109618 / CVE-2026-109619) - do not edit, remove with `protect --rollback`"
MARK_END = "; END php2shell-guard"
APACHE_CONF_NAME = "php2shell-guard.conf"


def dropin_text(args):
    lines = [
        "; %s %s mitigation drop-in for %s" % (TOOL, __version__, " / ".join(CVES)),
        "; Generated %s. Interim measure only: updating PHP is the only complete fix." % datetime.datetime.now().isoformat(timespec="seconds"),
        "; Reference: %s" % ADVISORY_URL,
        "",
        "; CVE-2026-109619: removes the confirmed session upload-progress path",
        "session.upload_progress.enabled = 0",
        "; CVE-2026-109619 (PHP 8.5 only, ignored by older versions)",
        "fatal_error_backtraces = 0",
    ]
    if args.post_max:
        lines += ["", "; CVE-2026-109618: bound decoded request size",
                  "post_max_size = %s" % args.post_max,
                  "upload_max_filesize = %s" % args.upload_max,
                  "max_input_nesting_level = %d" % args.nesting]
    if args.memory_unlimited:
        lines += ["", "; CVE-2026-109618: removes the controllable memory_limit failure. Pair with",
                  "; request-size limits at the proxy and a cgroup/container memory boundary.",
                  "memory_limit = -1"]
    return "\n".join(lines) + "\n"


def fpm_block_lines(args, is_php85):
    lines = [MARK_BEGIN,
             "php_admin_flag[session.upload_progress.enabled] = off"]
    if is_php85:
        lines.append("php_admin_flag[fatal_error_backtraces] = off")
    if args.post_max:
        lines.append("php_admin_value[post_max_size] = %s" % args.post_max)
        lines.append("php_admin_value[upload_max_filesize] = %s" % args.upload_max)
    if args.memory_unlimited:
        lines.append("php_admin_value[memory_limit] = -1")
    lines.append(MARK_END)
    return lines


def apache_conf_text(args, has_85):
    body = ["# %s %s - interim mitigation for %s" % (TOOL, __version__, " / ".join(CVES)),
            "# php_admin_* cannot be overridden by .htaccess or ini_set(). Remove with `protect --rollback`.", ""]
    for mod in ("php_module", "php7_module", "php5_module"):
        body.append("<IfModule %s>" % mod)
        body.append("    php_admin_flag session.upload_progress.enabled off")
        if has_85 and mod == "php_module":
            body.append("    php_admin_flag fatal_error_backtraces off")
        if args.post_max:
            body.append("    php_admin_value post_max_size %s" % args.post_max)
            body.append("    php_admin_value upload_max_filesize %s" % args.upload_max)
        if args.memory_unlimited:
            body.append("    php_admin_value memory_limit -1")
        body.append("</IfModule>")
    if args.post_max:
        body += ["", "# Reject oversized bodies before PHP sees them (bytes)",
                 "LimitRequestBody %d" % (ini_bytes(args.post_max) or 33554432)]
    return "\n".join(body) + "\n"


def discover_confd_dirs():
    dirs = set(d for d in expand_globs(CONFD_GLOBS) if os.path.isdir(d))
    # ask each binary where it scans
    for b in find_php_binaries():
        kind = binary_kind(b["path"])
        if kind == "module" or b.get("unreadable"):
            continue
        conf, info, note = effective_ini_from_binary(b["path"], kind)
        if info and info.get("scan_dir") and os.path.isdir(info["scan_dir"]):
            dirs.add(info["scan_dir"])
        elif info and info.get("ini_file"):
            # no scan dir: fall back to appending to php.ini is too invasive; report it
            dirs.add("!" + info["ini_file"])
    return sorted(dirs)


def discover_fpm_pools():
    return sorted(set(p for p in expand_globs(FPM_POOL_GLOBS) if os.path.isfile(p)))


def discover_apache_dir():
    for d in ("/etc/apache2/conf-available", "/etc/httpd/conf.d", "/usr/local/apache/conf/includes",
              "/usr/local/etc/apache24/Includes", "/etc/apache24/Includes", "/opt/homebrew/etc/httpd/extra"):
        if os.path.isdir(d):
            return d
    return None


def php_services():
    svcs = []
    svc_re = r"^(php[\w.-]*fpm[\w.-]*|apache2|httpd|lsws|lshttpd|litespeed|frankenphp|ea-php\d\d-php-fpm|plesk-php\d\d-fpm)"
    systemd_ok = False
    if which("systemctl"):
        rc, out, _ = run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"], timeout=20)
        systemd_ok = rc == 0
        for line in out.splitlines():
            name = line.split()[0] if line.split() else ""
            if re.match(svc_re + r"\.service$", name):
                active = " active " in (" " + line + " ") and " running " in (" " + line + " ")
                svcs.append((name, active))
    if not systemd_ok and which("service") and os.path.isdir("/etc/init.d"):
        running = " ".join(p["comm"] for p in running_processes())
        for f in sorted(os.listdir("/etc/init.d")):
            if re.match(svc_re + r"$", f):
                base = re.sub(r"[\d.]", "", f.replace("-", ""))
                svcs.append((f, bool(re.search(r"php-?fpm", running)) if "fpm" in f else base in running))
    elif not svcs and which("brew"):
        rc, out, _ = run(["brew", "services", "list"], timeout=30)
        for line in out.splitlines():
            if line.startswith(("php", "httpd")):
                parts = line.split()
                svcs.append((parts[0], len(parts) > 1 and parts[1] == "started"))
    return svcs


def _worker_pids():
    global _PROC_CACHE
    _PROC_CACHE = None
    return {p["pid"]: p["comm"] for p in running_processes()
            if p["comm"] in ("apache2", "httpd", "litespeed", "lshttpd", "frankenphp") or re.match(r"php-?fpm|lsphp", p["comm"])}


def _fallback_restart(name):
    """When the service manager cannot restart (containers, hand-started daemons),
    fall back to the daemon's own reload mechanism."""
    base = name.replace(".service", "")
    if base in ("apache2", "httpd"):
        for tool in ("apachectl", "apache2ctl", "httpd"):
            if which(tool):
                return [tool, "-k", "graceful"]
    if "fpm" in base:
        masters = [p for p in running_processes() if re.match(r"php-?fpm", p["comm"]) and p["ppid"] in (None, 0, 1)
                   or (re.match(r"php-?fpm", p["comm"]) and "master" in p["cmdline"])]
        if masters:
            return ["kill", "-USR2"] + [str(p["pid"]) for p in masters]
    if base in ("lsws", "lshttpd", "litespeed") and os.path.exists("/usr/local/lsws/bin/lswsctrl"):
        return ["/usr/local/lsws/bin/lswsctrl", "restart"]
    return None


def restart_services(dry):
    before = _worker_pids() if not dry else {}
    restarted = []
    for name, active in php_services():
        if not active:
            continue
        if name.endswith(".service"):
            cmd = ["systemctl", "restart", name]
        elif which("brew") and not os.path.isdir("/etc/init.d"):
            cmd = ["brew", "services", "restart", name]
        else:
            cmd = ["service", name, "restart"]
        if dry:
            print("  would run: %s" % " ".join(cmd))
            continue
        rc, out, err = run(cmd, timeout=120)
        if rc != 0:
            fb = _fallback_restart(name)
            print("  %s %s" % (c("FAIL", "red"), " ".join(cmd)))
            print("    " + (err or out).strip().splitlines()[-1][:200] if (err or out).strip() else "")
            if fb:
                rc, out, err = run(fb, timeout=120)
                print("  %s fallback: %s" % (c("ok  ", "green") if rc == 0 else c("FAIL", "red"), " ".join(fb)))
        else:
            print("  %s %s" % (c("ok  ", "green") if rc == 0 else c("FAIL", "red"), " ".join(cmd)))
        if rc == 0:
            restarted.append(name)
    if dry or not restarted:
        return
    time.sleep(1.5)
    after = _worker_pids()
    unchanged = sorted(set(before) & set(after))
    if unchanged and len(unchanged) == len(before):
        print(c("  WARNING: no PHP/web worker process id changed; the restart may not have taken effect "
                "(pids %s). Restart by hand and re-run scan." % ",".join(map(str, unchanged[:8])), "yellow"))
    else:
        print("  worker processes replaced (%d before, %d after, %d survived)" % (len(before), len(after), len(unchanged)))
        if unchanged:
            print(c("  survivors still run the old configuration: %s" % ", ".join("%s[%d]" % (before[p], p) for p in unchanged[:10]), "yellow"))
            print("  (masters started outside the service manager are not restarted by it; stop them by hand)")


def cmd_protect(args):
    apply_ = args.apply
    if args.rollback:
        return protect_rollback(args)
    if not args.post_max and args.upload_max:
        print("--upload-max requires --post-max")
        return 3
    if args.post_max and not args.upload_max:
        pm = ini_bytes(args.post_max) or 0
        args.upload_max = "%dM" % max(1, (pm // (1024 ** 2)) - 2) if pm >= 3 * 1024 ** 2 else args.post_max
    if apply_ and not is_root() and os.name != "nt":
        print(c("protect --apply needs root to write configuration and restart services", "red"))
        return 3
    banner("%s protect (%s)" % (TOOL, "APPLY" if apply_ else "DRY RUN - add --apply to write"))
    print("  Interim mitigations from the php.net advisory. They reduce exposure; only updating PHP is complete.\n")

    confd = discover_confd_dirs()
    pools = discover_fpm_pools()
    adir = discover_apache_dir()
    has_85 = any((parse_version(php_version_of(b["path"], binary_kind(b["path"]))[0] or "") or (0, 0))[:2] == (8, 5)
                 for b in find_php_binaries() if not b.get("unreadable"))
    changes = []

    text = dropin_text(args)
    print("php.ini drop-in (%s):" % DROPIN_NAME)
    print("".join("    " + l + "\n" for l in text.splitlines()))
    for d in confd:
        if d.startswith("!"):
            print("  %s %s has no scan dir; add the directives to it by hand" % (sev("MEDIUM"), d[1:]))
            continue
        target = os.path.join(d, DROPIN_NAME)
        exists = os.path.exists(target)
        print("  %s %s" % ("update " if exists else "write  ", target))
        if apply_:
            with open(target, "w") as fh:
                fh.write(text)
            os.chmod(target, 0o644)
            changes.append(target)
    if not confd:
        print("  no conf.d directories found")

    print("\nFPM pools (php_admin_* lines inserted under each [pool] header):")
    for p in pools:
        try:
            with open(p, "r", errors="replace") as fh:
                content = fh.read()
        except OSError as e:
            print("  skip %s (%s)" % (p, e))
            continue
        is85 = has_85 and ("8.5" in p)
        block = fpm_block_lines(args, is85)
        new = insert_fpm_block(content, block)
        if new == content:
            print("  unchanged %s" % p)
            continue
        print("  %s %s" % ("patch  " if not args.no_fpm_pools else "skip   ", p))
        if apply_ and not args.no_fpm_pools:
            bak = p + ".php2shell-guard.bak"
            if not os.path.exists(bak):
                shutil.copy2(p, bak)
            with open(p, "w") as fh:
                fh.write(new)
            changes.append(p)
    if not pools:
        print("  no pool files found")

    print("\nApache (mod_php) config:")
    if adir and not args.no_apache:
        target = os.path.join(adir, APACHE_CONF_NAME)
        print("  write   %s" % target)
        print("".join("    " + l + "\n" for l in apache_conf_text(args, has_85).splitlines()))
        if apply_:
            with open(target, "w") as fh:
                fh.write(apache_conf_text(args, has_85))
            changes.append(target)
            if adir == "/etc/apache2/conf-available" and which("a2enconf"):
                run(["a2enconf", APACHE_CONF_NAME[:-5]], timeout=30)
            for tester in (("apachectl", "-t"), ("apache2ctl", "-t"), ("httpd", "-t")):
                if which(tester[0]):
                    rc, out, err = run(list(tester), timeout=30)
                    ok = rc == 0
                    print("  %s %s -t: %s" % (c("ok  ", "green") if ok else c("FAIL", "red"), tester[0], (err or out).strip().splitlines()[-1] if (err or out).strip() else ""))
                    if not ok:
                        print(c("  Apache config test failed: removing %s" % target, "red"))
                        os.remove(target)
                        if which("a2disconf"):
                            run(["a2disconf", APACHE_CONF_NAME[:-5]], timeout=30)
                    break
    else:
        print("  no Apache config dir found (or --no-apache)")

    print("\nServices:")
    svcs = php_services()
    if not svcs:
        print("  none detected; restart PHP-FPM / Apache / LiteSpeed by hand")
    if args.restart:
        restart_services(dry=not apply_)
    else:
        for name, active in svcs:
            print("  %s %s" % ("running" if active else "stopped", name))
        print("  (add --restart to restart running services; every worker must reload the config)")

    print()
    if apply_:
        print(c("Applied %d change(s)." % len(changes), "green"))
        print("Verify with: %s scan" % sys.argv[0])
        if not args.restart:
            print(c("Workers still run the old configuration until restarted.", "yellow"))
    else:
        print("Dry run complete. Re-run with --apply (as root) to write these changes.")
    return 0


def insert_fpm_block(content, block):
    lines = content.splitlines()
    out, changed = [], False
    # drop any previous block first
    cleaned, skipping = [], False
    for l in lines:
        if l.strip() == MARK_BEGIN:
            skipping = True
            continue
        if skipping and l.strip() == MARK_END:
            skipping = False
            continue
        if not skipping:
            cleaned.append(l)
    for l in cleaned:
        out.append(l)
        m = re.match(r"^\s*\[([^\]]+)\]\s*$", l)
        if m and m.group(1).lower() not in ("global", "general"):
            out.extend(block)
            changed = True
    if not changed:
        return content
    return "\n".join(out) + "\n"


def protect_rollback(args):
    apply_ = args.apply
    banner("%s protect --rollback (%s)" % (TOOL, "APPLY" if apply_ else "DRY RUN"))
    if apply_ and not is_root() and os.name != "nt":
        print(c("needs root", "red"))
        return 3
    n = 0
    for d in discover_confd_dirs():
        if d.startswith("!"):
            continue
        t = os.path.join(d, DROPIN_NAME)
        if os.path.exists(t):
            print("  remove %s" % t)
            n += 1
            if apply_:
                os.remove(t)
    for p in discover_fpm_pools():
        try:
            with open(p, "r", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        if MARK_BEGIN not in content:
            continue
        new = insert_fpm_block(content, [])
        # insert_fpm_block with empty block re-adds nothing but strips the old block
        print("  strip  %s" % p)
        n += 1
        if apply_:
            with open(p, "w") as fh:
                fh.write(new)
    adir = discover_apache_dir()
    if adir:
        t = os.path.join(adir, APACHE_CONF_NAME)
        if os.path.exists(t):
            print("  remove %s" % t)
            n += 1
            if apply_:
                if which("a2disconf"):
                    run(["a2disconf", APACHE_CONF_NAME[:-5]], timeout=30)
                os.remove(t)
    print("\n%d item(s) %s." % (n, "removed" if apply_ else "would be removed"))
    if args.restart:
        print("Services:")
        restart_services(dry=not apply_)
    elif apply_ and n:
        print(c("Restart PHP-FPM / Apache so workers drop the mitigation config.", "yellow"))
    return 0


# --------------------------------------------------------------------------
# hunt
# --------------------------------------------------------------------------

LOG_PATTERNS = [
    ("HIGH", "oom_pre_script", re.compile(r"Allowed memory size of \d+ bytes exhausted.*(?:in Unknown on line 0|Unknown:0)")),
    ("MEDIUM", "oom_any", re.compile(r"Allowed memory size of \d+ bytes exhausted")),
    ("HIGH", "worker_segfault", re.compile(r"exit signal Segmentation fault|SIGSEGV|exited on signal 11|signal 11 \(SIGSEGV\)|segfault at")),
    ("MEDIUM", "session_destruction", re.compile(r"Session object destruction failed|Failed to write session data", re.I)),
    ("MEDIUM", "upstream_reset", re.compile(r"upstream prematurely closed connection|recv\(\) failed \(104: Connection reset by peer\) while reading response header from upstream")),
    ("LOW", "max_exec_time", re.compile(r"Maximum execution time of \d+ seconds exceeded")),
    ("MEDIUM", "fpm_child_exit", re.compile(r"child \d+ exited on signal (?:11|6|7)")),
]
WEBSHELL_PATTERNS = [
    re.compile(rb"eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|hex2bin)\s*\(", re.I),
    re.compile(rb"(?:system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b", re.I),
    re.compile(rb"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
    re.compile(rb"assert\s*\(\s*\$_(?:GET|POST|REQUEST)", re.I),
    re.compile(rb"preg_replace\s*\(\s*['\"][^'\"]*/e['\"]", re.I),
    re.compile(rb"(?:create_function|array_map|call_user_func(?:_array)?)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|['\"](?:system|exec|shell_exec|passthru)['\"])", re.I),
    re.compile(rb"\bmove_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\[.tmp_name.\]\s*,\s*\$_(?:GET|POST|REQUEST)", re.I),
    re.compile(rb"(?:c99|r57|wso|b374k|FilesMan|WebShell|phpspy|uname -a;)", re.I),
]
SESSION_INJECT_RE = re.compile(rb"<\?php|<\?=|<script language=\"php\"|\|O:\d+:\"|upload_progress_[^|]*<\?")


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def hunt_logs(paths, since, max_lines=2000000):
    hits, files = {}, []
    for p in paths:
        try:
            if os.path.getmtime(p) < since.timestamp() or os.path.getsize(p) == 0:
                continue
        except OSError:
            continue
        files.append(p)
        try:
            with open_log(p) as fh:
                for n, raw in enumerate(fh):
                    if n > max_lines:
                        break
                    line = raw.decode("utf-8", "replace")
                    for sev_, name, rx in LOG_PATTERNS:
                        if rx.search(line):
                            h = hits.setdefault(name, {"severity": sev_, "count": 0, "files": set(), "samples": []})
                            h["count"] += 1
                            h["files"].add(p)
                            if len(h["samples"]) < 5:
                                h["samples"].append(line.strip()[:300])
                            break
        except OSError:
            continue
    for h in hits.values():
        h["files"] = sorted(h["files"])
    return hits, files


def session_dirs_from_scan():
    dirs = set()
    for b in find_php_binaries():
        kind = binary_kind(b["path"])
        if kind == "module" or b.get("unreadable"):
            continue
        conf, info, _ = effective_ini_from_binary(b["path"], kind)
        if conf and conf.get("session.save_path"):
            sp = conf["session.save_path"][0]
            m = re.search(r"(?:\d+;)?(?:\d+;)?(/\S+)$", sp)
            if m and os.path.isdir(m.group(1)):
                dirs.add(m.group(1))
    for d in expand_globs(SESSION_DIR_CANDIDATES):
        if os.path.isdir(d):
            dirs.add(d)
    return sorted(dirs)


def hunt_sessions(dirs, max_files=50000):
    hits, scanned = [], 0
    for d in dirs:
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            if not n.startswith("sess_"):
                continue
            p = os.path.join(d, n)
            try:
                if not os.path.isfile(p) or os.path.getsize(p) > 5 * 1024 * 1024:
                    continue
                with open(p, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            scanned += 1
            m = SESSION_INJECT_RE.search(data)
            if m:
                hits.append({"file": p, "size": len(data), "mtime": datetime.datetime.fromtimestamp(os.path.getmtime(p)).isoformat(),
                             "match": m.group(0).decode("latin-1")[:40]})
            if scanned >= max_files:
                return hits, scanned
    return hits, scanned


def detect_webroots():
    roots = set()
    for conf in iter_conf_files(APACHE_CONF_DIRS + ["/etc/nginx", "/usr/local/etc/nginx", "/usr/local/lsws/conf", "/etc/caddy"], exts=(".conf", "Caddyfile")):
        try:
            with open(conf, "r", errors="replace") as fh:
                for line in fh:
                    m = re.match(r"\s*(?:DocumentRoot|root|docRoot)\s+\"?([^\s\";]+)", line)
                    if m and os.path.isdir(m.group(1)) and m.group(1) not in ("/", "/usr", "/etc"):
                        roots.add(m.group(1).rstrip("/"))
        except OSError:
            continue
    for d in ("/var/www", "/srv/www", "/usr/share/nginx/html", "/home/*/public_html", "/var/www/vhosts/*/httpdocs", "/usr/local/lsws/Example/html", "/usr/local/www"):
        for p in glob.glob(d):
            if os.path.isdir(p):
                roots.add(p.rstrip("/"))
    # collapse nested roots
    out = []
    for r in sorted(roots):
        if not any(r.startswith(o + "/") for o in out):
            out.append(r)
    return out


def hunt_webroots(roots, since, max_files=300000):
    recent, suspicious, n = [], [], 0
    exts = (".php", ".phtml", ".php5", ".php7", ".php8", ".phar", ".inc", ".phps")
    for root in roots:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in ("node_modules", ".git", "vendor") or d == "vendor" and False]
            for f in fns:
                n += 1
                if n > max_files:
                    return recent, suspicious, n
                p = os.path.join(dp, f)
                lower = f.lower()
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                is_php = lower.endswith(exts) or ".php." in lower
                if is_php and st.st_mtime >= since.timestamp():
                    recent.append({"file": p, "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(), "size": st.st_size})
                if (is_php or lower.endswith((".ico", ".txt", ".jpg", ".png"))) and st.st_size < 2 * 1024 * 1024:
                    try:
                        with open(p, "rb") as fh:
                            data = fh.read()
                    except OSError:
                        continue
                    if not is_php and b"<?php" not in data:
                        continue
                    for rx in WEBSHELL_PATTERNS:
                        m = rx.search(data)
                        if m:
                            suspicious.append({"file": p, "pattern": m.group(0).decode("latin-1")[:60],
                                               "sha256": hashlib.sha256(data).hexdigest(),
                                               "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat()})
                            break
    return recent, suspicious, n


def hunt_processes():
    procs = running_processes()
    by_pid = {p["pid"]: p for p in procs}
    # need all processes for children; on Linux re-read /proc minimal
    sus = []
    if os.path.isdir("/proc") and platform.system() == "Linux":
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/stat" % pid) as fh:
                    st = fh.read()
                comm = st[st.index("(") + 1:st.rindex(")")]
                ppid = int(st.rsplit(")", 1)[1].split()[1])
                with open("/proc/%s/cmdline" % pid, "rb") as fh:
                    cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            except (OSError, ValueError):
                continue
            parent = by_pid.get(ppid)
            if parent and os.path.basename(comm) in SHELL_NAMES and parent["comm"] in WEB_WORKER_NAMES + ("php",):
                sus.append({"pid": int(pid), "comm": comm, "cmdline": cmd[:200], "parent": "%s[%d]" % (parent["comm"], ppid)})
    else:
        rc, out, _ = run(["ps", "-axo", "pid=,ppid=,comm="], timeout=15)
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            pid, ppid, comm = int(parts[0]), int(parts[1]), os.path.basename(parts[2])
            parent = by_pid.get(ppid)
            if parent and comm in SHELL_NAMES and parent["comm"] in WEB_WORKER_NAMES:
                sus.append({"pid": pid, "comm": comm, "cmdline": "", "parent": "%s[%d]" % (parent["comm"], ppid)})
    return sus


def hunt_persistence(since):
    out = []
    for pat in ("/etc/cron*", "/var/spool/cron", "/var/spool/cron/crontabs", "/etc/systemd/system", "/etc/rc.local",
                "/etc/ld.so.preload", "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys", "/var/www/.ssh/authorized_keys",
                "/etc/passwd", "/etc/sudoers.d"):
        for p in glob.glob(pat):
            try:
                if os.path.isdir(p):
                    for dp, _d, fns in os.walk(p):
                        for f in fns:
                            fp = os.path.join(dp, f)
                            try:
                                if os.path.getmtime(fp) >= since.timestamp():
                                    out.append({"file": fp, "mtime": datetime.datetime.fromtimestamp(os.path.getmtime(fp)).isoformat()})
                            except OSError:
                                pass
                elif os.path.getmtime(p) >= since.timestamp():
                    out.append({"file": p, "mtime": datetime.datetime.fromtimestamp(os.path.getmtime(p)).isoformat()})
            except OSError:
                continue
    return out


def cmd_hunt(args):
    since = datetime.datetime.now() - datetime.timedelta(days=args.days)
    report = {"tool": TOOL, "version": __version__, "host": socket.gethostname(), "since": since.isoformat(), "logs": {},
              "log_files": [], "session_dirs": [], "session_hits": [], "sessions_scanned": 0, "webroots": [],
              "recent_php_files": [], "suspicious_files": [], "shell_children": [], "persistence": [], "findings": []}
    log_paths = sorted(set(os.path.realpath(p) for p in (args.logs or expand_globs(ERROR_LOG_GLOBS)) if os.path.isfile(p)))
    hits, files = hunt_logs(log_paths, since)
    report["logs"], report["log_files"] = hits, files
    sdirs = args.session_dir or session_dirs_from_scan()
    report["session_dirs"] = sdirs
    report["session_hits"], report["sessions_scanned"] = hunt_sessions(sdirs)
    roots = args.webroot or detect_webroots()
    report["webroots"] = roots
    if roots and not args.no_webroot:
        report["recent_php_files"], report["suspicious_files"], report["files_scanned"] = hunt_webroots(roots, since)
    report["shell_children"] = hunt_processes()
    report["persistence"] = hunt_persistence(since)

    f = report["findings"]
    for name, h in hits.items():
        f.append({"severity": h["severity"], "title": "%s: %d log line(s) in %d file(s)" % (name, h["count"], len(h["files"])),
                  "detail": "; ".join(h["samples"][:2])})
    for s in report["session_hits"]:
        f.append({"severity": "CRITICAL", "title": "session file contains PHP/serialized-object marker: %s" % s["file"], "detail": "match %r, mtime %s" % (s["match"], s["mtime"])})
    for s in report["suspicious_files"]:
        f.append({"severity": "CRITICAL", "title": "webshell-like code in %s" % s["file"], "detail": "pattern %r sha256 %s" % (s["pattern"], s["sha256"][:16])})
    if report["recent_php_files"]:
        f.append({"severity": "MEDIUM", "title": "%d PHP file(s) modified in the last %d day(s) under %s" % (len(report["recent_php_files"]), args.days, ", ".join(roots)),
                  "detail": "; ".join(x["file"] for x in report["recent_php_files"][:5])})
    for s in report["shell_children"]:
        f.append({"severity": "CRITICAL", "title": "web worker %s spawned %s (pid %d)" % (s["parent"], s["comm"], s["pid"]), "detail": s["cmdline"]})
    if report["persistence"]:
        f.append({"severity": "LOW", "title": "%d persistence-related file(s) changed since %s" % (len(report["persistence"]), since.date()),
                  "detail": "; ".join(x["file"] for x in report["persistence"][:6])})
    f.sort(key=lambda x: SEV_RANK.get(x["severity"], 9))

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        banner("%s hunt - %s (window: since %s)" % (TOOL, report["host"], since.strftime("%Y-%m-%d")))
        print("  logs scanned: %d   session dirs: %s   webroots: %s   sessions scanned: %d" % (
            len(files), ", ".join(sdirs) or "-", ", ".join(roots) or "-", report["sessions_scanned"]))
        print()
        if not f:
            print(c("  no exploitation indicators found (absence of evidence is not proof; keep logs)", "green"))
        for x in f:
            print("  %s %s" % (sev(x["severity"]), x["title"]))
            if x["detail"]:
                print("             %s" % x["detail"][:400])
        print()
        print("  Notes: pre-script OOM ('Unknown on line 0') and worker segfaults correlate with exploitation attempts but\n"
              "  also with legitimate oversized uploads. A successful exploit may leave no error at all; treat shells\n"
              "  spawned by web workers and injected session files as confirmed incidents.")
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
    return 1 if any(x["severity"] in ("CRITICAL", "HIGH") for x in f) else 0


# --------------------------------------------------------------------------
# remote
# --------------------------------------------------------------------------

WAF_HINTS = [
    ("cloudflare", lambda h: "cloudflare" in h.get("server", "").lower() or "cf-ray" in h),
    ("imperva/incapsula", lambda h: "x-iinfo" in h or "incap_ses" in h.get("set-cookie", "")),
    ("sucuri", lambda h: "x-sucuri-id" in h or "sucuri" in h.get("server", "").lower()),
    ("akamai", lambda h: "akamai" in h.get("server", "").lower() or "x-akamai-transformed" in h),
    ("aws-waf/cloudfront", lambda h: "x-amz-cf-id" in h or "cloudfront" in h.get("via", "").lower()),
    ("imunify360", lambda h: "imunify" in h.get("server", "").lower() or "x-protected-by" in h),
    ("fastly", lambda h: "x-served-by" in h and "cache-" in h.get("x-served-by", "")),
    ("bunny", lambda h: "bunnycdn" in h.get("server", "").lower()),
    ("modsecurity", lambda h: "mod_security" in h.get("server", "").lower()),
]


def http_request(url, method="GET", data=None, headers=None, timeout=10, insecure=False):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "%s/%s (+https://github.com/Swordsec/php2shell-guard)" % (TOOL, __version__))
    req.add_header("Accept", "*/*")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(16384)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(16384)
        except Exception:
            body = b""
        return e.code, {k.lower(): v for k, v in e.headers.items()}, body, None
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError) as e:
        return None, {}, b"", str(e)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


PHP_BANNER_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?(?:[-~]?(?:RC|rc|alpha|beta)\d*)?)", re.I)


def remote_check(url, timeout=10, insecure=False, probe_waf=False):
    r = {"target": url, "reachable": False, "status": None, "php_banner": None, "php_version": None, "verdict": "unknown",
         "reason": None, "session_cookie": False, "edge": [], "waf_probe": None, "error": None}
    status, hdrs, body, err = http_request(url, timeout=timeout, insecure=insecure)
    if status is None:
        r["error"] = err
        r["verdict"] = "unreachable"
        return r
    r["reachable"], r["status"] = True, status
    banner_src = " ".join(v for k, v in hdrs.items() if k in ("x-powered-by", "server"))
    m = PHP_BANNER_RE.search(banner_src)
    if m:
        r["php_banner"] = m.group(0)
        r["php_version"] = m.group(1)
    r["session_cookie"] = "phpsessid" in hdrs.get("set-cookie", "").lower()
    r["edge"] = [name for name, fn in WAF_HINTS if fn(hdrs)]
    if r["php_version"]:
        v = parse_version(r["php_version"] + (".0" if r["php_version"].count(".") == 1 else ""))
        if r["php_version"].count(".") == 1:
            st = "branch_only"
            why = "banner shows branch %s without patch level" % r["php_version"]
            if v and (v[0], v[1]) < (8, 2):
                st, why = "eol_branch", "branch %s has no upstream fix; vendor backport status not visible remotely" % r["php_version"]
        else:
            st, why = classify_version(r["php_version"])
            st = {"patched": "likely_patched", "vulnerable": "likely_vulnerable", "eol": "eol_branch"}.get(st, st)
        r["verdict"], r["reason"] = st, why
    else:
        r["verdict"], r["reason"] = "no_banner", "no PHP version in Server/X-Powered-By (hidden or not PHP)"
    if probe_waf:
        r["waf_probe"] = waf_probe(url, timeout, insecure)
    return r


def waf_probe(url, timeout, insecure):
    """Send one tiny, inert multipart POST carrying the session upload-progress
    field name, to learn whether the edge filters it. ~250 bytes, no file part,
    no session id, no PHP code. This cannot trigger either vulnerability; it
    only tells you whether a WAF rule for the feature is in front of the host."""
    boundary = "----php2shellguard%d" % int(time.time())
    body = ("--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n%s-waf-coverage-check\r\n--%s--\r\n"
            % (boundary, TOOL, boundary)).encode()
    status, hdrs, resp, err = http_request(url, method="POST", data=body, timeout=timeout, insecure=insecure,
                                           headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    if status is None:
        return {"result": "error", "status": None, "detail": err}
    if status in (403, 406, 418, 429, 451) or (status == 400 and any(k in resp.lower() for k in (b"blocked", b"waf", b"forbidden"))):
        return {"result": "filtered", "status": status, "detail": "edge rejected the upload-progress field (WAF coverage present)"}
    return {"result": "not_filtered", "status": status, "detail": "request reached the application layer unfiltered; rely on patching/ini mitigation"}


def cmd_remote(args):
    targets = list(args.targets)
    if args.file:
        with open(args.file) as fh:
            for line in fh:
                t = line.strip()
                if t and not t.startswith("#"):
                    targets.append(t)
    targets = [t if re.match(r"^https?://", t) else "https://" + t for t in targets]
    if not targets:
        print("no targets; pass URLs or -f file")
        return 3
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(remote_check, t, args.timeout, args.insecure, args.probe_waf): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())
    results.sort(key=lambda r: targets.index(r["target"]))
    if args.json:
        print(json.dumps(results, indent=2))
    elif args.csv:
        print("target,verdict,php_version,status,edge,session_cookie,waf_probe,reason")
        for r in results:
            wp = (r["waf_probe"] or {}).get("result", "")
            print(",".join('"%s"' % str(x).replace('"', "'") for x in (r["target"], r["verdict"], r["php_version"] or "", r["status"] or "",
                                                                      "|".join(r["edge"]), r["session_cookie"], wp, r["reason"] or r["error"] or "")))
    else:
        banner("%s remote - %d target(s) (passive banner check%s)" % (TOOL, len(results), ", with WAF probe" if args.probe_waf else ""))
        for r in results:
            col = {"likely_vulnerable": "red", "eol_branch": "red", "likely_patched": "green", "unreachable": "dim"}.get(r["verdict"], "yellow")
            extra = []
            if r["edge"]:
                extra.append("edge=" + "/".join(r["edge"]))
            if r["session_cookie"]:
                extra.append("PHPSESSID")
            if r["waf_probe"]:
                extra.append("waf-probe=%s(%s)" % (r["waf_probe"]["result"], r["waf_probe"]["status"]))
            print("  %s %-45s php=%-12s %s" % (c("%-18s" % r["verdict"], col), r["target"][:45], r["php_version"] or "-", " ".join(extra)))
            print("      %s" % (r["reason"] or r["error"] or ""))
        print()
        print("  A banner is a hint, not proof: CDNs hide it, distro backports keep old numbers, and the ini state is not\n"
              "  visible remotely. Confirm on the host with `%s scan`." % sys.argv[0])
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
    if any(r["verdict"] in ("likely_vulnerable", "eol_branch") for r in results):
        return 1
    if all(r["verdict"] in ("unreachable", "no_banner", "unknown") for r in results):
        return 2
    return 0


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

RULES = {}

RULES["modsecurity"] = r"""# php2shell-guard - ModSecurity v2/v3 rules for CVE-2026-109618 / CVE-2026-109619
# Load after the CRS (or standalone). Requires SecRequestBodyAccess On and
# a request body limit large enough to actually see multipart parts:
#   SecRequestBodyAccess On
#   SecRequestBodyLimit 33554432
#   SecRequestBodyNoFilesLimit 1048576
#   SecRequestBodyLimitAction Reject
# Rule IDs 9951000-9951099 are reserved for this file.

# 1. Session upload-progress field in a multipart body (confirmed 109619 path).
#    Near-zero legitimate use; the feature is almost never consumed by apps.
SecRule REQUEST_METHOD "@streq POST" \
    "id:9951001,phase:2,deny,status:403,log,msg:'php2shell: PHP_SESSION_UPLOAD_PROGRESS field in multipart body',tag:'php2shell',tag:'CVE-2026-109619',severity:'CRITICAL',chain"
    SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data" "chain"
        SecRule ARGS_NAMES|REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" "t:none"

# 2. Multipart POST without a usable Content-Length (chunked), which sidesteps
#    the early post_max_size check (109618 OOM vector).
SecRule REQUEST_HEADERS:Transfer-Encoding "@contains chunked" \
    "id:9951002,phase:1,deny,status:411,log,msg:'php2shell: chunked multipart POST without Content-Length',tag:'php2shell',tag:'CVE-2026-109618',severity:'HIGH',chain"
    SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data" "chain"
        SecRule &REQUEST_HEADERS:Content-Length "@eq 0"

# 3. Excessive number of multipart parts / form fields (memory amplification).
SecRule &ARGS "@gt 500" \
    "id:9951003,phase:2,deny,status:413,log,msg:'php2shell: more than 500 form fields in one request',tag:'php2shell',tag:'CVE-2026-109618',severity:'HIGH'"
SecRule FILES_COMBINED_SIZE "@gt 33554432" \
    "id:9951004,phase:2,deny,status:413,log,msg:'php2shell: combined upload size above 32M',tag:'php2shell',tag:'CVE-2026-109618',severity:'MEDIUM'"

# 4. Very long form field names / deep nesting (hash-table amplification).
SecRule ARGS_NAMES "@rx ^.{1024,}$" \
    "id:9951005,phase:2,deny,status:400,log,msg:'php2shell: form field name longer than 1024 bytes',tag:'php2shell',tag:'CVE-2026-109618',severity:'HIGH'"
SecRule ARGS_NAMES "@rx (\[[^\]]*\]){16,}" \
    "id:9951006,phase:2,deny,status:400,log,msg:'php2shell: form field nesting deeper than 16 levels',tag:'php2shell',tag:'CVE-2026-109618',severity:'MEDIUM'"

# 5. PHP code or serialized objects in upload filenames (session-file injection).
SecRule FILES|FILES_NAMES "@rx (?i)(<\?(php|=)|\|O:\d+:\")" \
    "id:9951007,phase:2,deny,status:403,log,msg:'php2shell: PHP tag or serialized object in upload filename',tag:'php2shell',tag:'CVE-2026-109619',severity:'CRITICAL'"

# 6. Session id supplied in a request body (fixation precondition; alert only,
#    some legacy apps post PHPSESSID legitimately).
SecRule ARGS_POST_NAMES "@streq PHPSESSID" \
    "id:9951008,phase:2,pass,log,msg:'php2shell: PHPSESSID passed in POST body',tag:'php2shell',severity:'NOTICE'"

# 7. Response-side: memory exhaustion before any script ran, or session
#    destruction failure, leaking to the client. Log only; correlate with 1-6.
SecRule RESPONSE_BODY "@rx Allowed memory size of \d+ bytes exhausted.{0,80}Unknown on line 0" \
    "id:9951020,phase:4,pass,log,msg:'php2shell: pre-script OOM fatal error in response',tag:'php2shell',tag:'CVE-2026-109618',severity:'HIGH'"
SecRule RESPONSE_BODY "@contains Session object destruction failed" \
    "id:9951021,phase:4,pass,log,msg:'php2shell: session destruction failure in response',tag:'php2shell',tag:'CVE-2026-109619',severity:'HIGH'"
"""

RULES["nginx"] = r"""# php2shell-guard - nginx front-end limits for CVE-2026-109618 / CVE-2026-109619
# Include inside the server {} or location {} that proxies to PHP-FPM / Apache.
# These cap what PHP has to parse before any application code runs.

# Bound the decoded request body (8m if the app has no uploads, 32m if it has).
client_max_body_size 32m;
client_body_buffer_size 128k;
client_body_timeout 15s;
client_header_buffer_size 4k;
large_client_header_buffers 4 16k;

# Block the session upload-progress field and PHP tags in multipart bodies.
# nginx cannot inspect bodies natively; this uses the 'ngx_http_lua' /
# OpenResty module if present. Without it, keep the limits above and run
# the ModSecurity/Coraza connector with rules from `php2shell-guard rules modsecurity`.
#
#   location ~ \.php$ {
#       access_by_lua_block {
#           local ct = ngx.var.http_content_type or ""
#           if ngx.var.request_method == "POST" and ct:lower():find("multipart/form-data", 1, true) then
#               ngx.req.read_body()
#               local body = ngx.req.get_body_data()
#               if body and (body:find("PHP_SESSION_UPLOAD_PROGRESS", 1, true) or body:find("<?php", 1, true)) then
#                   ngx.log(ngx.WARN, "php2shell: blocked multipart body from ", ngx.var.remote_addr)
#                   return ngx.exit(403)
#               end
#           end
#       end
#       ...fastcgi_pass...
#   }

# Reject chunked multipart POSTs without a Content-Length (they sidestep
# PHP's early post_max_size check). Harmless for ordinary browsers/forms.
#   if ($http_transfer_encoding ~* chunked) { return 411; }

# If the application never accepts multipart at all, refuse it outright:
#   if ($content_type ~* "multipart/form-data") { return 415; }

# Never pass per-request ini overrides from untrusted config:
#   fastcgi_param PHP_VALUE ...;        <- remove unless you own every value
#   fastcgi_param PHP_ADMIN_VALUE ...;  <- same
"""

RULES["apache"] = r"""# php2shell-guard - Apache httpd front-end hardening for CVE-2026-109618 / CVE-2026-109619
# Put in conf-available/ (Debian: a2enconf) or conf.d/ (RHEL) and reload.

# Cap decoded request body size in bytes (8M no uploads, 32M with uploads).
LimitRequestBody 33554432
LimitRequestFields 100
LimitRequestFieldSize 8190
LimitRequestLine 8190

# Slow-body protection (mod_reqtimeout, enabled by default on Debian).
<IfModule reqtimeout_module>
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
</IfModule>

# Administrative ini values that neither .htaccess nor ini_set() can undo.
<IfModule php_module>
    php_admin_flag session.upload_progress.enabled off
    # PHP 8.5 only; remove the line on older builds if your httpd refuses it
    # php_admin_flag fatal_error_backtraces off
    # Interim OOM mitigation from the php.net advisory (pair with a cgroup limit):
    # php_admin_value memory_limit -1
    php_admin_value post_max_size 32M
    php_admin_value upload_max_filesize 30M
</IfModule>
<IfModule php7_module>
    php_admin_flag session.upload_progress.enabled off
    php_admin_value post_max_size 32M
    php_admin_value upload_max_filesize 30M
</IfModule>

# Do NOT use RLimitMEM for this: RLIMIT_AS / RLIMIT_DATA make mmap() fail,
# which is exactly the allocation failure the vulnerability needs.

# Refuse chunked multipart POSTs (no usable Content-Length) with mod_rewrite:
<IfModule rewrite_module>
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} =POST
    RewriteCond %{HTTP:Transfer-Encoding} chunked [NC]
    RewriteCond %{HTTP:Content-Type} multipart/form-data [NC]
    RewriteRule .* - [R=411,L]
</IfModule>

# Body inspection needs mod_security; load rules from `php2shell-guard rules modsecurity`.
"""

RULES["haproxy"] = r"""# php2shell-guard - HAProxy front-end rules for CVE-2026-109618 / CVE-2026-109619
# Add to the frontend (or a shared defaults) in front of PHP backends.

frontend web
    bind :443 ssl crt /etc/haproxy/certs/
    option http-buffer-request
    # Buffer up to 1 MiB of the body for inspection (tune_bufsize/tune.h2 may need raising)
    timeout http-request 15s

    # 1. Chunked multipart POST without Content-Length (sidesteps post_max_size)
    acl is_post   method POST
    acl is_mp     req.hdr(content-type) -m sub -i multipart/form-data
    acl chunked   req.hdr(transfer-encoding) -m sub -i chunked
    acl no_cl     req.hdr_cnt(content-length) eq 0
    http-request deny deny_status 411 if is_post is_mp chunked no_cl

    # 2. Oversized bodies (32 MiB; use 8388608 if the app has no uploads)
    acl big_body  req.hdr_val(content-length) gt 33554432
    http-request deny deny_status 413 if is_post big_body

    # 3. Session upload-progress field or PHP tag inside the buffered body
    acl body_up   req.body -m sub PHP_SESSION_UPLOAD_PROGRESS
    acl body_php  req.body -m sub <?php
    acl body_obj  req.body -m reg \|O:[0-9]+:"
    http-request deny deny_status 403 if is_post is_mp body_up
    http-request deny deny_status 403 if is_post is_mp body_php
    http-request deny deny_status 403 if is_post is_mp body_obj

    # 4. Log the rest for hunting
    http-request capture req.hdr(content-length) len 12
    http-request capture req.hdr(content-type) len 40
    default_backend php
"""

RULES["suricata"] = r"""# php2shell-guard - Suricata/Snort rules for CVE-2026-109618 / CVE-2026-109619
# SIDs 9951100-9951199 reserved for this file. Test before deploying inline.

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"PHP2SHELL session upload-progress field in multipart POST"; flow:established,to_server; http.method; content:"POST"; http.content_type; content:"multipart/form-data"; nocase; http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; fast_pattern; classtype:web-application-attack; reference:cve,2026-109619; reference:url,www.php.net/archive/2026.php#2026-10-21-5; sid:9951101; rev:1; metadata:php2shell, severity critical;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"PHP2SHELL PHP open tag in multipart upload filename"; flow:established,to_server; http.method; content:"POST"; http.content_type; content:"multipart/form-data"; nocase; http.request_body; content:"filename="; content:"<?"; distance:0; within:300; classtype:web-application-attack; reference:cve,2026-109619; sid:9951102; rev:1; metadata:php2shell, severity critical;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"PHP2SHELL serialized object marker in multipart upload filename"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"filename="; content:"|7c|O:"; distance:0; within:300; pcre:"/filename=[^\r\n]{0,200}\|O:\d+:\"/"; classtype:web-application-attack; reference:cve,2026-109619; sid:9951103; rev:1; metadata:php2shell, severity high;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"PHP2SHELL chunked multipart POST without Content-Length"; flow:established,to_server; http.method; content:"POST"; http.header; content:"Transfer-Encoding|3a 20|chunked"; nocase; http.content_type; content:"multipart/form-data"; nocase; http.header; content:!"Content-Length|3a|"; nocase; classtype:attempted-dos; reference:cve,2026-109618; sid:9951104; rev:1; metadata:php2shell, severity medium;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"PHP2SHELL very large urlencoded POST body (possible OOM trigger)"; flow:established,to_server; http.method; content:"POST"; http.content_type; content:"application/x-www-form-urlencoded"; nocase; http.content_len; byte_test:0,>,3000000,0,string,dec; classtype:attempted-dos; reference:cve,2026-109618; sid:9951105; rev:1; metadata:php2shell, severity medium;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHP2SHELL pre-script memory exhaustion fatal error in response"; flow:established,to_client; http.response_body; content:"Allowed memory size of"; content:"Unknown on line 0"; distance:0; within:120; classtype:web-application-attack; reference:cve,2026-109618; sid:9951110; rev:1; metadata:php2shell, severity high;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHP2SHELL session destruction failure message in response"; flow:established,to_client; http.response_body; content:"Session object destruction failed"; classtype:web-application-attack; reference:cve,2026-109619; sid:9951111; rev:1; metadata:php2shell, severity high;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHP2SHELL unusually long PHPSESSID in Set-Cookie (possible heap leak)"; flow:established,to_client; http.header; content:"Set-Cookie|3a 20|PHPSESSID="; nocase; pcre:"/Set-Cookie\x3a\x20PHPSESSID=[^;\r\n]{300,}/i"; classtype:web-application-attack; reference:cve,2026-109619; sid:9951112; rev:1; metadata:php2shell, severity medium;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHP2SHELL server advertises unpatched PHP 8.x banner"; flow:established,to_client; http.header; content:"X-Powered-By|3a 20|PHP/8."; nocase; pcre:"/X-Powered-By\x3a\x20PHP\/8\.(?:2\.(?:[0-9]|[12][0-9]|3[0-4])|3\.(?:[0-9]|[12][0-9]|3[0-5])|4\.(?:[0-9]|1[0-9]|2[0-6])|5\.(?:[0-9]|1[01]))(?:[^0-9]|$)/i"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:policy-violation; reference:cve,2026-109618; sid:9951120; rev:1; metadata:php2shell, severity informational;)
"""

RULES["caddy"] = r"""# php2shell-guard - Caddy / FrankenPHP front-end limits for CVE-2026-109618 / CVE-2026-109619
# FrankenPHP embeds PHP; the same ini mitigations apply (php.ini or the
# php_ini directive). Cap the body before PHP parses it:

example.com {
    request_body {
        max_size 32MB
    }
    @upload_progress {
        method POST
        header Content-Type *multipart/form-data*
        # Caddy cannot match bodies natively; put Coraza (caddy-coraza) in front:
        #   coraza_waf { directives ` Include /etc/coraza/php2shell.conf ` }
    }
    @chunked_multipart {
        method POST
        header Transfer-Encoding *chunked*
        header Content-Type *multipart/form-data*
    }
    respond @chunked_multipart 411

    php_server {
        # FrankenPHP: ini values that apply before request parsing
        php_ini session.upload_progress.enabled 0
        php_ini post_max_size 32M
        php_ini upload_max_filesize 30M
    }
}
"""


def cmd_rules(args):
    names = list(RULES) if args.which in ("all", None) else [args.which]
    if args.out:
        os.makedirs(args.out, exist_ok=True)
    for n in names:
        ext = {"modsecurity": "conf", "nginx": "conf", "apache": "conf", "haproxy": "cfg", "suricata": "rules", "caddy": "Caddyfile"}[n]
        if args.out:
            p = os.path.join(args.out, "php2shell-%s.%s" % (n, ext))
            with open(p, "w") as fh:
                fh.write(RULES[n])
            print("wrote %s" % p)
        else:
            if len(names) > 1:
                print("#" * 78 + "\n# %s\n" % n + "#" * 78)
            print(RULES[n])
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog=TOOL, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="%s %s" % (TOOL, __version__))
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="audit this host for unpatched PHP runtimes and risky configuration")
    s.add_argument("--json", action="store_true", help="print the full report as JSON")
    s.add_argument("-o", "--output", help="also write the JSON report to this file")
    s.add_argument("--docker", action="store_true", help="also inspect running Docker containers")
    s.add_argument("--no-config", action="store_true", help="skip effective-ini and FPM pool checks (faster)")

    s = sub.add_parser("protect", help="apply php.net interim mitigations (dry run unless --apply)")
    s.add_argument("--apply", action="store_true", help="write changes (requires root)")
    s.add_argument("--rollback", action="store_true", help="remove everything protect wrote")
    s.add_argument("--restart", action="store_true", help="restart PHP-FPM / Apache / LiteSpeed services afterwards")
    s.add_argument("--memory-unlimited", action="store_true", help="also set memory_limit=-1 (CVE-2026-109618 interim advice)")
    s.add_argument("--post-max", metavar="SIZE", help="also cap post_max_size (8M without uploads, 32M with)")
    s.add_argument("--upload-max", metavar="SIZE", help="upload_max_filesize to pair with --post-max (default: post-max minus 2M)")
    s.add_argument("--nesting", type=int, default=32, help="max_input_nesting_level when --post-max is set (default 32)")
    s.add_argument("--no-fpm-pools", action="store_true", help="do not insert php_admin_* lines into FPM pool files")
    s.add_argument("--no-apache", action="store_true", help="do not write the Apache mod_php conf")

    s = sub.add_parser("hunt", help="look for exploitation traces on this host")
    s.add_argument("--days", type=int, default=14, help="look-back window for logs/files (default 14; exploitation began 2026-10-17)")
    s.add_argument("--logs", nargs="*", help="error log files to scan (default: common locations)")
    s.add_argument("--session-dir", nargs="*", help="session save paths to scan (default: from PHP config + common paths)")
    s.add_argument("--webroot", nargs="*", help="document roots to scan (default: from web server config + common paths)")
    s.add_argument("--no-webroot", action="store_true", help="skip webroot file scan")
    s.add_argument("--json", action="store_true")
    s.add_argument("-o", "--output")

    s = sub.add_parser("remote", help="passive banner check of your own hosts (no exploitation)")
    s.add_argument("targets", nargs="*", help="URLs or hostnames")
    s.add_argument("-f", "--file", help="file with one target per line")
    s.add_argument("--probe-waf", action="store_true", help="also send one tiny inert multipart POST to see if the edge filters the upload-progress field")
    s.add_argument("--workers", type=int, default=8)
    s.add_argument("--timeout", type=int, default=10)
    s.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    s.add_argument("--json", action="store_true")
    s.add_argument("--csv", action="store_true")
    s.add_argument("-o", "--output")

    s = sub.add_parser("rules", help="print WAF / proxy / IDS snippets")
    s.add_argument("which", nargs="?", default="all", choices=["all"] + list(RULES))
    s.add_argument("--out", help="write each ruleset to a file in this directory")
    return p


def main(argv=None):
    global USE_COLOR
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color:
        USE_COLOR = False
    if not args.cmd:
        parser.print_help()
        return 3
    try:
        return {"scan": cmd_scan, "protect": cmd_protect, "hunt": cmd_hunt, "remote": cmd_remote, "rules": cmd_rules}[args.cmd](args)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
