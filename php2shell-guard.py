#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell-guard - scanner, hardening and hunting tool for php2shell
(CVE-2026-109618 "RCE via OOM corruption" / CVE-2026-109619 "RCE via stale
global state").

    scan     audit this host: every PHP binary, running worker, package and
             effective configuration, with a per-install verdict
             (--docker: the same inside every running container)
    protect  apply (or roll back) the php.net-advised mitigations as drop-ins
             (--docker: inside running containers)
    hunt     look for exploitation traces (logs, session files, webroots,
             web-worker child processes, cron; --docker: in containers)
    remote   passive banner scan of your own hosts, optional WAF coverage check
    rules    print ModSecurity / nginx / Apache / HAProxy / Suricata snippets

Python 3.8+, standard library only. No exploit code is included and nothing
in this tool attempts to trigger either vulnerability.

https://github.com/Swordsec/php2shell-guard
"""

from __future__ import print_function

import argparse
import concurrent.futures
import contextlib
import datetime
import glob
import gzip
import hashlib
import io
import itertools
import json
import mmap
import os
import platform
import posixpath
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1.0"
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
# Directories Apache includes automatically (protect writes its conf into the first one found).
APACHE_INCLUDE_DIRS = (
    "/etc/apache2/conf-available", "/etc/httpd/conf.d", "/usr/local/apache/conf/includes",
    "/usr/local/etc/apache24/Includes", "/etc/apache24/Includes", "/opt/homebrew/etc/httpd/extra",
)
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


def run(cmd, timeout=20, env_extra=None, stdin_data=None, binary=False):
    """Run a command, return (rc, stdout, stderr). Never raises.
    stdout stays bytes when binary is set."""
    env = dict(os.environ)
    env.setdefault("LC_ALL", "C")
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           env=env, input=stdin_data)
        out = p.stdout if binary else p.stdout.decode("utf-8", "replace")
        return p.returncode, out, p.stderr.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as e:
        return -1, b"" if binary else "", str(e)


def which(name):
    return shutil.which(name)


def expand_globs(patterns):
    out = []
    for p in patterns:
        out.extend(glob.glob(p))
    return out


class HostContext(object):
    """Commands and files on this machine. Container (see the Docker section)
    offers the same methods through docker exec, so the scan / protect code
    below works on either."""
    name = None
    join = staticmethod(os.path.join)

    def run(self, cmd, timeout=20, stdin_data=None, binary=False):
        return run(cmd, timeout=timeout, stdin_data=stdin_data, binary=binary)

    def which(self, name):
        return which(name)

    def isfile(self, path):
        return os.path.isfile(path)

    def isdir(self, path):
        return os.path.isdir(path)

    def exists(self, path):
        return os.path.exists(path)

    def glob(self, pattern):
        return glob.glob(pattern)

    def existing(self, patterns, kind="f"):
        test = os.path.isdir if kind == "d" else os.path.isfile
        return sorted(set(p for p in expand_globs(patterns) if test(p)))

    def read_text(self, path):
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def read_bytes(self, path, limit):
        try:
            with open(path, "rb") as fh:
                return fh.read(limit)
        except OSError:
            return None

    def write_text(self, path, text, mode=None):
        with open(path, "w") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(path, mode)

    def backup(self, path, bak):
        if not os.path.exists(bak):
            shutil.copy2(path, bak)

    def remove(self, path):
        os.remove(path)

    def markers(self, path):
        return read_marker_hits(path)

    def bytes_version(self, path):
        return version_from_bytes(path)

    def where(self, path):
        return path


HOST = HostContext()


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


def php_version_of(path, kind, ctx=None):
    ctx = ctx or HOST
    if kind == "module":
        return ctx.bytes_version(path), "bytes"
    if kind == "frankenphp":
        rc, out, err = ctx.run([path, "version"], timeout=15)
        m = re.search(r"PHP (\d+\.\d+\.\d+\S*)", out + err)
        if m:
            return m.group(1), "frankenphp version"
    rc, out, err = ctx.run([path, "-n", "-v"], timeout=15)
    m = re.search(r"PHP (\d+\.\d+\.\d+[^\s]*)", out + err)
    if m:
        return m.group(1).rstrip(","), "-v"
    v = ctx.bytes_version(path)
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
    def add_ns(proc, inner_path, source):
        """A binary that lives in another mount namespace (container): reach it
        through /proc/<pid>/root and dedupe by device+inode."""
        path = "/proc/%d/root%s" % (proc["pid"], inner_path)
        try:
            st_ = os.stat(path)
        except OSError:
            return
        key = "ns:%d:%d" % (st_.st_dev, st_.st_ino)
        if key in found:
            found[key]["sources"].add(source)
            found[key]["pids"].append(proc["pid"])
            return
        found[key] = {"path": path, "display": inner_path, "sources": {source}, "nsroot": True,
                      "pids": [proc["pid"]], "container": proc.get("container")}

    for proc in running_processes():
        exe = proc["exe"]
        if exe and (BIN_NAME_RE.match(os.path.basename(exe)) or re.search(r"(libphp|mod_php)", exe)):
            on_host = False
            try:
                hs = os.stat(exe)
                on_host = proc.get("exe_stat") is None or (hs.st_dev, hs.st_ino) == proc["exe_stat"]
            except OSError:
                on_host = False
            if on_host:
                add(exe, "process")
            else:
                add_ns(proc, exe, "container-process")
        for mod in proc.get("php_modules", []):
            if os.path.exists(mod) and not proc.get("container"):
                add(mod, "process-maps")
            else:
                add_ns(proc, mod, "container-process-maps")
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
            exe, deleted, exe_stat = None, False, None
            try:
                exe = os.readlink(base + "/exe")
                if exe.endswith(" (deleted)"):
                    deleted = True
                    exe = exe[:-10]
                st_ = os.stat(base + "/exe")
                exe_stat = (st_.st_dev, st_.st_ino)
            except OSError:
                pass
            container = None
            try:
                with open(base + "/cgroup", "r", errors="replace") as fh:
                    cg = fh.read()
                m = re.search(r"(?:docker[-/]|cri-containerd-|containerd[-/]|libpod-|podman[-/]|crio-|/kubepods[^\n]*?/)([0-9a-f]{12,64})", cg)
                if m:
                    container = m.group(1)[:12]
                elif re.search(r"(?m)^\d+:[^:]*:/(docker|lxc|machine\.slice|kubepods|system\.slice/docker-)", cg):
                    container = "yes"
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
                          "exe_stat": exe_stat, "container": container,
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
                              "exe_stat": None, "container": None,
                              "cmdline": args, "php_modules": [], "module_deleted": False, "user": user})
    _PROC_CACHE = procs
    return procs


# --------------------------------------------------------------------------
# Package managers
# --------------------------------------------------------------------------

def changelog_mentions_cve(paths, ctx=None):
    ctx = ctx or HOST
    for p in paths:
        data = ctx.read_bytes(p, 8 * 1024 * 1024)
        if not data:
            continue
        if p.endswith(".gz"):
            try:
                data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(400000)
            except (OSError, EOFError):
                continue
        if re.search(rb"CVE-2026-10961[89]|php2shell", data[:400000], re.I):
            return p
    return None


def check_dpkg(ctx=None):
    ctx = ctx or HOST
    if not ctx.which("dpkg-query"):
        return []
    rc, out, _ = ctx.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Status}\t${Source}\n", "php*",
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
                                         "/usr/share/doc/%s/changelog.gz" % pkg], ctx)
            if cl:
                status, how = "patched", "changelog references the CVE (%s)" % cl
        results.append({"manager": "dpkg", "package": pkg, "version": ver, "status": status, "detail": how})
    return results


def check_rpm(ctx=None):
    ctx = ctx or HOST
    if not ctx.which("rpm"):
        return []
    rc, out, _ = ctx.run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\n",
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
        rc2, cl, _ = ctx.run(["rpm", "-q", "--changelog", name], timeout=30)
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


def check_apk(ctx=None):
    ctx = ctx or HOST
    if not ctx.which("apk"):
        return []
    rc, out, _ = ctx.run(["apk", "info", "-v"], timeout=30)
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


def check_pacman(ctx=None):
    ctx = ctx or HOST
    if not ctx.which("pacman"):
        return []
    rc, out, _ = ctx.run(["pacman", "-Q"], timeout=30)
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


def check_packages(ctx=None):
    ctx = ctx or HOST
    out = []
    checks = (check_dpkg, check_rpm, check_apk, check_pacman) + ((check_brew,) if ctx is HOST else ())
    for fn in checks:
        try:
            out.extend(fn() if fn is check_brew else fn(ctx))
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


def effective_ini_from_binary(path, kind, ctx=None):
    """Ask the binary itself for its effective configuration (`-i`)."""
    ctx = ctx or HOST
    if kind == "module":
        return None, None, "module (no executable)"
    if kind == "frankenphp":
        rc, out, err = ctx.run([path, "php-cli", "-i"], timeout=20)
    else:
        rc, out, err = ctx.run([path, "-i"], timeout=20)
    if rc != 0 and "=>" not in out:
        return None, None, (err.strip().splitlines() or ["-i failed"])[-1]
    conf, info = parse_phpinfo_text(out)
    return conf, info, None


def parse_ini_text(text):
    vals = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in ";#[":
            continue
        m = re.match(r"^([\w.]+)\s*=\s*(.*?)\s*(?:;.*)?$", line)
        if m:
            vals[m.group(1)] = m.group(2).strip().strip('"')
    return vals


def parse_ini_file(path, ctx=None):
    return parse_ini_text((ctx or HOST).read_text(path))


def resolve_static_ini(ini_file, scan_dir, ctx=None):
    """Resolve php.ini + scan dir drop-ins the way PHP does (alphabetical)."""
    ctx = ctx or HOST
    vals, files = {}, []
    if ini_file and ctx.isfile(ini_file):
        vals.update(parse_ini_file(ini_file, ctx))
        files.append(ini_file)
    if scan_dir and ctx.isdir(scan_dir):
        for f in sorted(ctx.glob(ctx.join(scan_dir, "*.ini"))):
            vals.update(parse_ini_file(f, ctx))
            files.append(f)
    conf = {k: (v, v) for k, v in vals.items() if k in INI_KEYS}
    return conf, files


def sapi_ini_dirs_for(path, ctx=None):
    """For a binary, guess sibling per-SAPI ini dirs (Debian layout)."""
    ctx = ctx or HOST
    out = []
    m = re.search(r"/etc/php/(\d\.\d)/", path)
    if m:
        for s in ("apache2", "fpm", "cgi", "litespeed", "embed"):
            d = "/etc/php/%s/%s" % (m.group(1), s)
            if ctx.isdir(d):
                out.append((s, ctx.join(d, "php.ini"), ctx.join(d, "conf.d")))
    return out


def parse_fpm_tt(text):
    """Per-pool php_* overrides and pm settings from `php-fpm -tt` output."""
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
    return pools


def fpm_pool_overrides(fpm_bin, ctx=None):
    """Dump FPM config with -tt and collect per-pool overrides."""
    rc, out, err = (ctx or HOST).run([fpm_bin, "-tt"], timeout=20)
    text = out + err
    pools = parse_fpm_tt(text)
    ok = rc == 0 and ("test is successful" in text or pools)
    return pools, ok, (text.strip().splitlines() or [""])[-1]


APACHE_PHP_DIRECTIVE_RE = re.compile(r"(php_(?:admin_)?(?:value|flag))\s+(session\.upload_progress\.enabled|memory_limit|post_max_size|upload_max_filesize|fatal_error_backtraces|max_input_nesting_level)\s+(\S+)", re.I)


def apache_directive(line):
    """(kind, key, value) for an Apache line this tool cares about, else None."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    m = APACHE_PHP_DIRECTIVE_RE.match(s)
    if m:
        return m.group(1).lower(), m.group(2).lower(), m.group(3)
    m = re.match(r"(RLimitMEM)\s+(.*)", s, re.I)
    if m:
        return "rlimitmem", "RLimitMEM", m.group(2)
    m = re.match(r"(LimitRequestBody)\s+(\d+)", s, re.I)
    if m:
        return "limitrequestbody", "LimitRequestBody", m.group(2)
    return None


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
                    d = apache_directive(line)
                    if not d:
                        continue
                    if d[0].startswith("php_"):
                        key = (real, d[0], d[1], d[2].lower())
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                    findings.append({"file": conf, "line": n, "kind": d[0], "key": d[1], "value": d[2]})
        except OSError:
            continue
    return findings


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def assess_install(entry, procs, pkgs, no_config=False, ctx=None):
    ctx = ctx or HOST
    path = entry["path"]
    nsroot = bool(entry.get("nsroot"))
    display = entry.get("display", path)
    kind = binary_kind(display)
    res = {"path": display if nsroot else path, "kind": kind, "sources": sorted(entry["sources"]), "version": None,
           "version_source": None, "version_status": None, "version_reason": None,
           "fingerprint": [], "running": [], "stale_running": False, "config": None, "config_note": None,
           "sapi_configs": [], "fpm_pools": None, "findings": [], "verdict": None,
           "container": entry.get("container") if nsroot else None, "proc_root": path if nsroot else None}
    if entry.get("unreadable"):
        res["verdict"] = "UNKNOWN"
        res["findings"].append(("INFO", "binary not readable (run as root for a full check)", ""))
        return res
    if nsroot:
        # never execute a foreign namespace's binary; read it instead
        ver, how = version_from_bytes(path), "bytes"
    else:
        ver, how = php_version_of(path, kind, ctx)
    res["version"], res["version_source"] = ver, how
    st, why = classify_version(ver or "")
    res["version_status"], res["version_reason"] = st, why
    res["fingerprint"] = sorted(ctx.markers(path))

    if nsroot:
        res["running"] = sorted(entry.get("pids", []))
        pidset = set(res["running"])
        res["stale_running"] = any(p["deleted"] for p in procs if p["pid"] in pidset)
        res["config_note"] = "inside a container (pid %s%s); run `scan --docker` or scan in that container for ini/pool checks" % (
            res["running"][0] if res["running"] else "?", ", id %s" % res["container"] if res["container"] and res["container"] != "yes" else "")
        no_config = True
    for p in procs:
        if not nsroot and (p["exe"] == path or path in p.get("php_modules", [])):
            res["running"].append(p["pid"])
            if p["deleted"] or (path in p.get("php_modules", []) and p["module_deleted"]):
                res["stale_running"] = True

    # effective config
    if not no_config:
        conf, info, note = effective_ini_from_binary(path, kind, ctx)
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
                for d in ctx.glob(pat):
                    cands.append(("apache2", d + "/php.ini", d + "/conf.d"))
            if ctx.isfile("/etc/php.ini"):
                cands.append(("apache2", "/etc/php.ini", "/etc/php.d"))
            if ctx.isdir("/usr/local/etc/php"):
                # Docker official php:*-apache images
                cands.append(("apache2", "/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d"))
            for sapi, ini, scan in cands:
                c_, files = resolve_static_ini(ini, scan, ctx)
                if files:
                    res["config"] = {k: v[0] for k, v in c_.items()}
                    # PHP defaults for directives the ini files leave commented out
                    res["config"].setdefault("session.upload_progress.enabled", "On (default)")
                    res["config_files"] = {"ini_file": ini, "scan_dir": scan, "additional": files[1:]}
                    res["config_note"] = "static parse of %s (+%d drop-ins)" % (ini, len(files) - 1)
                    break
        if kind == "cli":
            for sapi, ini, scan in sapi_ini_dirs_for((res.get("config_files") or {}).get("ini_file") or "", ctx):
                c_, files = resolve_static_ini(ini, scan, ctx)
                if files:
                    res["sapi_configs"].append({"sapi": sapi, "ini_file": ini, "config": {k: v[0] for k, v in c_.items()}})
        if kind == "fpm":
            pools, ok, last = fpm_pool_overrides(path, ctx)
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


HOST_UNPATCHED_FIX = "update to the fixed release for the branch and restart every worker"


def install_findings(inst, prefix="", unpatched_fix=HOST_UNPATCHED_FIX):
    """Findings for one assessed install. prefix names the container, if any."""
    where = (prefix + ":" if prefix else "") + inst["path"]
    label = "%s (%s)" % (where, inst["kind"])
    pool_prefix = prefix + ": " if prefix else ""
    out = []
    for f in inst["findings"]:
        out.append((f[0], label + ": " + f[1], f[2]))
    if inst["verdict"] == "VULNERABLE":
        out.append(("CRITICAL", "%s is unpatched (PHP %s, %s)" % (label, inst["version"], inst["version_reason"]), unpatched_fix))
    elif inst["verdict"] == "UNKNOWN":
        out.append(("MEDIUM", "%s: could not determine patch status" % label, "check manually"))
    out.extend(config_findings(inst.get("config"), label, inst["verdict"]))
    for sc in inst.get("sapi_configs", []):
        out.extend(config_findings(sc["config"], "%s [%s sapi: %s]" % (where, sc["sapi"], sc["ini_file"]), inst["verdict"]))
    fp = inst.get("fpm_pools")
    if fp and fp["pools"]:
        for pool, vals in fp["pools"].items():
            if pool.lower() in ("general", "global"):
                continue
            v = vals.get("session.upload_progress.enabled")
            if v and ini_bool(v[1]) is False:
                out.append(("OK", "%sFPM pool [%s] enforces session.upload_progress.enabled=off via %s" % (pool_prefix, pool, v[0]), ""))
            mlv = vals.get("memory_limit")
            if mlv and inst["verdict"] != "PATCHED" and mlv[1].strip() != "-1":
                out.append(("LOW", "%sFPM pool [%s] sets memory_limit=%s (%s)" % (pool_prefix, pool, mlv[1], mlv[0]),
                            "a pool-level finite limit overrides any php.ini memory_limit=-1 mitigation"))
            mr = vals.get("pm.max_requests")
            if mr and inst["verdict"] != "PATCHED" and mr[1].strip() == "0":
                out.append(("LOW", "%sFPM pool [%s] pm.max_requests=0 (workers never recycle)" % (pool_prefix, pool),
                            "a low pm.max_requests shortens how long stale state can persist in a worker"))
    elif fp and not fp["ok"]:
        out.append(("INFO", "%s: could not dump FPM pools (%s)" % (where, fp["note"]), "run as root"))
    return out


def package_findings(pkgs, prefix=""):
    pre = prefix + ": " if prefix else ""
    out = []
    for pk in pkgs:
        if pk["status"] == "vulnerable":
            out.append(("CRITICAL", "%spackage %s %s is unpatched (%s)" % (pre, pk["package"], pk["version"], pk["detail"]),
                        "apply the vendor update" + (" and rebuild the image" if prefix else "")))
        elif pk["status"] == "unknown":
            out.append(("MEDIUM", "%spackage %s %s: patch status not confirmed (%s)" % (pre, pk["package"], pk["version"], pk["detail"]),
                        "compare with your vendor advisory"))
    return out


def apache_findings(directives, prefix=""):
    pre = prefix + ":" if prefix else ""
    out = []
    for a in directives:
        loc = "%s%s:%d" % (pre, a["file"], a["line"])
        if a["kind"] == "rlimitmem":
            out.append(("MEDIUM", "Apache RLimitMEM in %s" % loc,
                        "php.net advises against RLIMIT_AS/RLIMIT_DATA style limits: they can cause the allocation failure the bug depends on"))
        elif a["key"] == "session.upload_progress.enabled" and ini_bool(a["value"]) is False:
            out.append(("OK", "Apache %s disables session.upload_progress in %s" % (a["kind"], loc), ""))
        elif a["key"] == "session.upload_progress.enabled":
            out.append(("HIGH", "Apache %s re-enables session.upload_progress in %s" % (a["kind"], loc), "remove it"))
        elif a["key"] == "memory_limit" and a["kind"] in ("php_value", "php_admin_value"):
            if a["value"].strip() == "-1":
                out.append(("OK", "Apache %s memory_limit -1 in %s" % (a["kind"], loc), ""))
            else:
                out.append(("INFO", "Apache %s memory_limit %s in %s" % (a["kind"], a["value"], loc),
                            "per-directory limits override a global memory_limit=-1 mitigation"))
    return out


def cmd_scan(args):
    t0 = time.time()
    docker = args.docker or bool(args.container)
    report = {"tool": TOOL, "version": __version__, "host": socket.gethostname(), "time": datetime.datetime.now().isoformat(),
              "platform": platform.platform(), "root": is_root(), "installs": [], "packages": [], "apache": [],
              "docker": [], "docker_error": None, "findings": [], "verdict": None}
    procs = running_processes()
    pkgs = check_packages()
    report["packages"] = pkgs
    bins = find_php_binaries()
    for b in bins:
        report["installs"].append(assess_install(b, procs, pkgs, no_config=args.no_config))

    # Apache directives
    report["apache"] = scan_apache_configs()
    report["docker_auto"] = False
    if docker:
        report["docker"], report["docker_error"] = scan_docker(args.container, no_config=args.no_config)
    elif not any(not i.get("proc_root") for i in report["installs"]) and which("docker"):
        # nothing on the host itself: PHP is probably inside containers. Cheap pass
        # (no ini / pool checks); --docker does the deep one.
        report["docker"], report["docker_error"] = scan_docker(None, no_config=True)
        report["docker_auto"] = True
    report["installs"], report["proc_covered"] = dedupe_proc_installs(report["installs"], report["docker"])
    report["hints"] = no_php_hints(report) if not report["installs"] else []

    # aggregate findings
    findings = []
    for inst in report["installs"]:
        findings.extend(install_findings(inst))
    findings.extend(package_findings(pkgs))
    findings.extend(apache_findings(report["apache"]))
    for d in report["docker"]:
        findings.extend(container_findings(d))
    if report["docker_error"]:
        findings.append(("MEDIUM", "Docker containers not (fully) inspected: %s" % report["docker_error"],
                         "check `docker ps` works for this user"))
    if not report["installs"] and not report["docker"]:
        findings.append(("INFO", "no PHP binaries or Apache PHP modules found on this host", ""))
    for h in report.get("hints", []):
        findings.append(("INFO", h, ""))

    findings.sort(key=lambda f: SEV_RANK.get(f[0], 9))
    report["findings"] = [{"severity": s, "title": t, "fix": x} for s, t, x in findings]
    units = report["installs"] + report["docker"]
    if any(u["verdict"] == "VULNERABLE" for u in units) or any(p["status"] == "vulnerable" for p in pkgs):
        report["verdict"] = "VULNERABLE"
    elif any(u["verdict"] == "UNKNOWN" for u in units) or (docker and report["docker_error"]):
        report["verdict"] = "UNKNOWN"
    elif units:
        report["verdict"] = "PATCHED"
    elif any(p["status"] == "unknown" for p in pkgs):
        report["verdict"] = "UNKNOWN"
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


def dedupe_proc_installs(installs, docker_results):
    """Runtimes seen from the host through /proc that `scan_docker` also
    covered are reported once, in the Docker section. Returns
    (remaining host installs, covered entries)."""
    remaining, covered = [], []
    for inst in installs:
        if not inst.get("proc_root"):
            remaining.append(inst)
            continue
        cid = inst.get("container")
        hit = None
        for d in docker_results:
            if cid and cid != "yes" and d.get("id") and d["id"][:12] == cid[:12]:
                hit = d
                break
            if any(di["path"] == inst["path"] and di["kind"] == inst["kind"] and di.get("version") == inst.get("version")
                   and sorted(di.get("fingerprint") or []) == sorted(inst.get("fingerprint") or [])
                   for di in d.get("installs", [])):
                hit = d
                break
        if hit is None:
            remaining.append(inst)
            continue
        inst["covered_by"] = hit["name"]
        hit.setdefault("proc_pids", []).extend(inst.get("running", []))
        covered.append(inst)
    return remaining, covered


def no_php_hints(report):
    """Explain a NO_PHP result: what else is on the box that could still
    front a PHP runtime somewhere else."""
    hints = []
    procs = running_processes()
    web = sorted(set(p["comm"] for p in procs if p["comm"] in ("nginx", "apache2", "httpd", "caddy", "litespeed", "lshttpd")
                     and not p.get("container")))
    if web:
        hints.append("web server running without a local PHP runtime (%s): it may proxy to containers, Kubernetes pods or another host; "
                     "scan those" % ", ".join(web))
    if which("docker"):
        if report.get("docker_error"):
            hints.append("docker: %s; PHP containers would not be visible" % report["docker_error"])
        elif report.get("docker_auto"):
            hints.append("no PHP on the host, so running containers were inspected automatically (cheap pass; `--docker` adds ini, pools and packages)")
    for tool in ("podman", "kubectl", "ctr", "crictl"):
        if which(tool):
            hints.append("%s is installed: workloads under it are not inspected through docker; run scan inside those containers/pods" % tool)
    if which("snap"):
        rc, out, _ = run(["snap", "list"], timeout=20)
        if rc == 0 and re.search(r"(?m)^(nextcloud|wordpress|php)", out):
            hints.append("a snap bundles its own PHP (see `snap list`); check its upstream for the fixed revision")
    if os.name != "nt" and os.path.isdir("/proc") and not is_root():
        hints.append("not root: binaries behind other users' processes (including containers) may be invisible")
    return hints


def print_install(i, pad="  "):
    col = {"PATCHED": "green", "VULNERABLE": "red"}.get(i["verdict"], "yellow")
    fp = ",".join(i["fingerprint"]) if i["fingerprint"] else "none"
    running = ("running pid " + ",".join(map(str, i["running"][:6])) + (" ..." if len(i["running"]) > 6 else "")) if i["running"] else "not running"
    if i["stale_running"]:
        running += c(" STALE BINARY", "red")
    where = ""
    if i.get("proc_root"):
        where = c("  [container%s via %s]" % (" " + i["container"] if i.get("container") and i["container"] != "yes" else "",
                                             i["proc_root"].split("/root")[0]), "cyan")
    print("%s%s %s%s" % (pad, c("%-10s" % i["verdict"], col), i["path"], where))
    if i["verdict"] == "PATCHED" and i["version_status"] in ("vulnerable", "eol") and i["fingerprint"]:
        status_line = "status=backported (version string predates the fix; patch markers confirm the build)"
    else:
        status_line = "status=%s: %s" % (i["version_status"], i["version_reason"])
    pad2 = pad + "    "
    print("%skind=%s  version=%s (%s)  %s" % (pad2, i["kind"], i["version"], i["version_source"], status_line))
    print("%spatch-markers=%s  %s  found-via=%s" % (pad2, fp, running, ",".join(i["sources"])))
    conf = i.get("config")
    if conf:
        keys = [("session.upload_progress.enabled", "upload_progress"), ("fatal_error_backtraces", "fatal_error_backtraces"),
                ("memory_limit", "memory_limit"), ("memory_hard_limit_percent", "hard_limit%"), ("post_max_size", "post_max_size"),
                ("upload_max_filesize", "upload_max_filesize"), ("max_input_nesting_level", "nesting")]
        print(pad2 + "ini: " + "  ".join("%s=%s" % (label, conf[k]) for k, label in keys if k in conf and conf[k] != "no value"))
        cf = i.get("config_files") or {}
        if cf.get("ini_file") or cf.get("scan_dir"):
            print("%sini-files: %s  scan-dir: %s" % (pad2, cf.get("ini_file") or "(none)", cf.get("scan_dir") or "(none)"))
    elif i.get("config_note"):
        print("%sini: %s" % (pad2, i["config_note"]))
    for sc in i.get("sapi_configs", []):
        print("%s[%s sapi] upload_progress=%s memory_limit=%s post_max_size=%s (%s)" % (
            pad2, sc["sapi"], sc["config"].get("session.upload_progress.enabled", "?"), sc["config"].get("memory_limit", "?"),
            sc["config"].get("post_max_size", "?"), sc["ini_file"]))
    fp_ = i.get("fpm_pools")
    if fp_ and fp_["pools"]:
        for pool, vals in fp_["pools"].items():
            if pool.lower() in ("general", "global"):
                continue
            ov = ["%s[%s]=%s" % (v[0], k, v[1]) for k, v in vals.items() if v[0] != "setting"]
            pm = vals.get("pm.max_requests", ("", "?"))[1]
            print("%sfpm pool [%s]: pm.max_requests=%s %s" % (pad2, pool, pm, " ".join(ov) if ov else "(no php_* overrides)"))


def print_packages(pkgs, pad="  "):
    for p in pkgs:
        col = {"patched": "green", "vulnerable": "red"}.get(p["status"], "yellow")
        print("%s%s %-6s %-28s %-40s %s" % (pad, c("%-10s" % p["status"].upper(), col), p["manager"], p["package"], p["version"], p["detail"]))


def print_scan_report(r):
    banner("%s %s - local audit of %s" % (TOOL, __version__, r["host"]))
    print("  %s | root=%s | %s" % (r["platform"], r["root"], r["time"]))
    if not r["root"] and (r["installs"] or not r["docker"]):
        print(c("  not running as root: process maps, FPM pool dumps and some binaries may be unreadable", "yellow"))
    print()
    banner("PHP runtimes on this host (%d)" % len(r["installs"]))
    for i in r["installs"]:
        print_install(i)
    if r["packages"]:
        print()
        banner("Packages (%d)" % len(r["packages"]))
        print_packages(r["packages"])
    if r["docker"] or r.get("docker_error"):
        print()
        banner("Docker containers with PHP (%d)%s" % (len(r["docker"]),
                                                       " - inspected automatically, no PHP on the host; --docker for ini/pools/packages" if r.get("docker_auto") else ""))
        if r.get("docker_error"):
            print(c("  %s" % r["docker_error"], "yellow"))
        for d in r["docker"]:
            col = {"PATCHED": "green", "VULNERABLE": "red"}.get(d["verdict"], "yellow")
            comp = d.get("compose")
            where = "  compose %s/%s" % (comp["project"], comp["service"]) if comp else ""
            if d.get("proc_pids"):
                where += c("  (also seen from the host: /proc pid %s)" % ",".join(map(str, sorted(set(d["proc_pids"]))[:4])), "cyan")
            print("  %s %s  image=%s%s" % (c("%-10s" % d["verdict"], col), c(d["name"], "bold"), d["image"], where))
            for i in d["installs"]:
                print_install(i, pad="      ")
            if d["packages"]:
                print_packages(d["packages"], pad="      ")
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
    if r["verdict"] == "NO_PHP":
        print("  Nothing serving PHP was found on this host itself. If PHP runs in containers, pods, a snap or on another\n"
              "  machine behind the web server here, run scan there (or with --docker). See the hints above.")
    if r["verdict"] == "VULNERABLE":
        print("  Update PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or your vendor backport) and restart every worker.")
        if any(d["verdict"] == "VULNERABLE" for d in r["docker"]):
            print("  Containers: rebuild from a fixed image. Until then `%s protect --docker --apply --restart`" % sys.argv[0])
            print("  applies the interim mitigations inside them. See %s" % ADVISORY_URL)
        else:
            print("  Until then: `%s protect --apply` applies the php.net interim mitigations. See %s" % (sys.argv[0], ADVISORY_URL))


# --------------------------------------------------------------------------
# Docker containers
# --------------------------------------------------------------------------
# Official php:* images ship no Python and no ps, so containers are driven
# from the host: docker exec runs the same probes the host scan runs,
# docker cp streams file trees for hunt, and the bind mounts reported by
# docker inspect let files that really live on the host be read in place.
# Paths that come from inside a container are only ever passed to sh as
# arguments, never spliced into a script.

# One line per process: P<US>stat<US>exe<US>cmdline, plus M<US>pid<US>module
# for PHP modules mapped into Apache / LiteSpeed processes.
CONTAINER_PROC_SH = r"""
for p in /proc/[0-9]*; do
  s=$(cat "$p/stat" 2>/dev/null) || continue
  printf 'P\037%s\037%s\037%s\n' "$s" "$(readlink "$p/exe" 2>/dev/null)" "$(tr '\000' ' ' < "$p/cmdline" 2>/dev/null)"
  case "$s" in
    *"(apache2)"*|*"(httpd)"*|*"(litespeed)"*|*"(lshttpd)"*)
      grep -E -o '/[^ ]*(libphp|mod_php)[^ ]*\.so( \(deleted\))?' "$p/maps" 2>/dev/null | sort -u |
        while read -r m; do printf 'M\037%s\037%s\n' "${p#/proc/}" "$m"; done;;
  esac
done
"""
# $1 = test flag (f, d, e), then glob patterns; prints the matches that pass.
CONTAINER_LIST_SH = 'k=$1; shift; for pat in "$@"; do for p in $pat; do [ -$k "$p" ] && echo "$p"; done; done'
# Every file on PATH (filtered with BIN_NAME_RE on the host).
CONTAINER_PATH_SH = 'IFS=:; for d in $PATH; do for f in "$d"/*; do [ -f "$f" ] && echo "$f"; done; done'
CONTAINER_REALPATH_SH = 'for f in "$@"; do r=$(readlink -f "$f" 2>/dev/null) || r=$f; [ -f "$r" ] && printf "%s\\t%s\\n" "$f" "$r"; done'
# grep -a is missing from some busybox builds (exit 2); fall back to tr. The
# octal range is deliberate: busybox tr -c does not understand [:print:].
CONTAINER_MARKERS_SH = r"""f=$1; shift
for m in "$@"; do
  grep -a -q -F "$m" "$f" 2>/dev/null; r=$?
  if [ "$r" -eq 0 ]; then echo "$m"
  elif [ "$r" -ge 2 ] && tr -c '\040-\176' '\n' < "$f" 2>/dev/null | grep -q -F "$m"; then echo "$m"; fi
done"""
CONTAINER_BYTES_VERSION_SH = r"""for re in 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9~-]*' 'PHP/[0-9]+\.[0-9]+\.[0-9]+'; do
  v=$(grep -a -o -E "$re" "$1" 2>/dev/null | head -n 1)
  [ -n "$v" ] || v=$(tr -c '\040-\176' '\n' < "$1" 2>/dev/null | grep -o -E "$re" | head -n 1)
  [ -n "$v" ] && break
done
echo "$v"
"""
CONTAINER_STAT_SH = r"""for pat in "$@"; do for p in $pat; do [ -f "$p" ] && printf '%s\t%s\t%s\n' "$p" "$(stat -c %Y "$p" 2>/dev/null)" "$(stat -c %s "$p" 2>/dev/null)"; done; done"""
CONTAINER_APACHE_GREP_SH = r"""for d in "$@"; do [ -d "$d" ] && grep -r -n -i -E '^[[:space:]]*(php_(admin_)?(value|flag)|RLimitMEM|LimitRequestBody)[[:space:]]' "$d" 2>/dev/null; done"""

DOCKER_WEB_RE = re.compile(r"nginx|httpd|apache|caddy|openresty|litespeed|lsws|frankenphp", re.I)
DOCKER_WEBROOT_CANDIDATES = ("/var/www", "/app", "/srv", "/usr/share/nginx/html", "/usr/local/apache2/htdocs")
# Mount destinations that hold configuration, logs or data, not code.
DOCKER_NON_CODE_MOUNTS = ("/etc", "/usr/local/etc", "/var/log", "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/redis",
                          "/data", "/proc", "/sys", "/dev", "/run", "/var/run", "/tmp")


def parse_proc_snapshot(text):
    """Process list in running_processes() format from CONTAINER_PROC_SH output."""
    procs, by_pid = [], {}
    for line in text.splitlines():
        parts = line.split("\x1f")
        if parts[0] == "P" and len(parts) >= 4:
            st = parts[1]
            try:
                pid = int(st.split(" ", 1)[0])
                comm = st[st.index("(") + 1:st.rindex(")")]
                ppid = int(st.rsplit(")", 1)[1].split()[1])
            except (ValueError, IndexError):
                continue
            exe, deleted = parts[2].strip() or None, False
            if exe and exe.endswith(" (deleted)"):
                exe, deleted = exe[:-10], True
            proc = {"pid": pid, "ppid": ppid, "comm": comm, "exe": exe, "deleted": deleted,
                    "cmdline": parts[3].strip(), "php_modules": [], "module_deleted": False, "user": None}
            procs.append(proc)
            by_pid[pid] = proc
        elif parts[0] == "M" and len(parts) >= 3:
            try:
                proc = by_pid[int(parts[1])]
            except (ValueError, KeyError):
                continue
            mp = parts[2].strip()
            if mp.endswith(" (deleted)"):
                proc["module_deleted"] = True
                mp = mp[:-10]
            if mp not in proc["php_modules"]:
                proc["php_modules"].append(mp)
    return procs


class Container(object):
    """A running container, with HostContext's interface implemented through
    docker exec (as root inside the container, like a root scan on a host)."""

    join = staticmethod(posixpath.join)

    def __init__(self, info):
        self.full_id = info.get("Id") or ""
        self.id = self.full_id[:12]
        self.name = (info.get("Name") or self.id).lstrip("/")
        cfg = info.get("Config") or {}
        self.image = cfg.get("Image") or info.get("Image") or "?"
        labels = cfg.get("Labels") or {}
        self.compose = None
        # compose build copies project/service labels into the image, so only
        # config-hash proves compose created this container
        if labels.get("com.docker.compose.project") and labels.get("com.docker.compose.config-hash"):
            self.compose = {"project": labels["com.docker.compose.project"],
                            "service": labels.get("com.docker.compose.service") or "",
                            "working_dir": labels.get("com.docker.compose.project.working_dir") or "",
                            "config_files": labels.get("com.docker.compose.project.config_files") or ""}
        self.mounts = [{"type": m.get("Type"), "source": m.get("Source") or "", "destination": m["Destination"],
                        "rw": m.get("RW", True)} for m in info.get("Mounts") or [] if m.get("Destination")]
        self._procs = None
        self._bins = None

    def run(self, cmd, timeout=20, stdin_data=None, binary=False):
        argv = ["docker", "exec", "-u", "0"] + (["-i"] if stdin_data is not None else []) + [self.full_id] + list(cmd)
        return run(argv, timeout=timeout, stdin_data=stdin_data, binary=binary)

    def sh(self, script, *args, **kw):
        return self.run(["sh", "-c", script, "sh"] + list(args), **kw)

    def which(self, name):
        rc, out, _ = self.sh('command -v "$1"', name)
        out = out.strip()
        return out if rc == 0 and out.startswith("/") else None

    def isfile(self, path):
        return self.sh('[ -f "$1" ]', path)[0] == 0

    def isdir(self, path):
        return self.sh('[ -d "$1" ]', path)[0] == 0

    def exists(self, path):
        return self.sh('[ -e "$1" ]', path)[0] == 0

    def glob(self, pattern):
        return self.existing([pattern], "e")

    def existing(self, patterns, kind="f"):
        rc, out, _ = self.sh(CONTAINER_LIST_SH, kind, *patterns, timeout=30)
        return sorted(set(l for l in out.splitlines() if l.startswith("/")))

    def stat_files(self, patterns):
        """[(path, mtime, size)] for regular files matching the globs."""
        rc, out, _ = self.sh(CONTAINER_STAT_SH, *patterns, timeout=30)
        res = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                res.append((parts[0], int(parts[1]), int(parts[2])))
        return res

    def read_text(self, path):
        rc, out, _ = self.run(["cat", path], timeout=30)
        return out if rc == 0 else None

    def read_bytes(self, path, limit):
        rc, out, _ = self.run(["head", "-c", str(limit), path], timeout=30, binary=True)
        return out if rc == 0 else None

    def write_text(self, path, text, mode=None):
        script = 'cat > "$1"' + (' && chmod %o "$1"' % mode if mode is not None else "")
        rc, out, err = self.sh(script, path, stdin_data=text.encode("utf-8"))
        if rc != 0:
            raise OSError((err or out).strip() or "write failed")

    def backup(self, path, bak):
        rc, out, err = self.sh('[ -e "$2" ] || cp -p "$1" "$2"', path, bak)
        if rc != 0:
            raise OSError((err or out).strip() or "backup failed")

    def remove(self, path):
        rc, out, err = self.run(["rm", "-f", path])
        if rc != 0:
            raise OSError((err or out).strip() or "remove failed")

    def markers(self, path):
        rc, out, _ = self.sh(CONTAINER_MARKERS_SH, path, *[m.decode() for m in PATCH_MARKERS], timeout=90)
        return set(l.strip() for l in out.splitlines() if l.strip())

    def bytes_version(self, path):
        rc, out, _ = self.sh(CONTAINER_BYTES_VERSION_SH, path, timeout=90)
        m = re.search(r"PHP/(\d+\.\d+\.\d+(?:[-~]?(?:RC|rc|alpha|beta|dev)\d*)?)", out)
        return m.group(1) if m else None

    def host_path(self, path):
        """The host file behind a bind mount, or None when path lives in the
        container (or the daemon's filesystem is not this machine's)."""
        best = None
        for m in self.mounts:
            d = m["destination"].rstrip("/")
            if m["type"] != "bind" or not m["source"] or not d:
                continue
            if path == d or path.startswith(d + "/"):
                if best is None or len(d) > len(best[0]):
                    best = (d, m["source"])
        if not best or not os.path.exists(best[1]):
            return None
        hp = best[1] if path == best[0] else os.path.join(best[1], *path[len(best[0]) + 1:].split("/"))
        src, real = os.path.realpath(best[1]), os.path.realpath(hp)
        if real != src and not real.startswith(src.rstrip(os.sep) + os.sep):
            return None  # a symlink inside the mount points elsewhere on the host
        return hp

    def where(self, path):
        hp = self.host_path(path)
        return "%s:%s%s" % (self.name, path, " (bind mount of %s)" % hp if hp else "")

    def processes(self, refresh=False):
        if self._procs is None or refresh:
            rc, out, _ = self.sh(CONTAINER_PROC_SH, timeout=30)
            self._procs = parse_proc_snapshot(out)
        return self._procs

    def php_binaries(self):
        """PHP executables and Apache PHP modules inside the container, as
        find_php_binaries() entries (real paths)."""
        if self._bins is not None:
            return self._bins
        cands = []
        rc, out, _ = self.sh(CONTAINER_PATH_SH, timeout=30)
        cands += [(l, "PATH") for l in out.splitlines() if BIN_NAME_RE.match(posixpath.basename(l))]
        for p in self.existing(BIN_GLOBS + MODULE_GLOBS, "f"):
            if p.endswith(".so"):
                cands.append((p, "module-glob"))
            elif BIN_NAME_RE.match(posixpath.basename(p)):
                cands.append((p, "path-glob"))
        for proc in self.processes():
            exe = proc["exe"]
            if exe and (BIN_NAME_RE.match(posixpath.basename(exe)) or re.search(r"(libphp|mod_php)", exe)):
                cands.append((exe, "process"))
            for mod in proc["php_modules"]:
                cands.append((mod, "process-maps"))
        found = {}
        if cands:
            rc, out, _ = self.sh(CONTAINER_REALPATH_SH, *sorted(set(p for p, _ in cands)), timeout=30)
            real = dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)
            for p, src in cands:
                if p in real:
                    found.setdefault(real[p], {"path": real[p], "sources": set()})["sources"].add(src)
        self._bins = sorted(found.values(), key=lambda e: e["path"])
        return self._bins


def docker_containers(names=None):
    """Running containers, optionally only those named (or id-prefixed).
    Returns (containers, error or None)."""
    if not which("docker"):
        return [], "docker CLI not found"
    rc, out, err = run(["docker", "ps", "-q", "--no-trunc"], timeout=30)
    if rc != 0:
        return [], "docker ps failed: %s" % ((err or out).strip().splitlines() or ["?"])[-1][:200]
    cts = []
    ids = out.split()
    if ids:
        rc, out, err = run(["docker", "inspect"] + ids, timeout=60)
        try:
            cts = [Container(d) for d in json.loads(out or "[]") if (d.get("State") or {}).get("Running")]
        except ValueError:
            return [], "docker inspect failed: %s" % ((err or out).strip().splitlines() or ["?"])[-1][:200]
    if not names:
        return cts, None
    sel, missing = [], []
    for n in names:
        hit = [ct for ct in cts if ct.name == n or ct.full_id.startswith(n)]
        if not hit:
            missing.append(n)
        sel.extend(h for h in hit if h not in sel)
    return sel, ("not running: %s" % ", ".join(missing)) if missing else None


def docker_php_targets(names=None):
    """[(container, php binaries)] for running containers that have PHP,
    plus the names of those without, and an error string."""
    cts, err = docker_containers(names)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, len(cts)))) as ex:
        bins = list(ex.map(lambda ct: ct.php_binaries(), cts))
    targets = [(ct, b) for ct, b in zip(cts, bins) if b]
    without = [ct.name for ct, b in zip(cts, bins) if not b]
    return targets, without, err


def scan_apache_configs_in(ct):
    rc, out, _ = ct.sh(CONTAINER_APACHE_GREP_SH, *(APACHE_CONF_DIRS + ["/usr/local/apache2/conf"]), timeout=30)
    findings, seen = [], set()
    for line in out.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3 or not parts[1].isdigit():
            continue
        f, n, text = parts
        if not (f.endswith(".conf") or posixpath.basename(f) == ".htaccess"):
            continue
        d = apache_directive(text)
        if not d:
            continue
        key = (f, d[0], d[1], d[2].lower())
        if key in seen:
            continue
        seen.add(key)
        findings.append({"file": f, "line": int(n), "kind": d[0], "key": d[1], "value": d[2]})
    return findings


def scan_container(ct, bins, no_config=False):
    procs = ct.processes()
    pkgs = check_packages(ct)
    installs = [assess_install(b, procs, pkgs, no_config=no_config, ctx=ct) for b in bins]
    if any(i["verdict"] == "VULNERABLE" for i in installs) or any(p["status"] == "vulnerable" for p in pkgs):
        verdict = "VULNERABLE"
    elif any(i["verdict"] == "UNKNOWN" for i in installs):
        verdict = "UNKNOWN"
    else:
        verdict = "PATCHED"
    first = next((i for i in installs if i["version"]), installs[0])
    bad = next((i for i in installs if i["verdict"] == "VULNERABLE"), None)
    return {"id": ct.id, "name": ct.name, "image": ct.image, "compose": ct.compose, "mounts": ct.mounts,
            "installs": installs, "packages": pkgs, "apache": scan_apache_configs_in(ct), "verdict": verdict,
            "version": first["version"], "fingerprint": any(i["fingerprint"] for i in installs),
            "note": bad["version_reason"] if bad else "", "binaries": [i["path"] for i in installs]}


def scan_docker(names=None, no_config=False):
    """Assess every running container that has PHP. Returns (results, error)."""
    targets, without, err = docker_php_targets(names)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, len(targets)))) as ex:
        results = list(ex.map(lambda t: scan_container(t[0], t[1], no_config), targets))
    if names and without:
        msg = "no PHP found in: %s" % ", ".join(without)
        err = "%s; %s" % (err, msg) if err else msg
    return results, err


def container_fix(d, inst):
    """How to replace an unpatched runtime in this container."""
    v = parse_version(inst.get("version") or "")
    flavour = {"fpm": "-fpm", "module": "-apache"}.get(inst["kind"], "-cli")
    if v and v[:2] in FIXED:
        target = "PHP %s+ (e.g. a freshly pulled php:%d.%d%s)" % (".".join(map(str, FIXED[v[:2]])), v[0], v[1], flavour)
    elif v and v[:2] < (8, 2):
        target = "PHP 8.2+ (e.g. php:8.3%s; %d.%d has no upstream fix) or a vendor-backported build" % (flavour, v[0], v[1])
    else:
        target = "a fixed PHP build"
    comp = d.get("compose")
    if comp and comp.get("service"):
        files = "".join(" -f %s" % f for f in comp["config_files"].split(",") if f)
        how = "docker compose%s build --pull %s && docker compose%s up -d %s" % (files, comp["service"], files, comp["service"])
        if re.match(re.escape(comp["project"]) + r"[-_]", d["image"]):
            how = "update FROM in the service's Dockerfile, then " + how
    else:
        how = "pull or rebuild %s and recreate the container" % d["image"]
    return "rebuild on %s: %s" % (target, how)


def container_findings(d):
    out = []
    for inst in d["installs"]:
        out.extend(install_findings(inst, d["name"], container_fix(d, inst)))
    out.extend(package_findings(d["packages"], d["name"]))
    out.extend(apache_findings(d["apache"], d["name"]))
    return out


def _container_workers(ct):
    procs = ct.processes(refresh=True)
    masters = [p for p in procs if re.match(r"php-?fpm", p["comm"]) and "master process" in p["cmdline"]]
    apache_pids = set(p["pid"] for p in procs if p["comm"] in ("apache2", "httpd"))
    apache_roots = [p for p in procs if p["pid"] in apache_pids and p["ppid"] not in apache_pids]
    roots = set(p["pid"] for p in masters + apache_roots)
    workers = set(p["pid"] for p in procs if p["ppid"] in roots)
    return masters, apache_roots, workers


def reload_container(ct, dry):
    """Have PHP-FPM / Apache inside the container re-read their configuration
    (graceful); restart the container when neither is found."""
    masters, apache_roots, before = _container_workers(ct)
    # kill through sh: slim images have no procps, only the shell builtin
    cmds = []
    if masters:
        cmds.append(["-USR2"] + [str(p["pid"]) for p in masters])
    if apache_roots:
        cmds.append(["-USR1"] + [str(p["pid"]) for p in apache_roots])
    if not cmds:
        if dry:
            print(c("  would run: docker restart %s (no PHP-FPM master or Apache found to reload: this is a full "
                    "container restart, not a graceful reload)" % ct.name, "yellow"))
            return
        print(c("  no PHP-FPM master or Apache found in %s: restarting the whole container" % ct.name, "yellow"))
        rc, out, err = run(["docker", "restart", ct.full_id], timeout=180)
        print("  %s docker restart %s" % (c("ok  ", "green") if rc == 0 else c("FAIL", "red"), ct.name))
        return
    for cmd in cmds:
        shown = "kill " + " ".join(cmd)
        if dry:
            print("  would run: docker exec %s %s" % (ct.name, shown))
            continue
        rc, out, err = ct.sh('kill "$@"', *cmd, timeout=30)
        print("  %s docker exec %s %s%s" % (c("ok  ", "green") if rc == 0 else c("FAIL", "red"), ct.name, shown,
                                           "" if rc == 0 else " (%s)" % (err or out).strip()[:120]))
    if dry:
        return
    time.sleep(2)
    _, _, after = _container_workers(ct)
    if before and not (before - after):
        print(c("  WARNING: no worker process was replaced (pids %s); restart the container by hand." %
                ",".join(map(str, sorted(before)[:8])), "yellow"))
    else:
        print("  workers replaced (%d before, %d after, %d survived)" % (len(before), len(after), len(before & after)))


def container_persistence_note(ct, paths):
    """Explain where container changes live and how to keep them."""
    layer = [p for p in paths if not ct.host_path(p)]
    for p in paths:
        hp = ct.host_path(p)
        if hp:
            print("  %s is a bind mount: the host file %s was changed and the change persists" % (p, hp))
    if not layer:
        return
    print(c("  %s in the container's writable layer: they survive `docker restart` but are" %
            ("The other changes are" if len(layer) < len(paths) else "These changes are"), "yellow"))
    print(c("  lost when the container is recreated (compose up --build / --force-recreate, image updates).", "yellow"))
    dropin = next((p for p in layer if p.endswith("/" + DROPIN_NAME)), None)
    if not dropin:
        return
    comp = ct.compose or {}
    dest = comp.get("working_dir") or "."
    print("  To keep the drop-in, copy it out and mount it read-only (or COPY it in the Dockerfile):")
    print("    docker cp %s:%s %s/%s" % (ct.name, dropin, dest, DROPIN_NAME))
    if comp.get("service"):
        print("    # docker-compose.yml, service %s:" % comp["service"])
    print("    volumes:")
    print("      - ./%s:%s:ro" % (DROPIN_NAME, dropin))


def stream_lines(cmd, merge_stderr=False, gz=False, max_lines=2000000):
    """Yield the decoded output lines of a command without buffering it all."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL)
    except OSError:
        return
    try:
        src = gzip.GzipFile(fileobj=p.stdout) if gz else p.stdout
        for raw in itertools.islice(src, max_lines):
            yield raw.decode("utf-8", "replace")
    except (OSError, EOFError):
        pass
    finally:
        if p.poll() is None:
            p.kill()
        p.stdout.close()
        p.wait()


def docker_tar_members(ct, path, want, max_bytes=2 * 1024 ** 3):
    """Stream `docker cp ct:path -` and yield (container path, mtime, size, fileobj)
    for regular files accepted by want(container path, size). Needs nothing
    inside the container. The fileobj must be read before the next item."""
    base = posixpath.dirname(path.rstrip("/")) or "/"
    try:
        p = subprocess.Popen(["docker", "cp", "%s:%s" % (ct.full_id, path), "-"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return
    total = 0
    try:
        with tarfile.open(fileobj=p.stdout, mode="r|") as tf:
            for m in tf:
                total += m.size
                if total > max_bytes:
                    break
                if not m.isreg():
                    continue
                cpath = posixpath.join(base, m.name)
                if want(cpath, m.size):
                    yield cpath, m.mtime, m.size, tf.extractfile(m)
    except (tarfile.TarError, OSError, EOFError):
        pass
    finally:
        if p.poll() is None:
            p.kill()
        p.stdout.close()
        p.wait()


LAYER_PERSISTENCE_RE = re.compile(r"^/(?:etc/cron|var/spool/cron|etc/systemd/system/|etc/rc\.local$|etc/ld\.so\.preload$|"
                                  r"root/\.ssh/|home/[^/]+/\.ssh/|var/www/\.ssh/|etc/passwd$|etc/shadow$|etc/sudoers|etc/profile\.d/)")


def classify_layer_changes(lines):
    """PHP files and persistence-related paths added or changed in a
    container's writable layer (`docker diff` output)."""
    php, persist = [], []
    for line in lines:
        m = re.match(r"^([AC])\s+(/.*)$", line.strip())
        if not m:
            continue
        path = m.group(2)
        low = posixpath.basename(path).lower()
        if low.endswith(WEB_EXTS) or ".php." in low:
            php.append(path)
        elif LAYER_PERSISTENCE_RE.match(path):
            persist.append(path)
    return php, persist


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


def discover_confd_dirs(ctx=None, bins=None):
    ctx = ctx or HOST
    dirs = set(ctx.existing(CONFD_GLOBS, "d"))
    # ask each binary where it scans
    for b in (find_php_binaries() if bins is None else bins):
        kind = binary_kind(b["path"])
        if kind == "module" or b.get("unreadable"):
            continue
        conf, info, note = effective_ini_from_binary(b["path"], kind, ctx)
        if info and info.get("scan_dir") and ctx.isdir(info["scan_dir"]):
            dirs.add(info["scan_dir"])
        elif info and info.get("ini_file"):
            # no scan dir: fall back to appending to php.ini is too invasive; report it
            dirs.add("!" + info["ini_file"])
    return sorted(dirs)


def discover_fpm_pools(ctx=None):
    return (ctx or HOST).existing(FPM_POOL_GLOBS, "f")


def discover_apache_dir(ctx=None):
    found = set((ctx or HOST).existing(list(APACHE_INCLUDE_DIRS), "d"))
    return next((d for d in APACHE_INCLUDE_DIRS if d in found), None)


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


def protect_target(args, ctx, bins, apply_):
    """Show (dry run) or write the mitigations for one target.
    Returns (paths planned, paths changed)."""
    confd = discover_confd_dirs(ctx, bins)
    pools = discover_fpm_pools(ctx)
    adir = discover_apache_dir(ctx)
    has_85 = any((parse_version(php_version_of(b["path"], binary_kind(b["path"]), ctx)[0] or "") or (0, 0))[:2] == (8, 5)
                 for b in bins if not b.get("unreadable"))
    has_module = any(binary_kind(b["path"]) == "module" for b in bins)
    planned, changes = [], []

    def write(path, text, mode=None, backup=False):
        planned.append(path)
        if not apply_:
            return True
        try:
            if backup:
                ctx.backup(path, path + ".php2shell-guard.bak")
            ctx.write_text(path, text, mode)
        except (OSError, IOError) as e:
            print("    %s %s" % (c("FAIL", "red"), e))
            return False
        changes.append(path)
        return True

    text = dropin_text(args)
    print("php.ini drop-in (%s):" % DROPIN_NAME)
    print("".join("    " + l + "\n" for l in text.splitlines()))
    for d in confd:
        if d.startswith("!"):
            print("  %s %s has no scan dir; add the directives to it by hand" % (sev("MEDIUM"), ctx.where(d[1:])))
            continue
        target = ctx.join(d, DROPIN_NAME)
        print("  %s %s" % ("update " if ctx.exists(target) else "write  ", ctx.where(target)))
        write(target, text, mode=0o644)
    if not confd:
        print("  no conf.d directories found")

    print("\nFPM pools (php_admin_* lines inserted under each [pool] header):")
    for p in pools:
        content = ctx.read_text(p)
        if content is None:
            print("  skip %s (unreadable)" % ctx.where(p))
            continue
        # one PHP per container; on a host only versioned pool paths can be told apart
        is85 = has_85 and ("8.5" in p or ctx is not HOST)
        block = fpm_block_lines(args, is85)
        new = insert_fpm_block(content, block)
        if new == content:
            print("  unchanged %s" % ctx.where(p))
            continue
        print("  %s %s" % ("patch  " if not args.no_fpm_pools else "skip   ", ctx.where(p)))
        if not args.no_fpm_pools:
            write(p, new, backup=True)
    if not pools:
        print("  no pool files found")

    print("\nApache (mod_php) config:")
    if not adir or args.no_apache:
        print("  no Apache config dir found (or --no-apache)")
    elif ctx is not HOST and not has_module:
        print("  skipped: no mod_php in this container")
    else:
        target = ctx.join(adir, APACHE_CONF_NAME)
        print("  write   %s" % ctx.where(target))
        print("".join("    " + l + "\n" for l in apache_conf_text(args, has_85).splitlines()))
        if write(target, apache_conf_text(args, has_85)) and apply_:
            if adir == "/etc/apache2/conf-available" and ctx.which("a2enconf"):
                ctx.run(["a2enconf", APACHE_CONF_NAME[:-5]], timeout=30)
            for tester in (("apachectl", "-t"), ("apache2ctl", "-t"), ("httpd", "-t")):
                if ctx.which(tester[0]):
                    rc, out, err = ctx.run(list(tester), timeout=30)
                    ok = rc == 0
                    print("  %s %s -t: %s" % (c("ok  ", "green") if ok else c("FAIL", "red"), tester[0], (err or out).strip().splitlines()[-1] if (err or out).strip() else ""))
                    if not ok:
                        print(c("  Apache config test failed: removing %s" % target, "red"))
                        ctx.remove(target)
                        changes.remove(target)
                        if ctx.which("a2disconf"):
                            ctx.run(["a2disconf", APACHE_CONF_NAME[:-5]], timeout=30)
                    break
    return planned, changes


def cmd_protect(args):
    apply_ = args.apply
    docker = args.docker or bool(args.container)
    if args.rollback:
        return protect_rollback(args)
    if not args.post_max and args.upload_max:
        print("--upload-max requires --post-max")
        return 3
    if args.post_max and not args.upload_max:
        pm = ini_bytes(args.post_max) or 0
        args.upload_max = "%dM" % max(1, (pm // (1024 ** 2)) - 2) if pm >= 3 * 1024 ** 2 else args.post_max
    if apply_ and not docker and not is_root() and os.name != "nt":
        print(c("protect --apply needs root to write configuration and restart services", "red"))
        return 3
    banner("%s protect%s (%s)" % (TOOL, " --docker" if docker else "", "APPLY" if apply_ else "DRY RUN - add --apply to write"))
    print("  Interim mitigations from the php.net advisory. They reduce exposure; only updating PHP is complete.\n")

    if docker:
        return protect_docker(args, apply_)

    planned, changes = protect_target(args, HOST, find_php_binaries(), apply_)

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


def protect_docker(args, apply_):
    targets, without, err = docker_php_targets(args.container)
    if err:
        print(c("  %s" % err, "yellow"))
    if without and not args.container:
        print("  no PHP in: %s" % ", ".join(without))
    if not targets:
        print("  no running container with PHP found")
        return 3 if err else 0
    changes = []
    for ct, bins in targets:
        print()
        banner("container %s (%s)" % (ct.name, ct.image))
        planned, ch = protect_target(args, ct, bins, apply_)
        changes += ch
        print("\nWorkers:")
        if args.restart:
            reload_container(ct, dry=not apply_)
        else:
            print("  (add --restart to reload PHP-FPM / Apache inside the container)")
        if apply_ and ch:
            print("\nPersistence:")
            container_persistence_note(ct, ch)
    print()
    if apply_:
        print(c("Applied %d change(s) in %d container(s)." % (len(changes), len(targets)), "green"))
        print("Verify with: %s scan --docker" % sys.argv[0])
        if not args.restart:
            print(c("Workers still run the old configuration until reloaded (--restart).", "yellow"))
    else:
        print("Dry run complete. Re-run with --apply to write these changes (docker access is enough, no root).")
        print("Changes made inside a container last until it is recreated; --apply explains how to keep them.")
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


def rollback_target(ctx, bins, apply_):
    """Remove (or list) everything protect wrote on one target; returns the count."""
    n = 0

    def act(fn, *a):
        if not apply_:
            return
        try:
            fn(*a)
        except (OSError, IOError) as e:
            print("    %s %s" % (c("FAIL", "red"), e))

    for d in discover_confd_dirs(ctx, bins):
        if d.startswith("!"):
            continue
        t = ctx.join(d, DROPIN_NAME)
        if ctx.exists(t):
            print("  remove %s" % ctx.where(t))
            n += 1
            act(ctx.remove, t)
    for p in discover_fpm_pools(ctx):
        content = ctx.read_text(p)
        if content is None or MARK_BEGIN not in content:
            continue
        # insert_fpm_block with empty block re-adds nothing but strips the old block
        print("  strip  %s" % ctx.where(p))
        n += 1
        act(ctx.write_text, p, insert_fpm_block(content, []))
    adir = discover_apache_dir(ctx)
    if adir:
        t = ctx.join(adir, APACHE_CONF_NAME)
        if ctx.exists(t):
            print("  remove %s" % ctx.where(t))
            n += 1
            if apply_ and ctx.which("a2disconf"):
                ctx.run(["a2disconf", APACHE_CONF_NAME[:-5]], timeout=30)
            act(ctx.remove, t)
    return n


def protect_rollback(args):
    apply_ = args.apply
    docker = args.docker or bool(args.container)
    banner("%s protect --rollback%s (%s)" % (TOOL, " --docker" if docker else "", "APPLY" if apply_ else "DRY RUN"))
    if apply_ and not docker and not is_root() and os.name != "nt":
        print(c("needs root", "red"))
        return 3
    if docker:
        targets, without, err = docker_php_targets(args.container)
        if err:
            print(c("  %s" % err, "yellow"))
        n = 0
        for ct, bins in targets:
            print(c("container %s (%s)" % (ct.name, ct.image), "bold"))
            k = rollback_target(ct, bins, apply_)
            n += k
            if not k:
                print("  nothing to remove")
            if args.restart:
                reload_container(ct, dry=not apply_)
            elif apply_ and k:
                print(c("  reload with --restart so workers drop the mitigation config", "yellow"))
        print("\n%d item(s) %s." % (n, "removed" if apply_ else "would be removed"))
        return 0
    n = rollback_target(HOST, find_php_binaries(), apply_)
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
    # known kits by their own identifiers; bare "c99"/"wso" also hit hashes and names like shouldShowSocial
    re.compile(rb"(?:\bc99(?:shell|sh_|_buff)|\br57(?:shell|_)|\bWSO(?:setcookie|_version|\s?\d\.\d)|\bb374k\b|\bFilesMan\b|\bphpspy\b|uname -a;)", re.I),
]
SESSION_INJECT_RE = re.compile(rb"<\?php|<\?=|<script language=\"php\"|\|O:\d+:\"|upload_progress_[^|]*<\?")


WEB_EXTS = (".php", ".phtml", ".php5", ".php7", ".php8", ".phar", ".inc", ".phps")


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def match_log_lines(lines, source, hits):
    """Count LOG_PATTERNS hits from an iterable of text lines into hits."""
    n = 0
    for line in lines:
        n += 1
        for sev_, name, rx in LOG_PATTERNS:
            if rx.search(line):
                h = hits.setdefault(name, {"severity": sev_, "count": 0, "files": set(), "samples": []})
                h["count"] += 1
                h["files"].add(source)
                if len(h["samples"]) < 5:
                    h["samples"].append(line.strip()[:300])
                break
    return n


def finish_log_hits(hits):
    for h in hits.values():
        h["files"] = sorted(h["files"])
    return hits


def hunt_logs(paths, since, max_lines=2000000, hits=None):
    hits, files = ({} if hits is None else hits), []
    for p in paths:
        try:
            if os.path.getmtime(p) < since.timestamp() or os.path.getsize(p) == 0:
                continue
        except OSError:
            continue
        files.append(p)
        try:
            with open_log(p) as fh:
                match_log_lines((raw.decode("utf-8", "replace") for raw in itertools.islice(fh, max_lines + 1)), p, hits)
        except OSError:
            continue
    return finish_log_hits(hits), files


def session_dirs_from_scan(ctx=None, bins=None):
    ctx = ctx or HOST
    dirs = set()
    for b in (find_php_binaries() if bins is None else bins):
        kind = binary_kind(b["path"])
        if kind == "module" or b.get("unreadable"):
            continue
        conf, info, _ = effective_ini_from_binary(b["path"], kind, ctx)
        if conf and conf.get("session.save_path"):
            sp = conf["session.save_path"][0]
            m = re.search(r"(?:\d+;)?(?:\d+;)?(/\S+)$", sp)
            if m and ctx.isdir(m.group(1)):
                dirs.add(m.group(1))
    dirs.update(ctx.existing(SESSION_DIR_CANDIDATES, "d"))
    return sorted(dirs)


def session_hit(label, data, mtime):
    m = SESSION_INJECT_RE.search(data)
    if not m:
        return None
    return {"file": label, "size": len(data), "mtime": datetime.datetime.fromtimestamp(mtime).isoformat(),
            "match": m.group(0).decode("latin-1")[:40]}


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
                mtime = os.path.getmtime(p)
            except OSError:
                continue
            scanned += 1
            h = session_hit(p, data, mtime)
            if h:
                hits.append(h)
            if scanned >= max_files:
                return hits, scanned
    return hits, scanned


def hunt_sessions_in_container(ct, d, max_files=50000):
    hits, scanned = [], 0
    top = d.rstrip("/")

    def want(cpath, size):
        return posixpath.dirname(cpath) == top and posixpath.basename(cpath).startswith("sess_") and size <= 5 * 1024 * 1024

    with contextlib.closing(docker_tar_members(ct, d, want)) as members:
        for cpath, mtime, size, fh in members:
            scanned += 1
            h = session_hit("%s:%s" % (ct.name, cpath), fh.read(), mtime)
            if h:
                hits.append(h)
            if scanned >= max_files:
                break
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
    return collapse_roots(roots)


def collapse_roots(roots):
    out = []
    for r in sorted(roots):
        if not any(r.startswith(o.rstrip("/") + "/") for o in out):
            out.append(r)
    return out


def check_web_file(label, name, mtime, size, read, since, recent, suspicious):
    """Recent-PHP and webshell checks for one file; read() returns its bytes."""
    lower = name.lower()
    is_php = lower.endswith(WEB_EXTS) or ".php." in lower
    if is_php and mtime >= since.timestamp():
        recent.append({"file": label, "mtime": datetime.datetime.fromtimestamp(mtime).isoformat(), "size": size})
    if (is_php or lower.endswith((".ico", ".txt", ".jpg", ".png"))) and size < 2 * 1024 * 1024:
        try:
            data = read()
        except OSError:
            return
        if not is_php and b"<?php" not in data:
            return
        for rx in WEBSHELL_PATTERNS:
            m = rx.search(data)
            if m:
                suspicious.append({"file": label, "pattern": m.group(0).decode("latin-1")[:60],
                                   "sha256": hashlib.sha256(data).hexdigest(),
                                   "mtime": datetime.datetime.fromtimestamp(mtime).isoformat()})
                break


WEBROOT_SKIP_DIRS = ("node_modules", ".git", "vendor")


def _read_file(p):
    with open(p, "rb") as fh:
        return fh.read()


def hunt_webroots(roots, since, max_files=300000):
    recent, suspicious, n = [], [], 0
    for root in roots:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in WEBROOT_SKIP_DIRS]
            for f in fns:
                n += 1
                if n > max_files:
                    return recent, suspicious, n
                p = os.path.join(dp, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                check_web_file(p, f, st.st_mtime, st.st_size, lambda p=p: _read_file(p), since, recent, suspicious)
    return recent, suspicious, n


def hunt_webroot_in_container(ct, root, since, max_files=300000):
    recent, suspicious = [], []
    count = [0]

    def want(cpath, size):
        if any(part in WEBROOT_SKIP_DIRS for part in cpath.split("/")):
            return False
        count[0] += 1
        return True

    with contextlib.closing(docker_tar_members(ct, root, want)) as members:
        for cpath, mtime, size, fh in members:
            check_web_file("%s:%s" % (ct.name, cpath), posixpath.basename(cpath), mtime, size, fh.read, since, recent, suspicious)
            if count[0] > max_files:
                break
    return recent, suspicious, count[0]


def container_webroots(ct, explicit=None):
    """(host dirs behind bind mounts, dirs to stream out of the container)."""
    on_host, inside = [], []
    if explicit:
        for d in explicit:
            hp = ct.host_path(d)
            (on_host if hp and os.path.isdir(hp) else inside).append(hp if hp and os.path.isdir(hp) else d)
        return on_host, inside
    for m in ct.mounts:
        d = m["destination"].rstrip("/")
        if not d or any(d == x or d.startswith(x + "/") for x in DOCKER_NON_CODE_MOUNTS):
            continue
        hp = ct.host_path(d)
        if hp and os.path.isdir(hp):
            on_host.append(hp)
        elif m["type"] == "volume" and ct.isdir(d):
            inside.append(d)
    mount_dests = [m["destination"].rstrip("/") for m in ct.mounts]
    for cand in DOCKER_WEBROOT_CANDIDATES:
        if any(cand == d or cand.startswith(d + "/") for d in mount_dests):
            continue  # covered by a mount
        if any(d.startswith(cand + "/") for d in mount_dests):
            continue  # docker cp would pull the mount in as well; the mount is scanned on its own
        if ct.isdir(cand):
            inside.append(cand)
    return on_host, collapse_roots(inside)


def is_web_worker(comm):
    return comm in WEB_WORKER_NAMES or comm == "php" or bool(BIN_NAME_RE.match(comm)) or \
        comm.startswith(("php-fpm", "lsphp", "apache", "httpd"))


def find_shell_children(procs):
    """Shells / interpreters whose parent is a PHP or web server worker."""
    by_pid = {p["pid"]: p for p in procs}
    out = []
    for p in procs:
        parent = by_pid.get(p["ppid"])
        if parent and os.path.basename(p["comm"]) in SHELL_NAMES and is_web_worker(parent["comm"]):
            out.append({"pid": p["pid"], "comm": p["comm"], "cmdline": (p.get("cmdline") or "")[:200],
                        "parent": "%s[%d]" % (parent["comm"], parent["pid"])})
    return out


def hunt_processes():
    procs = []
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
            procs.append({"pid": int(pid), "ppid": ppid, "comm": comm, "cmdline": cmd})
    else:
        rc, out, _ = run(["ps", "-axo", "pid=,ppid=,comm="], timeout=15)
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                procs.append({"pid": int(parts[0]), "ppid": int(parts[1]), "comm": os.path.basename(parts[2]), "cmdline": ""})
            except ValueError:
                continue
    return find_shell_children(procs)


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


def hunt_findings(r, days, since, prefix=""):
    """Findings for one hunt report (the host or one container)."""
    pre = prefix + ": " if prefix else ""
    f = []
    for name, h in r["logs"].items():
        f.append({"severity": h["severity"], "title": "%s%s: %d log line(s) in %d source(s)" % (pre, name, h["count"], len(h["files"])),
                  "detail": "; ".join(h["samples"][:2])})
    for s in r["session_hits"]:
        f.append({"severity": "CRITICAL", "title": "session file contains PHP/serialized-object marker: %s" % s["file"], "detail": "match %r, mtime %s" % (s["match"], s["mtime"])})
    for s in r["suspicious_files"]:
        f.append({"severity": "CRITICAL", "title": "webshell-like code in %s" % s["file"], "detail": "pattern %r sha256 %s" % (s["pattern"], s["sha256"][:16])})
    if r["recent_php_files"]:
        f.append({"severity": "MEDIUM", "title": "%s%d PHP file(s) modified in the last %d day(s) under %s" % (pre, len(r["recent_php_files"]), days, ", ".join(r["webroots"])),
                  "detail": "; ".join(x["file"] for x in r["recent_php_files"][:5])})
    for s in r["shell_children"]:
        f.append({"severity": "CRITICAL", "title": "%sweb worker %s spawned %s (pid %d)" % (pre, s["parent"], s["comm"], s["pid"]), "detail": s["cmdline"]})
    if r.get("persistence"):
        f.append({"severity": "LOW", "title": "%d persistence-related file(s) changed since %s" % (len(r["persistence"]), since.date()),
                  "detail": "; ".join(x["file"] for x in r["persistence"][:6])})
    if r.get("layer_php"):
        f.append({"severity": "MEDIUM", "title": "%s%d PHP file(s) written into the container layer (not in the image, not on a mount)" % (pre, len(r["layer_php"])),
                  "detail": "; ".join(r["layer_php"][:6]) + " (framework caches such as compiled views also land here)"})
    if r.get("layer_persistence"):
        f.append({"severity": "MEDIUM", "title": "%spersistence-related path(s) changed in the container layer" % pre,
                  "detail": "; ".join(r["layer_persistence"][:6])})
    return f


def hunt_host(args, since):
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
    report["findings"] = hunt_findings(report, args.days, since)
    report["summary"] = ["logs scanned: %d   session dirs: %s   webroots: %s   sessions scanned: %d" % (
        len(files), ", ".join(sdirs) or "-", ", ".join(roots) or "-", report["sessions_scanned"])]
    return report


def hunt_container(ct, bins, since, args, seen):
    """Hunt one container. seen holds host paths already scanned through
    another container's bind mount (several services often share one)."""
    r = {"name": ct.name, "id": ct.id, "image": ct.image, "logs": {}, "log_sources": [], "session_dirs": [],
         "session_hits": [], "sessions_scanned": 0, "webroots": [], "recent_php_files": [], "suspicious_files": [],
         "files_scanned": 0, "shell_children": [], "layer_php": [], "layer_persistence": []}

    def first_time(host_path):
        key = os.path.realpath(host_path)
        if key in seen:
            return False
        seen.add(key)
        return True

    hits = {}
    n = match_log_lines(stream_lines(["docker", "logs", "--since", "%dh" % (args.days * 24), ct.full_id], merge_stderr=True),
                        "%s (docker logs)" % ct.name, hits)
    r["log_sources"].append("docker logs (%d lines)" % n)
    for path, mtime, size in ct.stat_files(args.logs or ERROR_LOG_GLOBS):
        if mtime < since.timestamp() or size == 0:
            continue
        hp = ct.host_path(path)
        if hp and os.path.isfile(hp):
            if first_time(hp):
                hunt_logs([hp], since, hits=hits)
                r["log_sources"].append(hp)
        else:
            label = "%s:%s" % (ct.name, path)
            match_log_lines(stream_lines(["docker", "exec", ct.full_id, "cat", path], gz=path.endswith(".gz")), label, hits)
            r["log_sources"].append(label)
    r["logs"] = finish_log_hits(hits)

    if bins:
        r["session_dirs"] = args.session_dir or session_dirs_from_scan(ct, bins)
        for d in r["session_dirs"]:
            hp = ct.host_path(d)
            if hp and os.path.isdir(hp):
                if not first_time(hp):
                    continue
                h, k = hunt_sessions([hp])
            else:
                h, k = hunt_sessions_in_container(ct, d)
            r["session_hits"] += h
            r["sessions_scanned"] += k

    if not args.no_webroot:
        on_host, inside = container_webroots(ct, args.webroot)
        for root in on_host:
            if not first_time(root):
                continue
            rec, sus, k = hunt_webroots([root], since)
            r["webroots"].append(root)
            r["recent_php_files"] += rec
            r["suspicious_files"] += sus
            r["files_scanned"] += k
        for root in inside:
            rec, sus, k = hunt_webroot_in_container(ct, root, since)
            r["webroots"].append("%s:%s" % (ct.name, root))
            r["recent_php_files"] += rec
            r["suspicious_files"] += sus
            r["files_scanned"] += k

    r["shell_children"] = find_shell_children(ct.processes())
    rc, out, _ = run(["docker", "diff", ct.full_id], timeout=120)
    if rc == 0:
        r["layer_php"], r["layer_persistence"] = classify_layer_changes(out.splitlines())
    return r


def hunt_docker(args, since):
    report = {"tool": TOOL, "version": __version__, "host": socket.gethostname(), "since": since.isoformat(),
              "containers": [], "skipped": [], "docker_error": None, "findings": [], "summary": []}
    cts, err = docker_containers(args.container)
    report["docker_error"] = err
    seen = set()
    for ct in cts:
        bins = ct.php_binaries()
        web = bins or DOCKER_WEB_RE.search(ct.name + " " + ct.image) or any(is_web_worker(p["comm"]) for p in ct.processes())
        if not web and not args.container:
            report["skipped"].append(ct.name)
            continue
        r = hunt_container(ct, bins, since, args, seen)
        report["containers"].append(r)
        report["findings"] += hunt_findings(r, args.days, since, prefix=ct.name)
        report["summary"].append("%-16s logs: %s | sessions: %d in %s | webroots: %s (%d files)" % (
            ct.name, ", ".join(r["log_sources"]) or "-", r["sessions_scanned"], ", ".join(r["session_dirs"]) or "-",
            ", ".join(r["webroots"]) or "-", r["files_scanned"]))
    if err:
        report["summary"].insert(0, c(err, "yellow"))
    if report["skipped"]:
        report["summary"].append("not a PHP or web container, skipped: %s" % ", ".join(report["skipped"]))
    if not report["containers"]:
        report["summary"].append("no running PHP or web server container found")
    return report


def cmd_hunt(args):
    since = datetime.datetime.now() - datetime.timedelta(days=args.days)
    docker = args.docker or bool(args.container)
    report = hunt_docker(args, since) if docker else hunt_host(args, since)
    f = report["findings"]
    f.sort(key=lambda x: SEV_RANK.get(x["severity"], 9))

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        banner("%s hunt - %s%s (window: since %s)" % (TOOL, report["host"], " docker containers" if docker else "", since.strftime("%Y-%m-%d")))
        for line in report["summary"]:
            print("  " + line)
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
    s.add_argument("--docker", action="store_true",
                   help="also inspect PHP inside every running Docker container (version, patch markers, ini, FPM pools, packages)")
    s.add_argument("--container", action="append", metavar="NAME",
                   help="only this container (name or id prefix; repeatable; implies --docker)")
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
    s.add_argument("--docker", action="store_true",
                   help="work inside running Docker containers (docker exec) instead of on this host; no root needed")
    s.add_argument("--container", action="append", metavar="NAME",
                   help="only this container (name or id prefix; repeatable; implies --docker)")

    s = sub.add_parser("hunt", help="look for exploitation traces on this host")
    s.add_argument("--days", type=int, default=14, help="look-back window for logs/files (default 14; exploitation began 2026-10-17)")
    s.add_argument("--logs", nargs="*", help="error log files to scan (default: common locations)")
    s.add_argument("--session-dir", nargs="*", help="session save paths to scan (default: from PHP config + common paths)")
    s.add_argument("--webroot", nargs="*", help="document roots to scan (default: from web server config + common paths)")
    s.add_argument("--no-webroot", action="store_true", help="skip webroot file scan")
    s.add_argument("--docker", action="store_true",
                   help="hunt inside running PHP / web server containers instead of on this host "
                        "(docker logs, sessions, webroots, processes, container-layer changes); "
                        "--logs/--session-dir/--webroot then name paths inside the containers")
    s.add_argument("--container", action="append", metavar="NAME",
                   help="only this container (name or id prefix; repeatable; implies --docker)")
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
