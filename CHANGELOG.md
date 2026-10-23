# Changelog

## 1.0.1 - 2026-10-23

- `scan` finds PHP workers running inside containers from the host: their binaries are
  read through `/proc/<pid>/root` (device+inode deduplicated, never executed) and
  fingerprinted like local ones, without any container CLI. Reported as
  `[container via /proc/<pid>]`.
- When the host has no PHP of its own and `docker` is available, running containers are
  inspected automatically; `NO_PHP` now prints hints (web server without a local runtime,
  Podman/kubectl/ctr present, snaps bundling PHP, docker daemon unreachable).
- Reported after a mailcow host (PHP only in `ghcr.io/mailcow/phpfpm`) came back `NO_PHP`.

## 1.0.0 - 2026-10-22

Initial release, one day after the php.net fixed releases.

- `scan`: binary discovery across ~60 layouts, running-worker and Apache module
  detection via `/proc`, stale-binary detection, patch markers
  (`memory_hard_limit_percent`, `zend_mm_safe_error_ex`), dpkg/rpm/apk/pacman/brew
  package checks with changelog CVE grep, per-SAPI effective INI, FPM pool dumps,
  Apache directive audit, Docker container inspection, JSON output.
- `protect`: php.net interim mitigations as conf.d drop-ins, FPM pool `php_admin_*`
  blocks, Apache `php_admin_*` conf with syntax test; dry run, apply, rollback, restart.
- `hunt`: error-log signatures, session-file injection, webroot/webshell heuristics,
  web-worker child processes, persistence changes.
- `remote`: passive banner check with CDN/WAF fingerprinting and an inert WAF coverage probe.
- `rules`: ModSecurity, nginx, Apache, HAProxy, Suricata, Caddy snippets.
- `quickcheck.sh`: POSIX sh variant for hosts without Python.
