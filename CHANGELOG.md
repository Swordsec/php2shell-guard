# Changelog

## Unreleased

- Docker containers are first-class targets. `scan --docker` runs the full host
  assessment inside every running container through `docker exec` (binaries, patch
  markers, running/stale workers, effective ini, FPM pools, packages, Apache
  directives) with Compose-aware rebuild hints; `--container NAME` narrows it.
- `protect --docker` writes the drop-in, FPM pool blocks and Apache conf inside
  containers, reloads FPM/Apache gracefully with `--restart` (verified by worker PIDs),
  supports `--rollback`, and explains how to persist the change past a recreate.
- `hunt --docker`: `docker logs`, in-container or bind-mounted error logs, session
  files and webroots (streamed with `docker cp`, or walked on the host for bind mounts),
  shells spawned by web workers, and `docker diff` checks for PHP and persistence files
  in the writable layer.
- `hunt`: the shell-family webshell signature no longer matches bare `c99`/`wso`
  substrings (hashes in compiled Blade views, identifiers such as `shouldShowSocialIds`).
- `hunt`: shells spawned by Debian-named workers (`php-fpm8.3`) are now recognised.
- `scan` without `--docker` points at it when the host has no PHP but Docker is installed.

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
