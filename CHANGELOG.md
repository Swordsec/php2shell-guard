# Changelog

## 1.1.1 - 2026-10-23

Fixes from the first production run on a host whose PHP lives only in containers.

- `protect` (host mode) on a machine with no PHP of its own now writes nothing, names
  the containers that do run PHP, points at `protect --docker`, and exits 2. It used to
  write an Apache `php_admin_*` conf on the host, which does nothing when that Apache
  has no mod_php, and report success.
- `protect` never writes the Apache conf where no mod_php is found, on a host as in a
  container (reverse-proxy Apache ignores `php_admin_*`).
- `protect` and `hunt` in host mode no longer run container binaries reached through
  `/proc/<pid>/root` (for `-v` / `-i` probes). Those binaries are only ever read, as the
  1.0.1 notes promised; `php_version_of` and `effective_ini_from_binary` refuse such
  paths outright.
- One CRITICAL per unpatched runtime instead of one per binary and reason: the CLI,
  FPM and Apache module of the same build are reported together with the single fix,
  and the separate "EOL branch without a confirmed vendor backport" CRITICAL is folded
  into it. Three PHP 8.0.1 containers now give 3 findings, not 12.
- Inside containers that serve through FPM or mod_php, the CLI's (identical) ini
  findings are no longer repeated.
- `scan` marks an unpatched runtime whose effective configuration carries the interim
  mitigations: `interim mitigations active: upload_progress off, memory_limit -1`
  (with `--docker` or on the host; the automatic cheap container pass reads no ini).

## 1.1.0 - 2026-10-23

Docker containers are first-class targets (contributed by @falconsw in #1, merged on
top of 1.0.1's `/proc` detection).

- `scan --docker` runs the full host assessment inside every running container through
  `docker exec` (binaries, patch markers, running/stale workers, effective ini, FPM
  pools, packages, Apache directives) with Compose-aware rebuild hints; `--container
  NAME` narrows it. Containers already seen through `/proc` are reported once, in the
  Docker section, with a cross-reference instead of a duplicate host entry.
- When the host has no PHP of its own and `docker` is available, running containers are
  still inspected automatically, in the cheap `--no-config` mode; `--docker` does the
  deep pass.
- `protect --docker` writes the drop-in, FPM pool blocks and Apache conf inside
  containers, reloads FPM/Apache gracefully with `--restart` (verified by worker PIDs,
  with a loud warning when it has to fall back to `docker restart`), supports
  `--rollback`, and explains how to persist the change past a recreate.
- `hunt --docker`: `docker logs`, in-container or bind-mounted error logs, session
  files and webroots (streamed with `docker cp`, or walked on the host for bind mounts),
  shells spawned by web workers, and `docker diff` checks for PHP and persistence files
  in the writable layer.
- `hunt`: the shell-family webshell signature no longer matches bare `c99`/`wso`
  substrings (hashes in compiled Blade views, identifiers such as `shouldShowSocialIds`).
- `hunt`: shells spawned by Debian-named workers (`php-fpm8.3`) are now recognised.
- `quickcheck.sh`: busybox `tr -c` does not understand `[:print:]`; an octal range is
  used for the marker fallback.

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
