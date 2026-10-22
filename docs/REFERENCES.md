# References

Sources consulted while building php2shell-guard (October 2026). Facts in the tool
(fixed versions, mitigation directives, patch markers, distro package versions) trace
back to these.

## Primary

- php.net security advisory, 2026-10-21: https://www.php.net/archive/2026.php#2026-10-21-5
- GHSA-w8hw-w9fx-j79w (CVE-2026-109618, RCE via OOM corruption): https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619, RCE via stale global state): https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- php-src fixed tags: php-8.2.35, php-8.3.36, php-8.4.27, php-8.5.12. The diff of
  `main/main.c` and `Zend/zend_alloc.h` between php-8.4.26 and php-8.4.27 introduces the
  `memory_hard_limit_percent` INI entry used as a patch marker.
- php-src minimal backport branches: `PHP-7.4-CVE-2026-109618-109619`,
  `PHP-8.0-CVE-2026-109618-109619`, `PHP-8.1-CVE-2026-109618-109619` (commit "Avoid state
  corruption via bailout"). They add the exported `zend_mm_safe_error_ex` symbol used as
  the second patch marker, and disable the session upload-progress callback.
- PHP ChangeLog 8: https://www.php.net/ChangeLog-8.php

## Vendor status

- Debian security tracker: https://security-tracker.debian.org/tracker/CVE-2026-109618
  (DSA-6574-1 trixie `8.4.27-1~deb13u1`, DLA-4848-1 bookworm `8.2.35-1~deb12u1`)
- Ubuntu: https://ubuntu.com/blog/php2shell-vulnerability-fixes-available (USN-8948-1/-2)
- AlmaLinux: https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/
- Per-platform roundup: https://ma.ttias.be/php-cve-2026-109618-patch/
- NCSC-NL operational repo (software inventory, cPanel mitigation script): https://github.com/NCSC-NL/php2shell

## Technical analyses and detection

- Datadog Security Labs: https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
- watchTowr: https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/ and the FAQ
- Tenable FAQ: https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote
- Qualys: https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities
- Imperva: https://www.imperva.com/blog/php2shell-vulnerability-updates/
- Elastic Security Labs detection coverage: https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection
- Cloudflare WAF protections: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/
- JFrog: https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
- Arctic Wolf, Armis, Aikido, Malwarebytes, SecurityWeek, BleepingComputer, The Hacker News coverage (see links in the php.net advisory thread and Wikipedia's PHP2Shell article)

## Other community tools reviewed

Reviewed for approach and gaps; no code was copied.

- CyberRoute/php2shell-scanner (remote validator with LFI canary)
- 0xrsydn/php2shell-scan (reachability/baseline/verdict probes)
- murrez/php2shell, JoasASantos/php2shell-scanner (banner scanners)
- ikow/php2shell-poc (detection rules: Suricata, Sigma, ModSecurity)
- ersinkoc/php-fix (one-line upload_progress disable)
- mikensec/php2shell-lab (offline analysis harness)
