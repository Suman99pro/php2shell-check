# php2shell-check

A single-file, read-only Bash script that checks whether a Linux server is exposed to **PHP2Shell** and the related session issue disclosed in October 2026.

| CVE | What it is | Status |
|---|---|---|
| CVE-2026-109618 | Remote code execution via out-of-memory corruption (CVSS v4.0 9.2) | Fixed 2026-10-21; exploitation in the wild reported |
| CVE-2026-109619 | Remote code execution via stale request state (CVSS v4.0 9.2) | Fixed 2026-10-21; exploitation in the wild reported |
| CVE-2026-115560 | Code execution via session upload progress plus a runtime `session.serialize_handler` switch | No upstream patch yet; interim mitigation below |

Fixed PHP releases: **8.5.12, 8.4.27, 8.3.36, 8.2.35**. PHP 8.1 and older are end-of-life and have no fix.

## Quick start

```bash
git clone https://github.com/suman99pro/php2shell-check.git
cd php2shell-check
sudo bash php2shell-check.sh --webroot /var/www
echo $?
```

`--webroot` is optional. It scans your application code for the runtime `ini_set('session.serialize_handler', ...)` call that CVE-2026-115560 needs.

## What it checks

1. **PHP versions**: every PHP binary it can find (PATH, common install paths, Remi, Plesk, cPanel, and binaries of running php-fpm/Apache processes) against the fixed releases.
2. **Distro backports**: Debian/Ubuntu and RPM package changelogs, because a patched package can still show an old version number. When a changelog lists the CVEs, the version finding is downgraded from VULNERABLE to REVIEW.
3. **Configuration**: `session.upload_progress.enabled`, `session.serialize_handler`, and `memory_limit=-1` across php.ini, conf.d and php-fpm pool files.
4. **Containers**: PHP versions inside running Docker containers.

It prints fix commands for your package manager. **It never changes anything on the system.**

## Reading the result

| Tag | Meaning |
|---|---|
| `[VULNERABLE]` | Version is below the fixed release with no sign of a backport. Patch now. |
| `[REVIEW]` | Probably fine or unknown. A person should read the line. |
| `[OK]` | Check passed. |

Exit codes: `0` no findings, `1` vulnerable, `2` review needed.

## How to fix

1. Upgrade PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your vendor's patched package).
2. Restart php-fpm / Apache so old workers exit.
3. Set `session.upload_progress.enabled = 0` and restart. This is the interim mitigation for CVE-2026-115560.
4. Do not treat `memory_limit=-1` as a fix. It only blocks the known trigger path.
5. Rebuild containers from patched base images.
6. Review web and PHP error logs from 20 October onward for bursts of memory-exhausted errors and unexpected new files in the web root.

PHP states that no configuration change fully mitigates CVE-2026-109618 and CVE-2026-109619. Updating is the fix.

## Limitations

- It checks versions and configuration. It **cannot tell you whether a host was already compromised**.
- The CLI `php.ini` can differ from the one used by php-fpm or Apache. The script scans common config locations, but confirm the effective values for your web SAPI.
- Backport detection reads package changelogs. A custom or source build is judged by version number only.
- Requires Linux and bash 4+. Some checks need root.

## References

- PHP 8.5.12 release notes: https://github.com/php/php-src/releases/tag/php-8.5.12
- watchTowr: https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/
- Datadog Security Labs: https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
- The Hacker News on CVE-2026-115560: https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html

Beware of fake PoCs circulating around this disclosure. Do not run untrusted exploit code.

## License

MIT. See `LICENSE`. Provided as-is, without warranty.

