#!/usr/bin/env bash
# License: MIT. Provided as-is, without warranty. Verify findings against your vendor advisories.
# Version: 1.0.0 (2026-10-24)
# php2shell-check.sh - read-only exposure check for PHP2Shell
#   CVE-2026-109618 (OOM corruption RCE), CVE-2026-109619 (stale state RCE)
#   CVE-2026-115560 (session upload-progress + serialize_handler switch; unpatched upstream)
#
# Usage:  sudo bash php2shell-check.sh [--webroot /var/www]
# Exit:   0 = no findings, 1 = vulnerable/exposed, 2 = needs manual review
# Makes NO changes to the system. Fix commands are printed, never executed.

set -u
WEBROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --webroot) WEBROOT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) shift ;;
  esac
done

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else R=; G=; Y=; B=; N=; fi
VULN=0; REVIEW=0
FIXES=()
bad()  { echo "  ${R}[VULNERABLE]${N} $*"; VULN=1; }
warn() { echo "  ${Y}[REVIEW]${N}     $*"; REVIEW=1; }
ok()   { echo "  ${G}[OK]${N}         $*"; }
info() { echo "  [info]       $*"; }
fix()  { FIXES+=("$*"); }

# Fixed releases published 2026-10-21 (upstream PHP security advisory)
fixed_for() {
  case "$1" in
    8.2) echo 8.2.35 ;; 8.3) echo 8.3.36 ;; 8.4) echo 8.4.27 ;; 8.5) echo 8.5.12 ;; *) echo "" ;;
  esac
}
ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }

echo "${B}== PHP2Shell exposure check ==${N}  host: $(hostname)  $(date -u +%FT%TZ)"
[ "$(id -u)" -ne 0 ] && echo "  (not root: some package/config checks may be incomplete)"

# Pre-scan: do installed distro packages carry a backported fix? (version numbers lie on Debian/Ubuntu/RHEL)
BACKPORT=0
if command -v dpkg >/dev/null 2>&1; then
  for p in $(dpkg -l 2>/dev/null | awk '/^ii +php[0-9.]*-(cli|fpm|common)|^ii +libapache2-mod-php/{print $2}'); do
    zcat -f "/usr/share/doc/$p/changelog.Debian.gz" 2>/dev/null | head -200 | grep -Eq 'CVE-2026-109618|CVE-2026-109619' && BACKPORT=1
  done
fi
if command -v rpm >/dev/null 2>&1; then
  for p in $(rpm -qa 2>/dev/null | grep -Ei '^(php|php-fpm|php-cli|ea-php[0-9]+-php)' | head -30); do
    rpm -q --changelog "$p" 2>/dev/null | head -150 | grep -Eq 'CVE-2026-109618|CVE-2026-109619' && BACKPORT=1
  done
fi

# ---------- 1. Find PHP binaries ----------
echo; echo "${B}[1] PHP installations${N}"
declare -A SEEN
BINS=()
add_bin() { local p; p=$(readlink -f "$1" 2>/dev/null) || return; [ -x "$p" ] || return
  [ -n "${SEEN[$p]:-}" ] && return; SEEN[$p]=1; BINS+=("$p"); }
for c in php php-cli php-fpm php-cgi; do command -v "$c" >/dev/null 2>&1 && add_bin "$(command -v "$c")"; done
for p in /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
         /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
         /opt/plesk/php/*/bin/php /opt/cpanel/ea-php*/root/usr/bin/php \
         /usr/local/php*/bin/php /opt/php*/bin/php; do
  [ -e "$p" ] && add_bin "$p"
done
# binaries of running processes
for pid in $(pgrep -f 'php-fpm|php-cgi|httpd|apache2' 2>/dev/null | head -50); do
  exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) && case "$exe" in *php*) add_bin "$exe";; esac
done
# Apache mod_php
for m in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so; do
  [ -e "$m" ] && warn "Apache mod_php module found: $m (version = distro package below; restart Apache after update)"
done

if [ ${#BINS[@]} -eq 0 ]; then
  info "No PHP binary found. If PHP runs in containers, check images (see end of report)."
fi

declare -A VERS
for b in ${BINS[@]+"${BINS[@]}"}; do
  v=$("$b" -v 2>/dev/null | head -n1 | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
  [ -z "$v" ] && continue
  VERS[$b]=$v
  mm=${v%.*}; want=$(fixed_for "$mm")
  if [ -n "$want" ]; then
    if ver_lt "$v" "$want"; then
      if [ "$BACKPORT" -eq 1 ]; then
        warn "$b  ->  PHP $v is below upstream $want, but the distro changelog lists the PHP2Shell CVEs (backport). Likely patched; confirm the package is the latest and workers were restarted."
      else
        bad "$b  ->  PHP $v  (fixed in $want)"
        fix "Upgrade PHP $mm to >= $want (see package commands below)."
      fi
    else
      ok "$b  ->  PHP $v  (>= $want)"
    fi
  else
    bad "$b  ->  PHP $v  is end-of-life / outside the patched branches (8.2-8.5). No upstream fix."
    fix "Migrate $b (PHP $v) to a supported branch: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or newer."
  fi
done

# ---------- 2. Distro backports (version string may look old but be patched) ----------
echo; echo "${B}[2] Distribution package patch status${N}"
CVE_RE='CVE-2026-109618|CVE-2026-109619'
if command -v dpkg >/dev/null 2>&1; then
  pk=$(dpkg -l 2>/dev/null | awk '/^ii +php[0-9.]*-(common|cli|fpm)|^ii +libapache2-mod-php/{print $2}' | sort -u)
  if [ -n "$pk" ]; then
    for p in $pk; do
      cl=$(zcat -f "/usr/share/doc/$p/changelog.Debian.gz" 2>/dev/null | head -200)
      if echo "$cl" | grep -Eq "$CVE_RE"; then ok "$p changelog mentions the PHP2Shell CVEs (backport applied)"
      else warn "$p ($(dpkg-query -W -f='${Version}' "$p")): changelog has no PHP2Shell CVE entry -> run: apt update && apt list --upgradable | grep -i php"; fi
    done
    fix "Debian/Ubuntu:  sudo apt update && sudo apt install --only-upgrade 'php*' 'libapache2-mod-php*'   (Sury/Ondrej PPA for 8.x branches)"
  else info "No dpkg php packages"; fi
fi
if command -v rpm >/dev/null 2>&1; then
  pk=$(rpm -qa 2>/dev/null | grep -Ei '^(php|php[0-9]+|php-fpm|php-cli|ea-php[0-9]+-php|.*-php-common)' | sort -u | head -30)
  if [ -n "$pk" ]; then
    for p in $pk; do
      if rpm -q --changelog "$p" 2>/dev/null | head -150 | grep -Eq "$CVE_RE"; then ok "$p changelog mentions the PHP2Shell CVEs"
      else warn "$p: no PHP2Shell CVE in changelog -> run: dnf check-update 'php*'"; fi
    done
    fix "RHEL/Alma/Rocky/Fedora:  sudo dnf upgrade 'php*'   (Remi: dnf module reset php && dnf upgrade)"
  else info "No rpm php packages"; fi
fi
command -v apk >/dev/null 2>&1 && fix "Alpine:  apk update && apk upgrade php*"
command -v zypper >/dev/null 2>&1 && fix "SUSE:  sudo zypper refresh && sudo zypper update 'php*'"

# ---------- 3. Configuration exposure ----------
echo; echo "${B}[3] Configuration (CVE-2026-115560 and mitigations)${N}"
INIS=()
for b in ${BINS[@]+"${BINS[@]}"}; do
  while IFS= read -r f; do [ -f "$f" ] && INIS+=("$f"); done < <("$b" --ini 2>/dev/null | grep -oE '/[^ ,]+\.ini' | sort -u)
done
for f in /etc/php.ini /etc/php.d/*.ini /etc/php/*/*/php.ini /etc/php/*/*/conf.d/*.ini \
         /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php/php.ini \
         /usr/local/etc/php/conf.d/*.ini /usr/local/etc/php-fpm.d/*.conf; do
  [ -f "$f" ] && INIS+=("$f")
done
mapfile -t INIS < <(printf '%s\n' ${INIS[@]+"${INIS[@]}"} | sort -u)

up_on=0; up_seen=0; ser_bad=""
for f in ${INIS[@]+"${INIS[@]}"}; do
  l=$(grep -Ei '^[[:space:]]*(php_(admin_)?value\[)?session\.upload_progress\.enabled' "$f" 2>/dev/null | tail -n1)
  if [ -n "$l" ]; then up_seen=1
    echo "$l" | grep -Eiq '(=|,)[[:space:]]*(0|off|false|no)[[:space:]]*\]?$' || up_on=1
    info "$f: $(echo "$l" | xargs)"
  fi
  s=$(grep -Ei '^[[:space:]]*(php_(admin_)?value\[)?session\.serialize_handler' "$f" 2>/dev/null | tail -n1)
  echo "$s" | grep -Eiq 'php_binary|php_serialize' && ser_bad="$ser_bad $f"
done
if [ "$up_seen" -eq 0 ] || [ "$up_on" -eq 1 ]; then
  warn "session.upload_progress.enabled is ON (PHP default since 5.4) - the session path abused in PHP2Shell and CVE-2026-115560"
  fix "Mitigation until patched (also covers CVE-2026-115560): set  session.upload_progress.enabled = 0  in php.ini / conf.d, then restart php-fpm / Apache. May break upload progress bars."
else
  ok "session.upload_progress.enabled is explicitly disabled"
fi
[ -n "$ser_bad" ] && warn "session.serialize_handler=php_binary/php_serialize set in:$ser_bad  (precondition for CVE-2026-115560)"

for f in ${INIS[@]+"${INIS[@]}"}; do
  grep -Eqi '^[[:space:]]*(php_(admin_)?value\[)?memory_limit[[:space:]]*=[[:space:]]*-1' "$f" 2>/dev/null && \
    warn "memory_limit=-1 in $f: only blocks the known trigger path, NOT a fix; also risks OOM-killing the host."
done

if [ -n "$WEBROOT" ] && [ -d "$WEBROOT" ]; then
  echo "  scanning $WEBROOT for runtime serialize_handler switches (CVE-2026-115560 precondition)..."
  hits=$(grep -RIn --include='*.php' -E "ini_set\(\s*['\"]session\.serialize_handler['\"]" "$WEBROOT" 2>/dev/null | head -20)
  if [ -n "$hits" ]; then warn "ini_set('session.serialize_handler') found in application code:"; echo "$hits" | sed 's/^/      /'
    fix "Remove ini_set('session.serialize_handler', ...) calls from application code (or disable upload progress as above)."
  else ok "no ini_set('session.serialize_handler') in $WEBROOT"; fi
else
  info "Tip: re-run with  --webroot /var/www  to scan app code for the CVE-2026-115560 precondition"
fi

# ---------- 4. Containers ----------
echo; echo "${B}[4] Containers${N}"
if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
  docker ps --format '{{.Names}} {{.Image}}' | grep -i php | while read -r n i; do
    v=$(docker exec "$n" php -v 2>/dev/null | head -n1 | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
    [ -n "$v" ] && echo "  [info]       container $n ($i): PHP $v  -> compare with fixed versions"
  done
  fix "Containers: rebuild with patched base image (e.g. php:8.4.27-fpm, php:8.3.36, php:8.5.12, php:8.2.35) and redeploy; old tags/digests stay vulnerable."
else info "docker not available or no access"; fi

# ---------- Report ----------
echo; echo "${B}== Summary ==${N}"
if [ $VULN -eq 1 ]; then echo "  ${R}VULNERABLE${N} - patch PHP immediately; exploitation in the wild has been reported."
elif [ $REVIEW -eq 1 ]; then echo "  ${Y}REVIEW NEEDED${N} - versions look patched/unknown; resolve [REVIEW] items above."
else echo "  ${G}No findings.${N}"; fi

if [ ${#FIXES[@]} -gt 0 ]; then
  echo; echo "${B}== What to do ==${N}"
  printf '%s\n' "${FIXES[@]}" | awk '!s[$0]++' | nl -w2 -s'. '
  cat <<'EOT'
  After upgrading: restart workers so old code leaves memory
     sudo systemctl restart php*-fpm apache2 httpd nginx   (use the units that exist)
  Verify:  php -v   and re-run this script.
  Hardening while you patch:
     - Put a WAF / reverse proxy rule in front limiting large multipart uploads to routes that need them
     - Set a per-worker memory cap (systemd MemoryMax= / cgroup) so a crash can't take the host down
     - Review web logs and PHP error logs from Oct 20 onward for "Allowed memory size exhausted"
       bursts and unexpected new files under the web root; rotate secrets if compromise is suspected
  Note: CVE-2026-115560 has no upstream patch yet; the INI mitigation above is the official interim step.
EOT
fi
[ $VULN -eq 1 ] && exit 1
[ $REVIEW -eq 1 ] && exit 2
exit 0

