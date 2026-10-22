#!/bin/sh
# php2shell-guard quickcheck - POSIX sh, no python needed.
# Finds PHP binaries on this host and reports whether each build carries the
# php2shell fix (CVE-2026-109618 / CVE-2026-109619).
#
#   sh quickcheck.sh            # human output, exit 1 if anything is unpatched
#   sh quickcheck.sh --json     # one JSON object per line
#
# Signals used, in order of trust:
#   1. patch marker strings that only exist in fixed builds
#        memory_hard_limit_percent  (full fix, 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+)
#        zend_mm_safe_error_ex      (minimal 7.4 / 8.0 / 8.1 backports)
#   2. the version number against the upstream fixed-release table
# Distro backports keep the old version number, so (1) wins over (2).
# For packages, FPM pools, Apache directives and Docker use php2shell-guard.py.

JSON=0
[ "$1" = "--json" ] && JSON=1

seen=""
bad=0
total=0

candidates() {
    # PATH entries
    oldifs=$IFS; IFS=:
    for d in $PATH; do
        for n in php php-cgi php-fpm lsphp frankenphp php5 php7 php8 php8.0 php8.1 php8.2 php8.3 php8.4 php8.5 php8.6 php80 php81 php82 php83 php84 php85 php-fpm8.0 php-fpm8.1 php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5 php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm; do
            [ -f "$d/$n" ] && echo "$d/$n"
        done
    done
    IFS=$oldifs
    # Known install locations
    for p in /usr/bin/php* /usr/sbin/php-fpm* /usr/sbin/php*-fpm /usr/lib/cgi-bin/php* \
             /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm /usr/local/bin/frankenphp \
             /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
             /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/bin/lsphp \
             /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
             /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/fcgi-bin/lsphp* \
             /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm \
             /opt/homebrew/opt/php*/bin/php /opt/homebrew/opt/php*/sbin/php-fpm \
             /usr/local/opt/php*/bin/php /usr/local/opt/php*/sbin/php-fpm \
             /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /etc/httpd/modules/libphp*.so \
             /usr/local/apache/modules/libphp*.so /opt/cpanel/ea-php*/root/usr/lib64/apache2/modules/libphp*.so \
             /opt/homebrew/opt/php*/lib/httpd/modules/libphp.so /usr/local/opt/php*/lib/httpd/modules/libphp.so; do
        [ -f "$p" ] && echo "$p"
    done
    # Binaries behind running workers (Linux)
    if [ -d /proc ]; then
        for e in /proc/[0-9]*/exe; do
            t=$(readlink "$e" 2>/dev/null) || continue
            case "$t" in *php*) echo "${t% (deleted)}";; esac
        done
        for m in /proc/[0-9]*/maps; do
            grep -o '/[^ ]*libphp[^ ]*\.so' "$m" 2>/dev/null
        done
    fi
}

has_marker() {
    # grep -a is not universal (busybox); fall back to tr
    if grep -a -q -e memory_hard_limit_percent -e zend_mm_safe_error_ex "$1" 2>/dev/null; then
        return 0
    fi
    tr -c '[:print:]' '\n' < "$1" 2>/dev/null | grep -q -e memory_hard_limit_percent -e zend_mm_safe_error_ex
}

version_of() {
    case "$1" in
        *.so) tr -c '[:print:]' '\n' < "$1" 2>/dev/null | grep -o 'X-Powered-By: PHP/[0-9][0-9.]*[A-Za-z0-9-]*' | head -1 | sed 's#.*PHP/##' ;;
        *frankenphp*) "$1" version 2>/dev/null | grep -o 'PHP [0-9][0-9.]*' | head -1 | cut -d' ' -f2 ;;
        *) "$1" -n -v 2>/dev/null | grep -o 'PHP [0-9][0-9.]*[A-Za-z0-9-]*' | head -1 | cut -d' ' -f2 ;;
    esac
}

# version_status VERSION -> patched|vulnerable|eol|unknown
version_status() {
    v=$1
    maj=${v%%.*}; rest=${v#*.}; min=${rest%%.*}; rest=${rest#*.}; pat=$(printf '%s' "$rest" | sed 's/[^0-9].*//')
    [ -z "$maj" ] || [ -z "$min" ] || [ -z "$pat" ] && { echo unknown; return; }
    case "$maj.$min" in
        8.2) fix=35 ;; 8.3) fix=36 ;; 8.4) fix=27 ;; 8.5) fix=12 ;;
        8.6|8.7|8.8|8.9|9.*) echo patched; return ;;
        8.0|8.1|7.*|5.*) echo eol; return ;;
        *) echo unknown; return ;;
    esac
    if [ "$pat" -gt "$fix" ]; then echo patched
    elif [ "$pat" -eq "$fix" ]; then
        case "$v" in *RC*|*rc*|*dev*|*alpha*|*beta*) echo vulnerable ;; *) echo patched ;; esac
    else echo vulnerable; fi
}

for raw in $(candidates | sort -u); do
    bin=$(readlink -f "$raw" 2>/dev/null || echo "$raw")
    case " $seen " in *" $bin "*) continue;; esac
    seen="$seen $bin"
    [ -r "$bin" ] || { [ $JSON = 1 ] && printf '{"path":"%s","verdict":"UNREADABLE"}\n' "$bin" || printf '%-12s %s (not readable, run as root)\n' UNREADABLE "$bin"; continue; }
    total=$((total + 1))
    ver=$(version_of "$bin")
    vs=$(version_status "$ver")
    if has_marker "$bin"; then
        verdict=PATCHED; why="fix marker present in binary"
    else
        case "$vs" in
            patched) verdict=PATCHED; why="version $ver is a fixed release (no marker found; verify origin)" ;;
            vulnerable) verdict=VULNERABLE; why="version $ver predates the fix" ;;
            eol) verdict=VULNERABLE; why="EOL branch $ver and no backport marker; confirm with your vendor" ;;
            *) verdict=UNKNOWN; why="could not read version" ;;
        esac
    fi
    [ "$verdict" = VULNERABLE ] && bad=$((bad + 1))
    if [ $JSON = 1 ]; then
        printf '{"path":"%s","version":"%s","verdict":"%s","reason":"%s"}\n' "$bin" "$ver" "$verdict" "$why"
    else
        printf '%-12s %-55s %-12s %s\n' "$verdict" "$bin" "${ver:--}" "$why"
    fi
done

if [ $JSON = 0 ]; then
    echo
    if [ $total -eq 0 ]; then echo "no PHP binaries found"
    elif [ $bad -gt 0 ]; then echo "RESULT: $bad of $total PHP build(s) unpatched. Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or your vendor backport) and restart every worker."
    else echo "RESULT: all $total PHP build(s) carry the fix. Restart workers if any binary changed since they started."; fi
    echo "Config / packages / FPM pools / Docker: python3 php2shell-guard.py scan"
fi
[ $bad -gt 0 ] && exit 1
exit 0
