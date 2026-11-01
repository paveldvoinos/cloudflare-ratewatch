#!/bin/sh
# Build dist/cf-ratewatch_<version>_all.deb with plain dpkg-deb.
# Usage: packaging/build-deb.sh [version]   (default: __version__ from cf_ratewatch.py)
set -eu
cd "$(dirname "$0")/.."

PKG=cf-ratewatch
VERSION="${1:-$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' cf_ratewatch.py)}"
VERSION="$(printf %s "$VERSION" | sed 's/^v//; s/-/~/g')"   # v1.2.0-rc1 -> 1.2.0~rc1 (sorts before 1.2.0)
MAINTAINER="${DEB_MAINTAINER:-paveldvoinos <paveldvoinos@users.noreply.github.com>}"
EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
chmod 755 "$ROOT"

install -Dm755 cf_ratewatch.py "$ROOT/usr/bin/cf-ratewatch"
sed -i "1s|.*|#!/usr/bin/python3|" "$ROOT/usr/bin/cf-ratewatch"   # Debian policy: no /usr/bin/env in shebangs
install -Dm644 contrib/cf-ratewatch.service "$ROOT/usr/lib/systemd/system/cf-ratewatch.service"
install -Dm644 contrib/cf-ratewatch.timer "$ROOT/usr/lib/systemd/system/cf-ratewatch.timer"
install -Dm644 contrib/cf-ratewatch.sysusers "$ROOT/usr/lib/sysusers.d/cf-ratewatch.conf"
install -Dm644 config.example.toml "$ROOT/etc/cf-ratewatch/config.toml"
sed -i 's#^ExecStart=.*#ExecStart=/usr/bin/cf-ratewatch -c /etc/cf-ratewatch/config.toml run#' \
    "$ROOT/usr/lib/systemd/system/cf-ratewatch.service"

DOC="$ROOT/usr/share/doc/$PKG"
install -Dm644 README.md "$DOC/README.md"
install -Dm644 config.example.toml "$DOC/examples/config.example.toml"
install -Dm644 -t "$DOC/grafana" contrib/grafana/*.json
install -Dm644 packaging/lintian-overrides "$ROOT/usr/share/lintian/overrides/$PKG"
{
    echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
    echo "Upstream-Name: $PKG"
    echo "Source: https://github.com/paveldvoinos/cloudflare-ratewatch"
    echo
    echo "Files: *"
    echo "Copyright: 2026 cf-ratewatch contributors"
    echo "License: MIT"
    sed 's/^$/./; s/^/ /' LICENSE
} > "$DOC/copyright"
chmod 644 "$DOC/copyright"
printf '%s (%s) unstable; urgency=medium\n\n  * Release %s: https://github.com/paveldvoinos/cloudflare-ratewatch/releases\n\n -- %s  %s\n' \
    "$PKG" "$VERSION" "$VERSION" "$MAINTAINER" "$(date -uR -d "@$EPOCH")" \
    | gzip -9n > "$DOC/changelog.gz"
chmod 644 "$DOC/changelog.gz"

SIZE="$(du -sk "$ROOT" | cut -f1)"
mkdir -p "$ROOT/DEBIAN"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: all
Maintainer: $MAINTAINER
Depends: python3 (>= 3.11)
Section: net
Priority: optional
Installed-Size: $SIZE
Homepage: https://github.com/paveldvoinos/cloudflare-ratewatch
Description: hour-scale per-IP request limits for Cloudflare zones
 Counts requests per client IP over a long window (default 60 minutes)
 with the Cloudflare GraphQL Analytics API and blocks heavy hitters with
 IP Access Rules that expire on their own. Works on the Cloudflare Free
 plan, whose rate limiting only counts over 10 seconds. Optional metrics
 for Prometheus (textfile collector) and InfluxDB.
EOF
echo /etc/cf-ratewatch/config.toml > "$ROOT/DEBIAN/conffiles"
install -m755 packaging/postinst packaging/prerm packaging/postrm "$ROOT/DEBIAN/"

(cd "$ROOT" && find . -type f ! -path "./DEBIAN/*" -printf "%P\n" | LC_ALL=C sort | xargs md5sum > DEBIAN/md5sums)
find "$ROOT" -exec touch -h -d "@$EPOCH" {} +   # reproducible: same commit, same bytes
mkdir -p dist
OUT="dist/${PKG}_${VERSION}_all.deb"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$OUT"
echo "$OUT"
