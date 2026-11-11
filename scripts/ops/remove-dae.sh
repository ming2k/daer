#!/usr/bin/env bash
# Remove the old dae installation and keep a recoverable copy of its configuration.
#
#   sudo scripts/ops/remove-dae.sh
#
# daer does not depend on dae at runtime. Keeping both installed is actively harmful:
# both want to be the transparent proxy on this host.
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "run this with sudo: sudo $0" >&2
    exit 2
fi

stamp="$(date +%Y%m%d-%H%M%S)"
backup="/var/backups/dae-$stamp.tar.gz"
mkdir -p /var/backups
if [[ -d /etc/dae ]]; then
    tar -C /etc -czf "$backup" dae
    echo "backed up /etc/dae -> $backup"
fi

systemctl disable --now dae >/dev/null 2>&1 || true

if command -v wright >/dev/null 2>&1 && wright list 2>/dev/null | grep -q '^dae:'; then
    # wright owns the installed dae files; its transaction is the correct removal path.
    wright remove dae
else
    rm -f /usr/bin/dae /usr/lib/systemd/system/dae.service
    rm -rf /usr/share/dae
    rm -f /usr/share/bash-completion/completions/dae
    rm -f /usr/share/zsh/site-functions/_dae
    rm -f /usr/share/fish/vendor_completions.d/dae.fish
fi
# wright preserves user configuration; the tarball above is its recovery copy.
rm -rf /etc/dae

systemctl daemon-reload
systemctl reset-failed dae >/dev/null 2>&1 || true
echo "dae removed; daer is now the only transparent proxy installed"
