#!/bin/sh
set -eu
mkdir -p /run/samba /share/folder
chmod 0700 /run/samba
printf '%s\n' 'Fixture-Only-Protocol-Check-2037' 'Fixture-Only-Protocol-Check-2037' | smbpasswd -s -a smbreader -c /etc/samba/smb.conf >/dev/null
printf 'synthetic document\n' > /share/report.txt
printf 'nested synthetic document\n' > /share/folder/nested.txt
ln -s /etc/passwd /share/escape
chmod -R a-w /share
chown -R smbreader:smbreader /share
exec smbd --foreground --no-process-group --configfile=/etc/samba/smb.conf
