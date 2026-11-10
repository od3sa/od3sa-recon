#!/bin/sh
# Read-only Pager report. No writes, installs or network changes. Redacts MACs and SSIDs.
redact() {
  sed -E -e 's/([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/XX:XX:XX:XX:XX:XX/g' \
         -e 's/(ssid|SSID)([ =:"]+).*/\1\2<redacted>/'
}
sec() { echo; echo "===== $* ====="; }
{
sec release; cat /etc/openwrt_release 2>/dev/null; uname -a
sec cpu; head -n 12 /proc/cpuinfo
sec opkg; opkg print-architecture 2>/dev/null; cat /etc/opkg/distfeeds.conf 2>/dev/null; ls /etc/opkg 2>/dev/null
sec libc; ls /lib/ld-musl* 2>/dev/null; ldd --version 2>&1 | head -n 2
sec memory; free -m
sec storage; df -h; mount | grep -E 'mmc|overlay|root'
sec iw-dev; iw dev 2>/dev/null
sec iw-phy; iw phy 2>/dev/null | grep -E 'Wiphy|Supported interface modes|\* (monitor|managed|AP)|MHz \[' 
sec services; ls /etc/init.d
sec processes; ps w | grep -iE 'pinea|recon|blue|bt|gps|kismet' | grep -v grep
sec bluetooth; (hciconfig -a 2>/dev/null || ls /sys/class/bluetooth 2>/dev/null)
sec usb; lsusb -t 2>/dev/null; ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null
sec gpsd; uci -q show gpsd 2>/dev/null
# Does gpsd answer the "?WATCH" framing? The client needs it: a bare JSON
# object is what gpsd *answers* with, and sending one as a request gets an
# "Unrecognized request" error.
sec gpsd-framing; printf '?POLL;\n' | nc -w 2 127.0.0.1 2947 2>&1 | head -n 3
# What the pineapd recon and the blue5 scanner have written. The header of
# the WiGLE CSV and the schema of the recon database are what the ingest
# adapters need.
sec pineapd-recon; ls -la /root/recon 2>/dev/null
for db in /root/recon/*.db /root/recon/*.sqlite /root/recon/*.sqlite3; do
  [ -f "$db" ] || continue
  echo "--- $db"
  sqlite3 -readonly "$db" '.tables' 2>&1
  sqlite3 -readonly "$db" '.schema' 2>&1
done
sec blue5-output; ls -la /root/loot 2>/dev/null; head -n 1 /root/loot/wigle*.csv 2>/dev/null
sec blue5-socket; ls -la /tmp/blue5_sock 2>/dev/null; file /tmp/blue5_sock 2>/dev/null; blue5 --help 2>&1 | head -n 40
sec packages; opkg list-installed 2>/dev/null | grep -E 'libpcap|libnl|protobuf|sqlite|libstdcpp|pcre|gpsd'
} 2>&1 | redact
