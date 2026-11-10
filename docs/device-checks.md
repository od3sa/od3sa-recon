# Device checks (read-only)

Run from a machine that can reach the Pager:
```
ssh root@172.16.52.1 'sh -s' < scripts/device-checks.sh > device-report.txt
```
The script only reads. It installs nothing, writes nothing and doesn't change the network. It redacts MAC addresses and SSIDs. Check the output again before pasting it anywhere.

| Command | What it tells us |
|---|---|
| `cat /etc/openwrt_release`, `uname -a` | OpenWrt release and kernel, which pick the SDK |
| `cat /proc/cpuinfo` | SoC and CPU (expect MT7628, MIPS 24KEc) |
| `opkg print-architecture`, `/etc/opkg/distfeeds.conf` | Package arch (expect mipsel_24kc) and feeds |
| `ldd --version` or `ls /lib/ld-musl*` | libc |
| `free -m`, `df -h`, `mount` | RAM headroom; where /mmc and the overlay live |
| `iw dev`, `iw phy` | Interfaces, monitor support, bands (6 GHz?) |
| `ls /etc/init.d`, `ps w` | Names of the recon, PineAP, BT recon and gpsd services |
| `hciconfig -a` or `/sys/class/bluetooth` | BT adapter |
| `lsusb -t`, `/dev/ttyUSB*`, `/dev/ttyACM*` | USB devices, GPS serial |
| `opkg list-installed` (filtered) | Deps already present |
| `printf '?POLL;\n' \| nc -w 2 127.0.0.1 2947` | whether gpsd answers the `?` framing — the client needs it, and a bare JSON object as a request gets an "Unrecognized request" error |
| `sqlite3 -readonly <db>` on `/root/recon/*` | the schema of the recon database, which the pineapd ingest adapter needs |
| `head -n 1 /root/loot/wigle*.csv` | the header of the blue5 scanner's output |
| `ls -la /tmp/blue5_sock`, `blue5 --help` | the blue5 socket and what its flags mean |

## Results
_Paste the redacted output here (date, firmware version)._
```
(pending)
```
