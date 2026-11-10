#!/bin/sh
#
# Put back the init script a firmware update removed.
#
# A firmware update wipes the overlay, so /etc/init.d/od3sa-recond is gone.
# Everything else this project needs lives on the SD card, under /mmc,
# which survives the update: the daemon, the database, the configuration
# and the plugins.
#
# The script is idempotent: running it twice does the same thing and ends
# in the same state. It copies one file and touches nothing else - not the
# database, not the plugins, not the configuration.
#
# PREFIX is empty on the device. It is there so that the test can run this
# script in a sandbox instead of against the real /mmc and /etc.

set -e

PREFIX="${OD3SA_PREFIX:-}"
SD_DIR="$PREFIX/mmc/od3sa-recon"
INIT_DIR="$PREFIX/etc/init.d"
INIT_SCRIPT="$INIT_DIR/od3sa-recond"

cp -p "$SD_DIR/od3sa-recond.init" "$INIT_SCRIPT"
chmod 0755 "$INIT_SCRIPT"
"$INIT_SCRIPT" enable
"$INIT_SCRIPT" restart
