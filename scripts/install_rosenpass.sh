#!/usr/bin/env bash
set -e

echo "Starting Rosenpass Installation..."

cd /tmp
rm -f rosenpass*.tar
wget https://github.com/rosenpass/rosenpass/releases/download/v0.2.2/rosenpass-x86_64-linux-0.2.2.tar
tar -xf rosenpass-x86_64-linux-0.2.2.tar

if [ -f "bin/rosenpass" ]; then
    cp bin/rosenpass /usr/bin/
elif [ -f "rosenpass" ]; then
    cp rosenpass /usr/bin/
fi

chmod +x /usr/bin/rosenpass || echo "Warning: rosenpass binary not found in tar file"

echo "Rosenpass Installation complete. (Binary is at /usr/bin/rosenpass)"
exit 0
