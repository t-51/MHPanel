#!/usr/bin/env bash
set -e

echo "Starting OpenVPN XOR (Scramble) Installation..."

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libssl-dev liblzo2-dev libpam0g-dev pkg-config wget curl unzip libnl-genl-3-dev libcap-ng-dev liblz4-dev libsystemd-dev

VERSION="2.6.23"

cd /tmp
rm -rf /tmp/openvpn* /tmp/xor*
wget -q "https://build.openvpn.net/downloads/releases/openvpn-${VERSION}.tar.gz" -O /tmp/openvpn.tar.gz
tar -xzf /tmp/openvpn.tar.gz
cd "openvpn-${VERSION}"

# Get patches from Tunnelblick
wget -q "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/main/third_party/sources/openvpn/openvpn-2.6.23/patches/02-tunnelblick-openvpn_xorpatch-a.diff" -O /tmp/xor_a.patch
wget -q "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/main/third_party/sources/openvpn/openvpn-2.6.23/patches/03-tunnelblick-openvpn_xorpatch-b.diff" -O /tmp/xor_b.patch
wget -q "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/main/third_party/sources/openvpn/openvpn-2.6.23/patches/04-tunnelblick-openvpn_xorpatch-c.diff" -O /tmp/xor_c.patch
wget -q "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/main/third_party/sources/openvpn/openvpn-2.6.23/patches/05-tunnelblick-openvpn_xorpatch-d.diff" -O /tmp/xor_d.patch
wget -q "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/main/third_party/sources/openvpn/openvpn-2.6.23/patches/06-tunnelblick-openvpn_xorpatch-e.diff" -O /tmp/xor_e.patch

patch -p1 < /tmp/xor_a.patch
patch -p1 < /tmp/xor_b.patch
patch -p1 < /tmp/xor_c.patch
patch -p1 < /tmp/xor_d.patch
patch -p1 < /tmp/xor_e.patch

export CFLAGS="-w"
./configure --prefix=/usr --sysconfdir=/etc/openvpn --enable-password-save --enable-pam-dlopen --enable-systemd
make -j$(nproc)
make install

# Restart openvpn services
systemctl restart openvpn-server@server || true
systemctl restart openvpn-server@server-tcp || true

echo "OpenVPN XOR Installation complete. Scramble support is now active in /usr/sbin/openvpn."
exit 0
