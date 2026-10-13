#!/usr/bin/env bash
set -e

echo "Starting UDPspeeder Installation..."

# Download pre-compiled binary
cd /tmp
rm -f speederv2_binaries.tar.gz*
wget https://github.com/wangyu-/UDPspeeder/releases/download/20230206.0/speederv2_binaries.tar.gz -O /tmp/speederv2.tar.gz
tar -xzf /tmp/speederv2.tar.gz

systemctl stop udpspeeder-openvpn || true

# The binary file for amd64 is speederv2_amd64
rm -f /usr/bin/udpspeeder
cp speederv2_amd64 /usr/bin/udpspeeder
chmod +x /usr/bin/udpspeeder

# Create systemd service for UDPspeeder to forward port 4000 to OpenVPN port (1194)
cat > /etc/systemd/system/udpspeeder-openvpn.service <<EOF
[Unit]
Description=UDPspeeder for OpenVPN
After=network.target

[Service]
Type=simple
# Listen on 4000, forward to 1194. fec 20:10
ExecStart=/usr/bin/udpspeeder -s -l0.0.0.0:4000 -r127.0.0.1:1194 -f20:10 -k "openvpn_speeder" --mode 0
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udpspeeder-openvpn
systemctl restart udpspeeder-openvpn

# Allow port 4000
ufw allow 4000/udp || true

echo "UDPspeeder Installation complete."
exit 0
