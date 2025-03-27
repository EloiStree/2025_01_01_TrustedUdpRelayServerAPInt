# Trusted Udp Relay Server APInt

It allows to make relay to send and received in UDP in IID format with device that don't support WebSocket client (like CircuitPython) 



```
git clone https://github.com/EloiStree/2025_01_01_TrustedUdpRelayServerAPIntIID.git /git/apint_udp_relay_iid
sudo nano apint_udp_relay_iid.service
sudo nano apint_udp_relay_iid.timer
```
```
[Unit]
Description=APIntIO Push IID Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /git/apint_udp_relay_iid/RunServer.py
Restart=always
User=root
WorkingDirectory=/git/apint_udp_relay_iid

[Install]
WantedBy=multi-user.target
```

```
[Unit]
Description=APIntIO Push IID Timer

[Timer]
OnBootSec=0min
OnUnitActiveSec=10s

[Install]
WantedBy=timers.target
```

```
cd /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable apint_udp_relay_iid.service
chmod +x /git/apint_udp_relay_iid/RunServer.py
sudo systemctl restart apint_udp_relay_iid.service
sudo systemctl status apint_udp_relay_iid.service

sudo systemctl enable apint_udp_relay_iid.timer
sudo systemctl start apint_udp_relay_iid.timer
sudo systemctl status apint_udp_relay_iid.timer
sudo systemctl list-timers | grep apint_udp_relay_iid

sudo systemctl restart apint_udp_relay_iid.service
sudo systemctl restart apint_udp_relay_iid.timer
```
