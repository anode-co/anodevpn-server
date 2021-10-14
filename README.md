# Anode VPN server

## Install:

Before using, you must install and run [cjdns](https://github.com/cjdelisle/cjdns/).

```console
$ npm install
```

## Configure:

```console
cp config.example.js config.js
```

Edit your config file as you see fit. The default settings should work.

## Run:

```console
node index.js
```

## Running with pm2

[pm2](https://pm2.keymetrics.io/) is a daemon process manager to make running applications in the background a little easier.

Installing pm2:

```console
$ npm install pm2 -g
```

Run the vpn server in the background.
```console
$ pm2 start index.js
```

## Firewall

Make sure to allow access to TCP and UDP for the cjdns port (change `30969` to match your cjdns port):

```console
$ ufw allow 30969
```

## Routing

You will need to set up IP Masquerading to route traffic from your connected clients to the Internet.

Each system is diffferent, but here's an example for Debian (replace `eth0` with the name of your public-facing ethernet device):

```console
$ iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
$ iiptables -A FORWARD -i tun0 -j ACCEPT
$ iiptables -A FORWARD -o tun0 -j ACCEPT
$ isudo sysctl -w net.ipv4.ip_forward=1
iptables-save
```

Persist between reboots:

```console
# Enable use 1, Disable use 0
# 1. Edit "sysctl.conf" file
sudo nano /etc/sysctl.conf
# 2. Add following line at the bottom of the file, if it's not in the file, otherwise replace 0 with 1
net.ipv4.ip_forward = 1
# 3. Use Ctrl + X, Y, Enter key to Save and exit nano editor
# 4. Apply the change
sudo sysctl -p
or
sudo sysctl -p /etc/sysctl.conf
iptables-save > /etc/iptables.rules

mkdir -p /etc/network/if-pre-up.d
echo "#!/bin/bash" > /etc/network/if-pre-up.d/firewall
echo "/sbin/iptables-restore < /etc/iptables.rules" >> /etc/network/if-pre-up.d/firewall
chmod +x /etc/network/if-pre-up.d/firewall
```

Add a route (replace `10.66.0.0/16` with a network range compatible with your `config.js` settings)
```console
$ ip route add 10.66.0.0/16 dev tun0
```
