# Anode VPN server

## Install:

Before using, you must install and run [cjdns](https://github.com/cjdelisle/cjdns/).

```console
$ npm install
```

## Configure:

```console
cp .env.example .env
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

## Running with docker

```
$ docker-compose up
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

## Back-end Setup

## Get your IP addresses

- We're going to assume that anyone running this has only one or a few IPv4 addresses, so they can't issue them to their users.
- But if they have IPv6 then they will have at least a /64 so they can take a /80 from that and issue ip to 65 thousand /96's
- Before moving forward, you need to determine what is your ipv6 address, if any.
- Once you know what is your address and prefix, you can decide what you're going to issue out to clients.
  - If your ISP gives you anything greater (ie fewer addresses) than a /96, you're pretty much hosed, you just don't have enough addresses to do v6
  - If your ISP gives you a /64, which is the general case, you can allocate a /80 out of that for your clients, and from the /80 you can give a /96 to each client

```
e.g. My IP is     2607:5300:203:88b2::/64
I allocate        2607:5300:203:88b2:fc00::/80  for VPN clients
First client gets 2607:5300:203:88b2:fc00:32db::/96  note 32db is random chosen by the server
```

## Setup cjdns and the server

```
git clone https://github.com/cjdelisle/cjdns.git
cd cjdns
./do
cd ..
git clone https://github.com/anode-co/anodevpn-server
cd anodevpn-server
cp config.example.js config.js
nano ./config.js
```

Example config.js

```js
/*@flow*/
module.exports = {
  cfg4: {
    allocSize: 32,
    networkSize: 0,
    prefix: "10.252.0.0/16",
  },

  cfg6: {
    allocSize: 96,
    networkSize: 0,
    prefix: "2607:5300:203:88b2:fc00::/80", // TODO this must be the block to issue from
  },

  serverPort: 8099,
  dryrun: false,
};
```

## IPv4

We can assume that for v4, we're going to be using a NAT, this makes it fairly easy, we just need to choose a prefix, e.g. `10.252.0.0/16` and start issuing addresses out of this range.

### Every reboot:

```
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -I FORWARD -i tun0 -j ACCEPT
iptables -I FORWARD -o tun0 -j ACCEPT
iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE   ## TODO replace eth0 with your public iface
```

### Every time you start cjdns:

```
ip route add 10.252.0.0/16 dev tun0
```

## IPv6

In order to do IPv6 you need to be able to reply to your ISP's NDP (neighbor discovery) requests. To do this, install npd6.

```
apt install npd6
```

Copy /etc/npd6.example.conf to /etc/npd6.conf

The following 2 lines need to be edited to your range, and your public iface:

```
prefix=2607:5300:203:88b2:fc00::/80


// Which interface are we monitoring and using?

interface = eno1
```

### Every reboot:

```
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
ip6tables -I FORWARD -i tun0 -j ACCEPT
ip6tables -I FORWARD -o tun0 -j ACCEPT
ip6tables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

### Every time you start cjdns:

```
ip route add 2607:5300:203:88b2:fc00::/80 dev tun0
```
