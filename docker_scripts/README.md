# IPv6 Support in Docker

Make sure to [Enable IPv6 support](https://docs.docker.com/config/daemon/ipv6/) in Docker before building.

### Get ip addresses

MacOS:

Go to System Preferences -> Network -> Advanced -> TCP/IP

If your system has an IPv6 address, it will show here.

Linux:

```console
$ ip addr show

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 56:00:02:77:66:66 brd ff:ff:ff:ff:ff:ff
    inet 45.77.111.157/23 brd 45.77.111.255 scope global dynamic ens3
       valid_lft 75221sec preferred_lft 75221sec
    inet6 2001:19f0:5:5f99:5400:2ff:fe77:6666/64 scope global dynamic mngtmpaddr noprefixroute
       valid_lft 2591608sec preferred_lft 604408sec
    inet6 fe80::5400:2ff:fe77:6666/64 scope link
       valid_lft forever preferred_lft forever
```

You can see from this that I have an inet6 address on `eth0` with the address range `2001:19f0:5:5f99:5400:2ff:fe77:6666/64`.

You can insert this IPv6 address into your Docker daemon config, `/etc/docker/daemon.json`:

```
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:19f0:5:5f99:5400:2ff:fe77:6666/64"
}
```

Then restart Docker.

```console
$ systemctl reload docker
```

You may also want to enable IPv6 forwarding on your ipv6 networking address.

```console
$ echo "net.ipv6.conf.all.forwarding=1" >> "/etc/sysctl.conf"
$ sudo sysctl --system
```
