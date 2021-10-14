# Anode VPN server

## Install:

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
