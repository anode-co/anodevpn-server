/*@flow*/
/* global BigInt */
const Fs = require('fs');
const Http = require('http');
const Crypto = require('crypto');

const IpAddr = require('ipaddr.js');
const Cjdns = require('cjdnsadmin');
const nThen = require('nthen');

const axios = require('axios');
const { exec } = require('child_process');
const lockfile = require('proper-lockfile');
const path = require('path');
const httpProxy = require('http-proxy');

/*::
const BigInt = (n:number|string)=>Number(n);
type NetConfig_t = {
    allocSize: number,
    networkSize: number,
    prefix: string,
}
type Config_t = {
    cfg6: void | NetConfig_t,
    cfg4: void | NetConfig_t,
    serverPort: number,
    dryrun: bool,
};
import type { IncomingMessage, ServerResponse } from 'http';
type ComputedConfig_t = {
    slots4: number,
    slots6: number,
    baseAddr6: number,
    baseAddr4: number,
};
type Lease_t = {
    s4: number,
    s6: number,
    to: number, // timeout milliseconds
};
type Db_t = {
    leases: {[string]:Lease_t},
    slotmap4: {[number]:number},
    slotmap6: {[number]:number},
}
type Context_t = {
    cfg: Config_t,
    db: Db_t,
    cc: ComputedConfig_t,
    mut: {
        externalConfigs: {[string]:number},
        lastSync: number,
        sessions: { [string]:{ conn: number } },
        cjdns: ?any,
        coordinatorPubkey: string,
    }
};
type CjdnsConn_t = {
  "error": string,
  "ip4Address": string,
  "ip4Alloc": number,
  "ip4Prefix": number,
  "ip6Address": string,
  "ip6Alloc": number,
  "ip6Prefix": number,
  "key": string,
  "outgoing": number,
  "txid": string,

  // hacks
  s4?: number,
  s6?: number,
  number: number,
};


type Session_t = {
  ctx: Context_t,
  req: IncomingMessage,
  res: ServerResponse,
  timeout: TimeoutID,
};
type Error_t = {
  code: number,
  error: string,
};
*/
const Config /*:Config_t*/ = require('./config.js');

const complete = (sess /*:Session_t*/, code /*:number*/, error /*:string|null*/, data) => {
    sess.res.setHeader('Content-Type', 'application/json');
    if (error) {
        console.error(`Request error ${code} - ${error}`);
        sess.res.statusCode = code;
        sess.res.end(JSON.stringify({
            status: "error",
            message: error,
        }, null, '\t'));
    } else {
        const s = JSON.stringify(data, (_, x) => {
            // $FlowFixMe - new fancy js stuff
            if (typeof x !== 'bigint') { return x; }
            return x.toString();
        }, '\t');
        console.error(`Request result ${code} - ${String(s)}`);
        sess.res.statusCode = code;
        sess.res.end(s);
    }
    clearTimeout(sess.timeout);
};

const MARK128 = BigInt(2)**BigInt(132);
const MASK128 = BigInt(2)**BigInt(128)-BigInt(1);
const MARK32 = BigInt(2)**BigInt(36);
const MASK32 = BigInt(0xffffffff);
const alloc4 = (ctx) => (ctx.cfg.cfg4 && ctx.cfg.cfg4.allocSize) || 32;
const alloc6 = (ctx) => (ctx.cfg.cfg6 && ctx.cfg.cfg6.allocSize) || 128;
const addrForSlot6 = (ctx, slot) => {
    return IpAddr.fromByteArray(
        Buffer.from(
            ( ctx.cc.baseAddr6 + (BigInt(slot) << BigInt(128 - alloc6(ctx))) + MARK128).toString(16),
            'hex'
        ).slice(1)
    ).toString();
};
const addrForSlot4 = (ctx, slot) => {
    return IpAddr.fromByteArray(
        Buffer.from(
            ( ctx.cc.baseAddr4 + (BigInt(slot) << BigInt(32 - alloc4(ctx))) + MARK32 ).toString(16),
            'hex'
        ).slice(1)
    ).toString();
};
const slotForAddr4 = (ctx, addrStr) => {
    const addr = BigInt('0x' + Buffer.from(IpAddr.parse(addrStr).toByteArray()).toString('hex'));
    return Number( (addr - ctx.cc.baseAddr4) >> BigInt(32 - alloc4(ctx)) );
};
const slotForAddr6 = (ctx, addrStr) => {
    const addr = BigInt('0x' + Buffer.from(IpAddr.parse(addrStr).toByteArray()).toString('hex'));
    return Number( (addr - ctx.cc.baseAddr6) >> BigInt(128 - alloc6(ctx)) );
};

const addLease = (ctx, pubkey, lease, then) => {
    if (!ctx.mut.cjdns) { return; }
    const cjdns = ctx.mut.cjdns;
    let ip6Prefix, ip6Alloc, ip6Address, ip4Prefix, ip4Alloc, ip4Address;
    if (lease.s4 > -1 && ctx.cfg.cfg4) {
        ip4Prefix = ctx.cfg.cfg4.networkSize;
        ip4Alloc = ctx.cfg.cfg4.allocSize;
        ip4Address = addrForSlot4(ctx, lease.s4);
    }
    if (lease.s6 > -1 && ctx.cfg.cfg6) {
        ip6Prefix = ctx.cfg.cfg6.networkSize;
        ip6Alloc = ctx.cfg.cfg6.allocSize;
        ip6Address = addrForSlot6(ctx, lease.s6);
    }
    console.error('addLease() IpTunnel_allowConnection',
        pubkey, ip6Prefix, ip6Alloc, ip6Address, ip4Prefix, ip4Alloc, ip4Address);
    if (ctx.cfg.dryrun) {
        return void then();
    }
    cjdns.IpTunnel_allowConnection(
        pubkey, ip6Prefix, ip6Alloc, ip6Address, ip4Prefix, ip4Alloc, ip4Address, (err, res) => {
            if (err) {
                console.error('addLease() IpTunnel_allowConnection',
                    pubkey, ip6Prefix, ip6Alloc, ip6Address, ip4Prefix, ip4Alloc, ip4Address, '->', err);
                then(err);
            } else if (res.error !== "none") {
                console.error('addLease() IpTunnel_allowConnection',
                    pubkey, ip6Prefix, ip6Alloc, ip6Address, ip4Prefix, ip4Alloc, ip4Address, '->', res);
                then(res);
            } else {
                ctx.mut.sessions[pubkey] = { conn: res.connection };
                then();
            }
        });
};

const now = () => +new Date();
const DAY_MS = 1000*60*60*24;

const syncSessions = (ctx, done) => {
    console.error('syncSessions() start');
    const fail = (w, err) => {
        w.abort();
        console.error("syncSessions() failed, trying in 3 seconds", err);
        setTimeout(()=>syncSessions(ctx, done), 3000);
    };
    let numbers;
    const connections /*:{[string]:CjdnsConn_t}*/ = {};
    nThen((w) => {
        if (!ctx.mut.cjdns) { return void fail(w, "cjdns missing"); }
        ctx.mut.cjdns.IpTunnel_listConnections(w((err, ret) => {
            if (err) { return void fail(w, err); }
            if (ret.error !== 'none') { return void fail(w, "cjdns replied " + ret.error); }
            numbers = ret.connections.map(Number);
        }));
    }).nThen((w) => {
        console.error(`syncSessions() Getting [${numbers.length}] connections...`);
        let nt = nThen;
        numbers.forEach((n) => {
            nt = nt((w) => {
                if (!ctx.mut.cjdns) { return void fail(w, "cjdns missing"); }
                ctx.mut.cjdns.IpTunnel_showConnection(n, w((err, ret) => {
                    if (err) { return void fail(w, err); }
                    if (ret.error !== 'none') { return void fail(w, "cjdns replied " + ret.error); }
                    if (ret.outgoing === 1) {
                        throw new Error("Cannot run a VPN server because this node is a VPN client " +
                            "with lease: " + JSON.stringify(ret, null, '\t'));
                    }
                    ret.number = n;
                    connections[n] = ret;
                    ctx.mut.sessions[ret.key] = { conn: n };
                }));
            }).nThen;
        });
        nt(w());
    }).nThen((w) => {
        const connByKey = {};
        const externalConfigs = {};
        for (const num in connections) {
            const conn = connections[num];
            connByKey[conn.key] = conn;
            const lease = ctx.db.leases[conn.key];
            if (conn.ip4Address) {
                conn.s4 = slotForAddr4(ctx, conn.ip4Address);
                // make sure we mark off these slots as used, even if they're allocated externally
                if (conn.s4 > -1 && conn.s4 < ctx.cc.slots4) {
                    ctx.db.slotmap4[conn.s4] = 1;
                }
            }
            if (conn.ip6Address) {
                conn.s6 = slotForAddr6(ctx, conn.ip6Address);
                if (conn.s6 > -1 && conn.s6 < ctx.cc.slots6) {
                    ctx.db.slotmap6[conn.s6] = 1;
                }
            }
            if (!lease) {
                console.error(`syncSessions() external ${conn.key} ${conn.ip4Address} ${conn.ip6Address} ${num}`);
                externalConfigs[conn.key] = 1;
            }
        }
        ctx.mut.externalConfigs = externalConfigs;
        const leasesNeeded = {};
        for (const key in ctx.db.leases) {
            const conn = connByKey[key];
            if (conn) {
                const lease = ctx.db.leases[key];
                console.error(`syncSessions() detected lease for ${key} at connection num ${conn.number}`);
                if (conn.ip4Address && ctx.cfg.cfg4) {
                    if (conn.ip4Alloc !== ctx.cfg.cfg4.allocSize) {
                        console.error(conn, ctx.cfg.cfg4.allocSize);
                        throw new Error("Entry exists with cjdns which has a different alloc size");
                    }
                    if (lease.s4 !== conn.s4) {
                        const oldAddr = addrForSlot4(ctx, lease.s4);
                        // Always trust cjdns rather than the db because cjdns is what's in practice
                        console.error(`syncSessions() Warning: change of address for ` +
                            `[${conn.key}] [${oldAddr}] -> [${conn.ip4Address}] [${conn.s4}] -> [${lease.s4}]`);
                        delete ctx.db.slotmap4[lease.s4];
                        lease.s4 = conn.s4;
                    }
                }
                if (conn.ip6Address && ctx.cfg.cfg6) {
                    if (conn.ip6Alloc !== ctx.cfg.cfg6.allocSize) {
                        console.error(conn, ctx.cfg.cfg6.allocSize);
                        throw new Error("Entry exists with cjdns which has a different alloc size");
                    }
                    if (lease.s6 !== conn.s6) {
                        const oldAddr = addrForSlot6(ctx, lease.s6);
                        console.error(`syncSessions() Warning: change of address for ` +
                            `[${conn.key}] [${oldAddr}] -> [${conn.ip6Address}] [${conn.s6}] -> [${lease.s6}]`);
                        delete ctx.db.slotmap6[lease.s6];
                        lease.s6 = conn.s6;
                    }
                }
            } else {
                console.error(`syncSessions() need lease for ${key}`);
                leasesNeeded[key] = ctx.db.leases[key];
            }
        }
        let nt = nThen;
        Object.keys(leasesNeeded).forEach((pubkey) => {
            nt = nt((w) => {
                if (!ctx.mut.cjdns) { return void fail(w, "cjdns missing"); }
                addLease(ctx, pubkey, leasesNeeded[pubkey], w());
            }).nThen;
        });
        nt(w());
    }).nThen((_) => {
        console.error('syncSessions() complete');
        ctx.mut.lastSync = now();
        done();
    });
};

// check if cjdns is up and running
const checkcjdns = (ctx, attemptNum, done) => {
    if (!ctx.mut.cjdns) {
        Cjdns.connect((err, cjdns) => {
            if (err) {
                console.error('checkcjdns()', err);
                setTimeout(() => checkcjdns(ctx, 0, done), 2000);
            } else {
                console.error('checkcjdns() cjdns connection established');
                ctx.mut.cjdns = cjdns;
                // We need a sync to occur asap
                ctx.mut.lastSync = 0;
                setTimeout(() => checkcjdns(ctx, 0, done), 100);
            }
        });
        return;
    }
    ctx.mut.cjdns.ping((err, ret) => {
        if (!err && ret.q === 'pong') {
            done();
        } else if (attemptNum > 5) {
            console.error('checkcjdns() cjdns connection lost');
            ctx.mut.cjdns = undefined;
            ctx.mut.sessions = {};
            checkcjdns(ctx, attemptNum + 1, done);
        } else {
            console.error('checkcjdns() no connection, retrying');
            setTimeout(() => checkcjdns(ctx, attemptNum + 1, done), 100);
        }
    });
};

const withCjdns = (sess, cb) => {
    if (sess.ctx.mut.cjdns) {
        cb(sess.ctx.mut.cjdns);
    } else {
        let i = 0;
        const again = () => {
            if (sess.ctx.mut.cjdns) {
                cb(sess.ctx.mut.cjdns);
            } else if (i < 5) {
                i++;
                setTimeout(again, 5000);
            } else {
                complete(sess, 500, "cjdns is not running");
            }
        };
        setTimeout(again, 1000);
    }
};

const readJson = (sess, then) => {
    const data = [];
    sess.req.on('data', (d) => data.push(d));
    sess.req.on('end', () => {
        let str = '';
        if (Buffer.isBuffer(typeof(data[0]))) {
            str = Buffer.concat(data).toString('utf8');
        } else {
            str = data.join('');
        }
        let o;
        try {
            o = JSON.parse(str);
        } catch (e) {
            return void complete(sess, 405, "could not parse json");
        }
        const auth = sess.req.headers['authorization'];
        if (auth && auth.indexOf('cjdns ') === 0) {
            const sig = auth.slice(6);
            const hash = Crypto.createHash('sha256').update(Buffer.from(str, 'utf8')).digest('base64');
            withCjdns(sess, (cjdns) => {
                cjdns.Sign_checkSig(sig, hash, (err, ret) => {
                    if (err) {
                        return void complete(sess, 500, "Sign_checksig error " + err);
                    } else if (ret.error === 'invalid signature') {
                        return void complete(sess, 403, "Sign_checksig invalid sig");
                    } else if (ret.error !== 'none') {
                        return void complete(sess, 500, "Sign_checksig error " + ret.error);
                    } else {
                        then(o, ret);
                    }
                });
            });
        } else {
            then(o);
        }
    });
};

const needAuth = (sess, cb) => {
    return (o, sig) => {
        if (!sig) {
            return void complete(sess, 403, "cjdns http signature required");
        } else if (!o.date || typeof(o.date) !== 'number') {
            return void complete(sess, 405, "date field required and must be a number");
        } else if (now() - +new Date(o.date*1000) > DAY_MS) {
            return void complete(sess, 405, "date is more than 1 day old");
        } else {
            cb(o, sig);
        }
    };
};


const storeDb = (ctx, then) => {
    Fs.writeFile('./db.json', JSON.stringify(ctx.db, null, '\t'), 'utf8', (err) => {
        if (err) { throw err; }
        then();
    });
};

const allocate = (sess, pubkey) => {
    let s4 = -1;
    if (sess.ctx.cc.slots4) {
        if (Object.keys(sess.ctx.db.slotmap4).length >= sess.ctx.cc.slots4) {
            return void complete(sess, 503, `IPv4 addresses exhausted`);
        }
        s4 = Math.floor(Math.random() * sess.ctx.cc.slots4);
        while (sess.ctx.db.slotmap4[s4]) { s4 = (s4 + 1) % sess.ctx.cc.slots4; }
        sess.ctx.db.slotmap4[s4] = 1;
    }
    let s6 = -1;
    if (sess.ctx.cc.slots6) {
        if (Object.keys(sess.ctx.db.slotmap6).length >= sess.ctx.cc.slots6) {
            return void complete(sess, 503, `IPv6 addresses exhausted`);
        }
        s6 = Math.floor(Math.random() * sess.ctx.cc.slots6);
        while (sess.ctx.db.slotmap6[s6]) { s6 = (s6 + 1) % sess.ctx.cc.slots6; }
        sess.ctx.db.slotmap6[s6] = 1;
    }
    const lease = sess.ctx.db.leases[pubkey] = { s4, s6, to: now() + DAY_MS };
    storeDb(sess.ctx, () => {
        addLease(sess.ctx, pubkey, lease, (err) => {
            if (err) {
                return void complete(sess, 500, `Failed to add lease ${String(err)}`);
            } else {
                return void complete(sess, 201, null, {
                    status: "success",
                    message: "allocated",
                    expiresAt: Math.floor(lease.to / 1000),
                });
            }
        });
    });
};

const PUBKEY = 'clientPublicKey';

const httpRequestAuth = (sess) => {
    readJson(sess, needAuth(sess, (o, sig) => {
        console.log("---- Authorization request ------");
        console.log(`from cjdns pubkey: ${o[PUBKEY]}`);
        const formattedDateTime = new Date(o.date).toLocaleString("en-US")
        console.log(`at datetime: ${formattedDateTime}`)

        if (!o[PUBKEY]) {
            return void complete(sess, 405, "expecting a cjdns public key");
        } else if (sig.pubkey !== o[PUBKEY] && sig.pubkey !== sess.ctx.mut.coordinatorPubkey) {
            return void complete(sess, 403,
                `request can only be made (signed) by either ` +
                `client (${o[PUBKEY]}) or coordinator (${sess.ctx.mut.coordinatorPubkey}) (signed by ${sig.pubkey})`);
        } else if (sess.ctx.mut.externalConfigs[o[PUBKEY]]) {
            return void complete(sess, 400, `cannot grant a lease because one was manually added`);
        } else {
            const l = sess.ctx.db.leases[o[PUBKEY]];
            console.error(`Request from ${o[PUBKEY]}`);
            if (l) {
                l.to = now() + DAY_MS;
                storeDb(sess.ctx, () => {
                    return void complete(sess, 200, null, {
                        status: "success",
                        message: "updated timeout",
                        expiresAt: Math.floor(l.to / 1000),
                    });
                });
            } else {
                console.error(`Allocating Request from ${o[PUBKEY]}`);
                allocate(sess, o[PUBKEY]);
            }
        }
    }));
};

const httpRequestPremium = (sess) => {
    console.log("---- Premium request ------");
    const { req, res } = sess;

    if (req.method !== 'POST') {
        return void complete(sess, 400, "Bad Request");
    }

    let body = '';
    req.on('data', (chunk) => {
        body += chunk;
    });

    req.on('end', () => {
        try {
            const request = JSON.parse(body);

            if (!request.ip) {
                return void complete(sess, 400, "Missing 'ip' property");
            }
            if (!request.address) {
                return void complete(sess, 400, "Missing 'address' property");
            }
            console.log(`from ip: ${request.ip}`);
            
            // Give Premium regardless of bcasttransaction success
            // The handler will drop client after a few minutes if the transaction is not confirmed
            givePremium(sess, request.ip);

            // Update clients file
            let clientFile = path.resolve(__dirname,"./clients.json");
            Fs.readFile(clientFile, 'utf8', (err, data) => {
                if (err) {
                    console.error(err);
                    return;
                }

                let parsedData;
                try {
                    parsedData = JSON.parse(data);
                    let clients = parsedData.clients;
                    let ipExists = false;
                    const currentTime = Date.now();
                    for (let i = 0; i < clients.length; i++) {
                        if (clients[i].ip === request.ip) { 
                            console.log(`Overwriting existing client information`);
                            ipExists = true;
                            clients[i].duration = 1; 
                            clients[i].time = currentTime;
                            clients[i].transaction = request.transaction;
                            clients[i].txid = ""; // Let premium_handler handle the broadcast transaction, by leaving this empty
                            clients[i].address = request.address;
                            break;
                        }
                    }
                    if (!ipExists) {
                        console.log(`Appending new client information`);
                        var newClient = { ip: request.ip, duration: 1, time: currentTime, transaction: request.transaction, address: request.address, txid: "" };
                        clients.push(newClient);
                    } 
                    // Write the updated data back to json
                    parsedData.clients = clients;
                    lockfile.lock(clientFile)
                    .then(() => { 
                        Fs.writeFile(clientFile, JSON.stringify(parsedData), 'utf8', (err) => {
                            if (err) {
                                console.error(err);
                                return;
                            }
                            console.log(`Updated ${clientFile}`);
                        });
                        return lockfile.unlock(clientFile);
                    });
                } catch (error) {
                    console.log('Error parsing JSON:', error);
                }
            });
        } catch (error) {
            console.error(`Error parsing JSON: ${error}`);
            return void complete(sess, 400, "Invalid JSON");
        }
    });
};

const givePremium = (sess, ip) => {
    const envVars = {
        PKTEER_IP: ip,
        PKTEER_PAID: 'true'
    };
    const envVarString = Object.entries(envVars).map(([key, value]) => `${key}=${value}`).join(' ');
    //-e "PKTEER_DURATION=$2" -e "PKTEER_CONN_TIME=$3"
    const command = `/server/monitor_cjdns.sh`;
    exec(`${envVarString} ${command}`, (err, stdout, stderr) => {
        if (err) {
            console.error(err);
            return;
        }

        // Handle the output of the handle_premium.js script if needed
        console.log(stdout);
        console.error(stderr);
        return void complete(sess, 200, null, 
        {
            status: "success",
            message: "Premium VPN granted"
        });
    });
}

const httpRequestPremiumAddress = (sess) => {
    console.log("---- Premium Address request ------");
    const { req, res } = sess;
    axios.post('http://localhost:8080/api/v1/wallet/address/create', {}, {
        headers: {
          'Content-Type': 'application/json'
        }
    })
    .then(response => {
        console.log('Response:', response.data);
        const modifiedResponse = {
            ...response.data,
            amount: parseInt(process.env.PKTEER_PREMIUM_PRICE, 10)
        };
        return void complete(sess, 200, null, modifiedResponse);
    })
    .catch(error => {
        console.error('Error:', error.message);
        return void complete(sess, 500, error.message);
    });
};

const httpReq = (ctx, req, res) => {
    console.error(`req ${req.method} ${req.url}`);
    const sess = {
        ctx,
        req,
        res,
        timeout: setTimeout(() => {
            console.error(`Request ${req.method} ${req.url} never completed`);
        }, 10000),
    };
    if (req.url === '/api/0.3/server/authorize/') {
        return void httpRequestAuth(sess);
    }
    if (req.url === '/api/0.4/server/premium/') {
        return void httpRequestPremium(sess);
    }
    if (req.url === '/api/0.4/server/premium/address/') {
        return void httpRequestPremiumAddress(sess);
    }
    if (req.url === '/metrics') {
        const target = 'http://localhost:9100';
        const prometheus = httpProxy.createProxyServer({});
        try {
            return prometheus.web(req, res, { target });
        } catch (error) {
            console.error('Error occurred while proxying request:', error);
            return void complete(sess, 500, "failed to proxy request");
        }
    }
    return void complete(sess, 404, "no such endpoint");
};

const getAddressCount = (prefix, alloc, addrWidth, t) => {
    alloc = alloc || addrWidth;
    const addrPfx = prefix.split('/');
    const pfx = Number(addrPfx[1]);
    if (isNaN(pfx)) { throw new Error(`prefix${t} is not in the form of address/prefix`); }
    if (pfx < 0 || pfx > addrWidth) { throw new Error(`prefix${t} is out of range`); }
    // throw if there's a problem
    IpAddr.parse(addrPfx[0]);
    if (alloc < pfx - 4) { throw new Error(`prefix${t} is too small for alloc size`); }
    return Number( BigInt(2)**BigInt((addrWidth-pfx) - (addrWidth-alloc)) );
};
const computedConfig = (cfg) /*:ComputedConfig_t*/ => {
    const out = {
        slots6: 0,
        slots4: 0,
        baseAddr6: BigInt(0),
        baseAddr4: BigInt(0),
    };
    if (cfg.cfg6) {
        const cfg6 = cfg.cfg6;
        out.slots6 = getAddressCount(cfg6.prefix, cfg6.allocSize, 128, '6');
        const addrPfx = cfg6.prefix.split('/');
        const baseAddr6 =
            BigInt('0x' + Buffer.from(IpAddr.parse(addrPfx[0]).toByteArray()).toString('hex'));
        out.baseAddr6 = (MASK128 ^ (MASK128 >> BigInt(addrPfx[1]))) & baseAddr6;
    }
    if (cfg.cfg4) {
        const cfg4 = cfg.cfg4;
        out.slots4 = getAddressCount(cfg4.prefix, cfg4.allocSize, 32, '4');
        const addrPfx = cfg4.prefix.split('/');
        const baseAddr4 =
            BigInt('0x' + Buffer.from(IpAddr.parse(addrPfx[0]).toByteArray()).toString('hex'));
        out.baseAddr4 = (MASK32 ^ (MASK32 >> BigInt(addrPfx[1]))) & baseAddr4;
    }
    if (out.slots4 === out.slots6) {
        if (out.slots4 === 0) {
            throw new Error("No slots are available, check your config");
        }
    } else if (out.slots4 > 0 && out.slots6 > 0) {
        console.error(`slots4 is ${out.slots4} but slots6 is ${out.slots6}`);
        const min = Math.min(out.slots4, out.slots6);
        console.error(`We will only issue ${min} slots`);
        out.slots4 = out.slots6 = min;
    }
    console.log(out);
    return Object.freeze(out);
};

const cleanup = (ctx /*:Context_t*/, done) => {
    console.error('cleanup() start');
    const fail = (w, err) => {
        w.abort();
        console.error("cleanup failed, trying in 3 seconds", err);
        setTimeout(()=>cleanup(ctx, done), 3000);
    };
    const t = now();
    const toDelete = [];
    for (const pubkey in ctx.db.leases) {
        const lease = ctx.db.leases[pubkey];
        if (lease.to > t) { continue; }
        toDelete.push({ pubkey, lease });
    }
    let nt = nThen;
    toDelete.forEach((td) => {
        nt = nt((w) => {
            const sn = ctx.mut.sessions[td.pubkey];
            if (!ctx.mut.cjdns) {
                return void fail(w, "lost cjdns");
            } else if (!sn) {
                console.error('No known session for ' + td.pubkey);
            } else {
                const cjdns = ctx.mut.cjdns;
                console.error(`cleanup() IpTunnel_removeConnection(${sn.conn})`);
                if (ctx.cfg.dryrun) {
                    delete ctx.mut.sessions[td.pubkey];
                } else {
                    cjdns.IpTunnel_removeConnection(Number(sn.conn), w((err, ret) => {
                        if (err) { return void fail(w, err); }
                        if (ret.error !== 'none') { return void fail(w, "cjdns replied " + ret.error); }
                        delete ctx.mut.sessions[td.pubkey];
                    }));
                }
            }
        }).nThen;
    });
    nt((w) => {
        for (const d of toDelete) {
            console.error('cleanup() drop ' + d.pubkey);
            if (d.lease.s4) { delete ctx.db.slotmap4[d.lease.s4]; }
            if (d.lease.s6) { delete ctx.db.slotmap6[d.lease.s6]; }
            delete ctx.db.leases[d.pubkey];
        }
        storeDb(ctx, w());
    }).nThen((_) => {
        console.error('cleanup() complete');
        done();
    });
};

const main = () => {
    let db = {
        leases: {},
        slotmap4: {},
        slotmap6: {},
    };
    let ctx;
    nThen((w) => {
        Fs.readFile('./db.json', 'utf8', w((err, ret) => {
            if (err) {
                if (err.code === 'ENOENT') { return; }
                throw err;
            }
            db = JSON.parse(ret);
        }));
    }).nThen((w) => {
        ctx = Object.freeze({
            cfg: Config,
            db,
            cc: computedConfig(Config),
            externalConfigs: {},
            mut: {
                externalConfigs: {},
                lastSync: 0,
                sessions: {},
                cjdns: undefined,
                coordinatorPubkey: '929cwrjn11muk4cs5pwkdc5f56hu475wrlhq90pb9g38pp447640.k',
            },
        });
    }).nThen((w) => {
        checkcjdns(ctx, 0, w());
    }).nThen((w) => {
        syncSessions(ctx, w());
    }).nThen((w) => {
        cleanup(ctx, w());
    }).nThen((w) => {
        // We need to keep checking even if we get stuck in a syncSessions or cleanup
        const checkLoop = () => checkcjdns(ctx, 0, () => setTimeout(checkLoop, 10000));
        checkLoop();

        let lastClean = 0;
        const again = () => {
            nThen((w) => {
                if (now() - ctx.mut.lastSync < 36000000) { return; }
                syncSessions(ctx, w());
            }).nThen((w) => {
                if (now() - lastClean < 600000) { return; }
                cleanup(ctx, w(() => { lastClean = now(); }));
            }).nThen((_) => {
                setTimeout(again, 10000);
            });
        };
        setTimeout(again, 10000);

        Http.createServer((req, res) => httpReq(ctx, req, res)).listen(Config.serverPort);
    });
};
main();
