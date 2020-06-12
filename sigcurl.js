const Https = require('https');
const Http = require('http');
const Crypto = require('crypto');

const Cjdnsadmin = require('cjdnsadmin');
const Minimist = require('minimist');

const METHODS = ['POST','GET','PUT','DELETE','OPTIONS'];

const usage = () => {
    console.error('Usage: node sigcurl OPTIONS <url>');
    console.error('     -H <header>:<value>  # Add a header');
    console.error('     -X <method>          # Specify the method');
    console.error('     -d <content>         # Content to post');
};

const postReq = (h, options, data) => {
    console.error(`> ${options.method} ${options.path}`);
    console.error(`> Host: ${options.host}`);
    for (const h in options.headers) {
        console.error(`> ${h}: ${options.headers[h]}`);
    }
    console.error(`>`);
    h.request(options, (res) => {
        console.error(`< ${res.statusCode} ${res.statusMessage}`);
        for (const h in res.headers) {
            console.error(`< ${h}: ${res.headers[h]}`);
        }
        console.error(`<`);
        const data = [];
        res.on('data', (d) => data.push(d));
        res.on('end', () => {
            console.log(data.join(''));
        });
    }).end(Buffer.from(data, 'utf8'));
};

const main = (argv) => {
    const m = Minimist(argv);
    const url = m._.pop();
    if (!/^http(s)?:\/\//.test(url)) {
        console.log(url);
        return void usage();
    }
    const path = url.replace(/^http(s)?:\/\/[^\/]*(\/)?/, '/');
    if (path === url) { throw new Error(`unexpected url ${url}`); }
    let port = 80;
    if (url.indexOf('https://') === 0) { port = 443; }
    let host = url.replace(/^http(s)?:\/\//, '').replace(path, '');
    if (host.indexOf(':') > -1) {
        port = host.split(':')[1];
        host = host.split(':')[0];
    }
    const data = m.d || '';
    const method = (m.X || (data ? 'POST' : 'GET')).toUpperCase();
    if (METHODS.indexOf(method) === -1) {
        throw new Error(`Requrest method must be one of ${METHODS}, not ${method}`);
    }
    const hmap = {
        'User-Agent': 'anodevpn-sigcurl',
        'Accept': '*/*',
    };
    let headers = m.H;
    if (typeof(headers) === 'string') { headers = [headers]; }
    if (headers) {
        for (const header of headers) {
            if (header.indexOf(':') === -1) {
                throw new Error(`Header [${header}] must have a : in it`);
            }
            hmap[header.slice(0, header.indexOf(':'))] = header.slice(header.indexOf(':')+1).trim();
        }
    }

    const options = {
        headers: hmap,
        host,
        method,
        path,
        port,
    };
    const h = (url.indexOf('https://') === 0) ? Https : Http;
    console.error(port);
    Cjdnsadmin.connect((err, cjdns) => {
        if (err) {
            throw err;
        }
        const hash = Crypto.createHash('sha256').update(Buffer.from(data, 'utf8')).digest('base64');
        cjdns.Sign_sign(hash, (err, ret) => {
            if (err) { throw err; }
            hmap['Authorization'] = 'cjdns ' + ret.signature;
            cjdns.disconnect();
            postReq(h, options, data);
        });
    });
};
main(process.argv);