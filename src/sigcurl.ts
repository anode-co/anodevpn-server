import Https from "https";
import Http from "http";
import crypto from "crypto";

import Cjdnsadmin from "cjdnsadmin";
import parseArgs from "minimist";

const METHODS = ["POST", "GET", "PUT", "DELETE", "OPTIONS"];

const printHelp = () => {
  console.error("Usage: node sigcurl OPTIONS <url>");
  console.error("     -H <header>:<value>  # Add a header");
  console.error("     -X <method>          # Specify the method");
  console.error("     -d <content>         # Content to post");
};

const handlePostRequest = (headers, options, data) => {
  console.error(`> ${options.method} ${options.path}`);
  console.error(`> Host: ${options.host}`);
  for (const h in options.headers) {
    console.error(`> ${h}: ${options.headers[h]}`);
  }
  console.error(`>`);
  headers
    .request(options, (response) => {
      console.error(`< ${response.statusCode} ${response.statusMessage}`);
      for (const header in response.headers) {
        console.error(`< ${header}: ${response.headers[header]}`);
      }
      console.error(`<`);
      const data = [];
      response.on("data", (datum) => data.push(datum));
      response.on("end", () => {
        console.log(data.join(""));
      });
    })
    .end(Buffer.from(data, "utf8"));
};

const main = (argv: string[]) => {
  const arguments = parseArgs(argv);
  const url = arguments._.pop();
  const data = arguments.d || "";
  const method = (arguments.X || (data ? "POST" : "GET")).toUpperCase();
  let headers = arguments.H;

  // process url
  if (!/^http(s)?:\/\//.test(url)) {
    console.log(url);
    printHelp();
    return;
  }
  const path = url.replace(/^http(s)?:\/\/[^\/]*(\/)?/, "/");
  if (path === url) {
    throw new Error(`unexpected url ${url}`);
  }

  // process port and host
  let port = 80;
  if (url.indexOf("https://") === 0) {
    port = 443;
  }
  let host = url.replace(/^http(s)?:\/\//, "").replace(path, "");
  if (host.indexOf(":") > -1) {
    const hostParts = host.split(":");
    host = hostParts[0];
    port = parseInt(hostParts[1]);
  }

  // process method
  if (METHODS.indexOf(method) === -1) {
    throw new Error(`Requrest method must be one of ${METHODS}, not ${method}`);
  }
  const hmap = {
    "User-Agent": "anodevpn-sigcurl",
    Accept: "*/*",
  };

  // process headers
  if (typeof headers === "string") {
    headers = [headers];
  }
  if (headers) {
    for (const header of headers) {
      if (header.indexOf(":") === -1) {
        throw new Error(`Header [${header}] must have a : in it`);
      }
      hmap[header.slice(0, header.indexOf(":"))] = header
        .slice(header.indexOf(":") + 1)
        .trim();
    }
  }

  const options = {
    headers: hmap,
    host,
    method,
    path,
    port,
  };
  const h = url.indexOf("https://") === 0 ? Https : Http;
  Cjdnsadmin.connect((err, cjdns) => {
    if (err) {
      throw err;
    }
    const hash = crypto
      .createHash("sha256")
      .update(Buffer.from(data, "utf8"))
      .digest("base64");
    cjdns.Sign_sign(hash, (err, ret) => {
      if (err) {
        throw err;
      }
      hmap["Authorization"] = `cjdns  ${ret.signature}`;
      cjdns.disconnect();
      handlePostRequest(h, options, data);
    });
  });
};
main(process.argv);
