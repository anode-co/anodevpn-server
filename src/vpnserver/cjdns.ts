import Cjdns from "cjdnsadmin";
import { ContextType } from "../types";

export type CheckCjdnsProps = {
  attemptNumber: number;
};

export const checkCjdns = (
  context: ContextType,
  options?: CheckCjdnsProps
): Promise<void> => {
  const maxPingAttempts = 5;
  let pingAttempts = 0;
  if (options?.attemptNumber) {
    pingAttempts = options.attemptNumber;
  }
  // if cjdns isn't running, try to start it.
  return new Promise<void>(async (resolve, reject) => {
    if (!context.mut.cjdns) {
      Cjdns.connect((err: any, cjdns: any) => {
        if (err) {
          console.error("checkcjdns()", err);
          setTimeout(() => checkCjdns(context), 2000);
        } else {
          console.error("checkcjdns() cjdns connection established");
          // context.mut.cjdns = cjdns;
          // We need a sync to occur asap
          // context.mut.lastSync = 0;
          // setTimeout(() => checkCjdns(context), 100);
          resolve();
        }
      });
      return;
    }
    context.mut.cjdns.ping((err: any, ret: { q: string }) => {
      if (!err && ret.q === "pong") {
        resolve();
      } else if (pingAttempts > maxPingAttempts) {
        console.error("checkcjdns() cjdns connection lost");
        context.mut.cjdns = undefined;
        context.mut.sessions = {};
        checkCjdns(context, { attemptNumber: pingAttempts + 1 });
      } else {
        console.error("checkcjdns() no connection, retrying");
        setTimeout(
          () =>
            checkCjdns(context, {
              attemptNumber: pingAttempts + 1,
            }),
          100
        );
      }
    });
  });
};

// create an async/await wrapper for cjdnsadmin
const cjdns = () => {
  const IpTunnel_listConnections = async () => {
    return new Promise((resolve, reject) => {
      //@ts-expect-error no types for Cjdns
      Cjdns.IpTunnel_listConnections(
        (err: any, response: { error?: string }) => {
          if (err) {
            reject(err);
          }
          if (response.error !== "none") {
            reject(`cjdns replied: ${response.error}`);
          }
          resolve(response);
        }
      );
    });
  };
  const IpTunnel_showConnection = async (number: string) => {
    return new Promise((resolve, reject) => {
      //@ts-expect-error no types for Cjdns
      Cjdns.IpTunnel_showConnection(
        number,
        (err: any, response: { error?: string; outgoing?: number }) => {
          if (err) {
            reject(err);
          }
          if (response.error !== "none") {
            reject(`cjdns replied: ${response.error}`);
          }
          if (response.outgoing === 1) {
            const lease = JSON.stringify(response, null, "\t");
            throw new Error(
              `Cannot run a VPN server because this node is a VPN client with lease ${lease}`
            );
          }
          resolve(response);
        }
      );
    });
  };
  const IpTunnel_allowConnection = async (
    publicKey: string,
    ipv6Prefix: string,
    ipv6Alloc: string,
    ipv6Address: string,
    ipv4Prefix: string,
    ipv4Alloc: string,
    ipv4Address: string
  ) => {
    return new Promise((resolve, reject) => {
      //@ts-expect-error no types for Cjdns
      Cjdns.IpTunnel_allowConnection(
        publicKey,
        ipv6Prefix,
        ipv6Alloc,
        ipv6Address,
        ipv4Prefix,
        ipv4Alloc,
        ipv4Address,
        (err: any, response: { error?: string }) => {
          if (err) {
            console.error(
              "addLease() IpTunnel_allowConnection",
              publicKey,
              ipv6Prefix,
              ipv6Alloc,
              ipv6Address,
              ipv4Prefix,
              ipv4Alloc,
              ipv4Address,
              "->",
              err
            );
            reject(err);
          } else if (response.error !== "none") {
            console.error(
              "addLease() IpTunnel_allowConnection",
              publicKey,
              ipv6Prefix,
              ipv6Alloc,
              ipv6Address,
              ipv4Prefix,
              ipv4Alloc,
              ipv4Address,
              "->",
              response
            );
            reject(response);
          } else {
            resolve(response);
          }
        }
      );
    });
  };

  return {
    IpTunnel_listConnections,
    IpTunnel_showConnection,
    IpTunnel_allowConnection,
  };
};
