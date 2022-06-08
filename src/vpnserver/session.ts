import {
  ContextType,
  LeaseSettingForIpType,
  LeaseType,
  CjdnsConnectionType,
  IpVersion,
} from "../types";
import { getLease, addLease, getLeaseKeys } from "./leaseManager";
import {
  setSlots,
  removeSlot,
  getSlotForAddress,
  getAddressForSlot,
} from "./slot";
import { getIpVersionString } from "./config";

type SyncSessionsProps = {
  context: ContextType;
};

// FIXME: fix async/await in loops
export const syncSessions = async ({
  context,
}: SyncSessionsProps): Promise<void> => {
  console.error("syncSessions() start");
  //   const fail = (w, err) => {
  //     w.abort();
  //     console.error("syncSessions() failed, trying in 3 seconds", err);
  //     setTimeout(() => syncSessions({ context }), 3000);
  //   };
  let numbers: string[]; // TODO: verify that this is the correct type
  const cjdns = context.mut.cjdns;
  return new Promise<void>(async (resolve, reject) => {
    if (!context.mut.cjdns) {
      throw new Error("cjdns is missing");
    }
    // get connections
    const listConnectionsResponse = await cjdns.IpTunnel_listConnections();
    if (listConnectionsResponse.err !== "none") {
      throw new Error(`cjdns replied: ${listConnectionsResponse.error}`);
    }
    numbers = listConnectionsResponse.connections.map(Number);
    console.error(`syncSessions() Getting [${numbers.length}] connections...`);

    const connections: { [number: string]: CjdnsConnectionType } = {};
    const connectionNumberKeyLookup: { [key: string]: string } = {};
    // store connection data
    numbers.forEach(async (number: string) => {
      if (!cjdns) {
        throw new Error("cjdns is missing");
      }
      const connectionResponse = await cjdns.IpTunnel_showConnection(number);
      // format response
      const connection: CjdnsConnectionType = {
        error: connectionResponse.err,
        ipv4: {
          address: connectionResponse.ipv4Address,
          alloc: connectionResponse.ipv4Alloc,
          prefix: connectionResponse.ipv4Prefix,
        } as LeaseSettingForIpType,
        ipv6: {
          address: connectionResponse.ipv6Address,
          alloc: connectionResponse.ipv6Alloc,
          prefix: connectionResponse.ip6Prefix,
        } as LeaseSettingForIpType,
        key: connectionResponse.key,
        outgoing: connectionResponse.outgoing,
        txid: connectionResponse.txid,
        number: number,
      };
      connections[number] = connection;
      connectionNumberKeyLookup[connectionResponse.key] = number;
      context.mut.sessions[connectionResponse.key] = { conn: number };
    });

    const externalConfigs = {};
    // add slots to database
    for (const number in connections) {
      const connection = connections[number];
      const lease = getLease({ context, publicKey: connection.key });
      [IpVersion.IPv4, IpVersion.IPv6].forEach((ipVersion) => {
        let ipVersionKey = getIpVersionString(ipVersion);
        if (connection[ipVersionKey].address) {
          connection[ipVersionKey].numSlots = getSlotForAddress({
            context,
            ipAddress: connection[ipVersionKey].address,
            ipVersion,
          });
          if (
            connection[ipVersionKey].numSlots > -1 &&
            connection[ipVersionKey].numSlots <
              context.cc[ipVersionKey].numSlots
          ) {
            // add to database
            setSlots({
              context,
              ipVersion,
              publicKey: `${connection[ipVersionKey].numSlots}`,
              number: 1,
            });
          }
        }
        if (!lease) {
          console.error(
            `syncSessions() external ${connection.key} ${connection.ipv4.address} ${connection.ipv6.address} ${number}`
          );
          externalConfigs[connection.key] = 1;
        }
      });
    }

    context.mut.externalConfigs = externalConfigs;
    const leaseKeys = await getLeaseKeys({ context });
    const leasesNeeded: { [key: string]: LeaseType } = {};
    leaseKeys.forEach(async (key: string) => {
      const number = connectionNumberKeyLookup[key];
      // move to next key if no number found
      if (!number) {
        return;
      }
      const connection = connections[number];
      if (!connection) {
        console.error(`syncSessions() need lease for ${key}`);
        leasesNeeded[key] = context.db.leases[key];
        return;
      }
      const lease = await getLease({ context, publicKey: connection.key });
      console.error(
        `syncSessions() detected lease for ${key} at connection num ${connection.number}`
      );
      [IpVersion.IPv4, IpVersion.IPv6].forEach(async (ipVersion) => {
        const ipVersionKey = getIpVersionString(ipVersion);
        if (connection[ipVersionKey].address && context.cfg[ipVersionKey]) {
          if (
            connection[ipVersionKey].alloc !==
            context.cfg[ipVersionKey].allocSize
          ) {
            console.error(connection, context.cfg[ipVersionKey].allocSize);
            throw new Error(
              "Entry exists with cjdns which has a different alloc size"
            );
          }
          if (lease[ipVersion].numSlots !== connection[ipVersionKey].numSlots) {
            const oldAddr = getAddressForSlot({
              context,
              slot: lease[ipVersionKey].numSlots,
              ipVersion,
            });
            // Always trust cjdns rather than the db because cjdns is what's in practice
            console.error(
              `syncSessions() Warning: change of address for [${connection.key}] [${oldAddr}] -> [${connection[ipVersionKey].address}] [${connection[ipVersionKey].numSlots}] -> [${lease[ipVersion].numSlots}]`
            );
            await removeSlot({
              context,
              publicKey: lease[ipVersionKey].numSlots,
              ipVersion,
            });
            lease[ipVersionKey].numSlots = connection[ipVersionKey].numSlots;
          }
        }
      });
    });

    for (const publicKey in leasesNeeded) {
      const leaseNeededForPublicKey = leasesNeeded[publicKey];
      await addLease({ context, publicKey, lease: leaseNeededForPublicKey });
    }
    context.mut.lastSync = new Date();
    resolve();
  });
};
