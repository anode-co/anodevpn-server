import { getIpVersionString } from "./getComputedConfig";
import { ContextType, IpVersion, LeaseType } from "./types";
import { useDatabase } from "./useDatabase";
const { removeSlot, removeLease, saveDatabase } = useDatabase();

export const pruneLeases = async ({ context }: { context: ContextType }) => {
  console.error("cleanup() start");
  const now = new Date();
  const expiredLeases: { publicKey: string; lease: LeaseType }[] = [];
  for (const publicKey in context.db.leases) {
    const lease = context.db.leases[publicKey];
    if (lease.expiration > now) {
      continue;
    }
    expiredLeases.push({ publicKey, lease });
  }
  // FIXME: fix async/await in loops
  expiredLeases.forEach(async ({ publicKey, lease }) => {
    const session = context.mut.sessions[publicKey];
    if (!context.mut.cjdns) {
      throw new Error("cjdns is missing");
    }
    if (!session) {
      console.error(`No known session for ${publicKey}`);
      // continue;
    } else {
      const cjdns = context.mut.cjdns;
      console.error(`cleanup() IpTunnel_removeConnection(${session.conn})`);
      if (!context.cfg.dryrun) {
        const response = await cjdns.IpTunnel_removeConnection(session.conn);
        if (response.err !== "none") {
          throw new Error(`cjdns replied ${response.error}`);
        }
      }
      delete context.mut.sessions[publicKey];
    }
  });
  // NOTE: why is this a separate loop?
  expiredLeases.forEach(({ publicKey, lease }) => {
    console.error("cleanup() drop " + publicKey);
    [IpVersion.IPv4, IpVersion.IPv6].forEach((ipVersion) => {
      const ipVersionKey = getIpVersionString(ipVersion);
      if (lease[ipVersionKey].numSlots) {
        removeSlot({ context, publicKey, ipVersion });
      }
      removeLease({ context, publicKey });
    });
  });
  saveDatabase({ context });
  console.error("cleanup() done");
};
