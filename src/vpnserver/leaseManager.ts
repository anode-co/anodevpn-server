import {
  ContextType,
  LeaseType,
  LeaseSettingsType,
  IpVersion,
  LeaseSettingForIpType,
} from "../types";
import { getIpVersionString } from "./config";
import { removeSlot, getAddressForSlot } from "./slot";
import { prisma } from "../database/prisma";

type AddLeaseProps = {
  context: ContextType;
  publicKey: string;
  lease: LeaseType;
};

// FIXME: Use this method:
// https://github.com/anode-co/anodevpn-server/blob/c3a798122895b9349b0b081e038e805c5f0563b7/index.js#L404
export const allocateLease = ({
  context,
  publicKey,
}: {
  context: ContextType;
  publicKey: string;
}) => {};

export const addLease = async ({
  context,
  publicKey,
  lease,
}: AddLeaseProps) => {
  if (!context.mut.cjdns) {
    throw new Error("cjdns missing");
  }
  const cjdns = context.mut.cjdns;
  // let ip6Prefix, ip6Alloc, ip6Address, ip4Prefix, ip4Alloc, ip4Address;
  const leaseSettings: LeaseSettingsType = {
    ipv4: {
      prefix: undefined,
      alloc: undefined,
      address: undefined,
    } as LeaseSettingForIpType,
    ipv6: {
      prefix: undefined,
      alloc: undefined,
      address: undefined,
    } as LeaseSettingForIpType,
  }[(IpVersion.IPv6, IpVersion.IPv4)].forEach((ipVersion) => {
    const ipVersionKey = getIpVersionString(ipVersion);
    if (lease[ipVersionKey].numSlots > -1 && context.cfg[ipVersionKey]) {
      leaseSettings[ipVersionKey].prefix = context.cfg[ipVersionKey].alloc;
      leaseSettings[ipVersionKey].alloc = context.cfg[ipVersionKey].allocSize;
      leaseSettings[ipVersionKey].address = getAddressForSlot({
        context,
        slot: lease[ipVersionKey].numSlots,
        ipVersion,
      });
    }
  });
  console.error(
    "addLease() IpTunnel_allowConnection",
    publicKey,
    leaseSettings.ipv6.prefix,
    leaseSettings.ipv6.alloc,
    leaseSettings.ipv6.address,
    leaseSettings.ipv4.prefix,
    leaseSettings.ipv4.alloc,
    leaseSettings.ipv4.address
  );
  if (context.cfg.dryrun) {
    return;
  }
  try {
    const response = await cjdns.IpTunnel_allowConnection(
      publicKey,
      leaseSettings.ipv6.prefix,
      leaseSettings.ipv6.alloc,
      leaseSettings.ipv6.address,
      leaseSettings.ipv4.prefix,
      leaseSettings.ipv4.alloc,
      leaseSettings.ipv4.address
    );
    if (response.error !== "none") {
      console.error(
        "addLease() IpTunnel_allowConnection",
        publicKey,
        leaseSettings.ipv6.prefix,
        leaseSettings.ipv6.alloc,
        leaseSettings.ipv6.address,
        leaseSettings.ipv4.prefix,
        leaseSettings.ipv4.alloc,
        leaseSettings.ipv4.address,
        "->",
        response
      );
      // TODO: format as leaseType?
      return response;
    }
    context.mut.sessions[publicKey] = { conn: response.connection };
  } catch (err) {
    console.error(
      "addLease() IpTunnel_allowConnection",
      publicKey,
      leaseSettings.ipv6.prefix,
      leaseSettings.ipv6.alloc,
      leaseSettings.ipv6.address,
      leaseSettings.ipv4.prefix,
      leaseSettings.ipv4.alloc,
      leaseSettings.ipv4.address,
      "->",
      err
    );
  }
};

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
  // saveDatabase({ context });
  console.error("cleanup() done");
};

export const getLease = async ({
  context,
  publicKey,
}: {
  context: ContextType;
  publicKey: string;
}) => {
  const lease = await prisma.lease.findUnique({
    where: { publicKey },
  });
  return lease;
};

export const removeLease = async ({
  context,
  publicKey,
}: {
  context: ContextType;
  publicKey: string;
}) => {
  await prisma.lease.delete({
    where: { publicKey },
  });
};

export const getLeaseKeys = async ({ context }: { context: ContextType }) => {
  const leases = await prisma.lease.findMany();
  const publicKeys = [];
  leases.forEach((lease) => {
    publicKeys.push(lease.publicKey);
  });
  return Object.keys(context.db.leases);
};
