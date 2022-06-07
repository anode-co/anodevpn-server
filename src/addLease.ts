import {
  ContextType,
  LeaseType,
  LeaseSettingsType,
  IpVersion,
  MARK128,
  MARK32,
  LeaseSettingForIpType,
} from "./types";
import IpAddr from "ipaddr.js";
import { useCjdns } from "./useCjdns";
import { getIpVersionString } from "./getComputedConfig";
const { cjdns } = useCjdns();

type AddLeaseProps = {
  context: ContextType;
  publicKey: string;
  lease: LeaseType;
};

export const getAddressForSlot = ({
  context,
  slot,
  ipVersion,
}: {
  context: ContextType;
  slot: number;
  ipVersion: IpVersion;
}) => {
  const ipVersionKey = getIpVersionString(ipVersion);
  let allocationMax = 32;
  let mark = MARK32;
  if (ipVersion === IpVersion.IPv6) {
    allocationMax = 128;
    mark = MARK128;
  }
  const str = (
    context.cc[ipVersion].baseAddress +
    (BigInt(slot) <<
      BigInt(allocationMax - getAllocationSize({ context, ipVersion }))) +
    mark
  ).toString(16);
  const byteArray = Array.from(Buffer.from(str, "hex").slice(1));
  return IpAddr.fromByteArray(byteArray).toString();
};

export const getAllocationSize = ({
  context,
  ipVersion,
}: {
  context: ContextType;
  ipVersion: IpVersion;
}): number => {
  let allocationMax = 32;
  let ipConfigVersionKey = "cfg4";
  if (ipVersion === IpVersion.IPv6) {
    allocationMax = 128;
    ipConfigVersionKey = "cfg6";
  }
  return context.cfg[ipConfigVersionKey]?.allocSize || allocationMax;
};
export const getSlotForAddress = ({
  context,
  ipAddress,
  ipVersion,
}: {
  context: ContextType;
  ipAddress: string;
  ipVersion: IpVersion;
}) => {
  let allocationCap = 32;
  let ipVersionKey = "ipv4";
  if (ipVersion === IpVersion.IPv6) {
    allocationCap = 128;
    ipVersionKey = "ipv6";
  }
  let allocationSize = getAllocationSize({ context, ipVersion });
  const address = BigInt(
    "0x" + Buffer.from(IpAddr.parse(ipAddress).toByteArray()).toString("hex")
  );
  return Number(
    (address - context.cc[ipVersionKey].baseAddress) >> BigInt(allocationSize)
  );
};

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
