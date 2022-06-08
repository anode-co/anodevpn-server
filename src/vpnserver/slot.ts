import { ContextType, IpVersion, MARK128, MARK32 } from "../types";
import IpAddr from "ipaddr.js";
import { getIpVersionString, getAllocationSize } from "./config";
import { prisma } from "../database/prisma";

export const setSlots = async ({
  context,
  ipVersion,
  publicKey,
  number,
}: {
  context: ContextType;
  ipVersion: IpVersion;
  publicKey: string;
  number: number;
}) => {
  const ipVersionString = getIpVersionString(ipVersion);
  // context.db.slots[ipVersionKey][publicKey] = numSlots;
  await prisma.slot.create({
    data: {
      publicKey,
      ipVersion: ipVersionString,
      number,
    },
  });
};

export const removeSlot = async ({
  context,
  publicKey,
  ipVersion,
}: {
  context: ContextType;
  publicKey: string;
  ipVersion: IpVersion;
}) => {
  // const ipVersionKey = getIpVersionString(ipVersion);
  // delete context.db.slots[ipVersionKey][publicKey];
  const ipVersionString = getIpVersionString(ipVersion);
  await prisma.slot.create({
    data: {
      publicKey,
      ipVersion: ipVersionString,
      number: 0,
    },
  });
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
