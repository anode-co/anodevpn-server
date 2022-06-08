import {
  ContextType,
  ServerConfigType,
  ComputedConfigType,
  MASK128,
  MASK32,
  IpVersion,
} from "../types";
import IpAddr from "ipaddr.js";

export const config: ServerConfigType = {
  ipv4: {
    allocSize: parseInt(process.env.CFG4_ALLOC_SIZE) || 32,
    networkSize: parseInt(process.env.CFG4_NETWORK_SIZE) || 0,
    prefix: process.env.CFG4_PREFIX || "10.66.0.0/16",
  },
  ipv6: {
    allocSize: parseInt(process.env.CFG6_ALLOC_SIZE) || 64,
    networkSize: parseInt(process.env.CFG6_NETWORK_SIZE) || 0,
    prefix: process.env.CFG6_PREFIX || "2c0f:f930:0002::/48",
  },
  serverPort: parseInt(process.env.SERVER_PORT) | 8099,
  dryrun: process.env.DRY_RUN.toLowerCase() === "true",
};

export function getIpVersionString(ipVersion: IpVersion) {
  let ipConfigVersionKey = "ipv4";
  if (ipVersion === IpVersion.IPv6) {
    ipConfigVersionKey = "ipv6";
  }
  return ipConfigVersionKey;
}

export function getComputedConfig(
  config: ServerConfigType
): ComputedConfigType {
  const computedConfig: ComputedConfigType = {
    ipv4: {
      numSlots: 0,
      baseAddress: BigInt(0),
    },
    ipv6: {
      numSlots: 0,
      baseAddress: BigInt(0),
    },
  };
  [IpVersion.IPv4, IpVersion.IPv6].forEach((ipVersion) => {
    const ipVersionKey = getIpVersionString(ipVersion);
    if (config[ipVersionKey]) {
      const ipConfig = config[ipVersionKey];
      computedConfig[ipVersionKey].numSlots = getAddressCount({
        prefix: ipConfig.prefix,
        ipAllocationRange: ipConfig.allocSize,
        addressWidth: 32,
        ipVersion,
      });
      const addressData = ipConfig.split("/");
      const addressPrefix = addressData[0];
      const addressRange = addressData[1];
      const baseAddress = BigInt(
        "0x" +
          Buffer.from(IpAddr.parse(addressPrefix).toByteArray()).toString("hex")
      );
      let mask = MASK32;
      if (ipVersion === IpVersion.IPv6) {
        mask = MASK128;
      }
      computedConfig[ipVersionKey].baseAddress =
        (mask ^ (mask >> BigInt(addressRange))) & baseAddress;
    }
  });
  if (
    computedConfig.ipv4.numSlots === 0 &&
    computedConfig.ipv6.numSlots === 0
  ) {
    throw new Error("No slots are available, check your config");
  }
  if (computedConfig.ipv4.numSlots !== computedConfig.ipv6.numSlots) {
    console.error(
      `${computedConfig.ipv4.numSlots} allocated for ipv4 but ${computedConfig.ipv6.numSlots} allocated for ipv6`
    );
    const min = Math.min(
      computedConfig.ipv4.numSlots,
      computedConfig.ipv4.numSlots
    );
    console.error(`We will only issue ${min} slots`);
    computedConfig.ipv4.numSlots = computedConfig.ipv4.numSlots = min;
  }
  console.log(computedConfig);
  return Object.freeze(computedConfig);
}

type AddressCountProps = {
  prefix: string;
  ipAllocationRange: number;
  addressWidth: number;
  ipVersion: string;
};

// TODO: describe how to use this function
// addressPrefix should look like: 24.23.222.0/24
export function getAddressCount({
  prefix,
  ipAllocationRange,
  addressWidth,
  ipVersion,
}: AddressCountProps): number {
  // convert the allocation range
  const allocationRange = ipAllocationRange || addressWidth;
  const addressPrefixData = prefix.split("/");
  const ipAddress = addressPrefixData[0];
  const pfx = parseInt(addressPrefixData[1]);
  if (isNaN(pfx)) {
    throw new Error(`prefix${ipVersion} is not in the form of address/prefix`);
  }
  if (pfx < 0 || pfx > addressWidth) {
    throw new Error(`prefix${ipVersion} is out of range`);
  }
  // throw if there's a problem
  IpAddr.parse(ipAddress);
  if (allocationRange < pfx - 4) {
    throw new Error(`prefix${ipVersion} is too small for alloc size`);
  }
  return Number(
    BigInt(2) ** BigInt(addressWidth - pfx - (addressWidth - allocationRange))
  );
}

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
