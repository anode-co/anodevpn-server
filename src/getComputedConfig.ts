import {
  ServerConfigType,
  ComputedConfigType,
  MASK128,
  MASK32,
  IpVersion,
} from "./types";
import { getAddressCount } from "./getAddressCount";
import IpAddr from "ipaddr.js";

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
