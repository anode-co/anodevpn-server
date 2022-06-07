import IpAddr from "ipaddr.js";

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
