// const BigInt = (n: number | string) => Number(n);
import type { IncomingMessage, ServerResponse } from "http";

export const MARK128: bigint = BigInt(2) ** BigInt(132);
export const MASK128: bigint = BigInt(2) ** BigInt(128) - BigInt(1);
export const MARK32: bigint = BigInt(2) ** BigInt(36);
export const MASK32: bigint = BigInt(0xffffffff);

export const coordinatorPublicKey =
  "1y7k7zb64f242hvv8mht54ssvgcqdfzbxrng5uz7qpgu7fkjudd0.k";

export enum IpVersion {
  IPv4 = "4",
  IPv6 = "6",
}
export type NetworkConfigType = {
  allocSize: number;
  networkSize: number;
  prefix: string;
};

export type ServerConfigType = {
  ipv4?: NetworkConfigType;
  ipv6?: NetworkConfigType;
  serverPort: number;
  dryrun: boolean;
};

export type ComputedNetworkConfigType = {
  numSlots: number;
  baseAddress: bigint;
};

export type ComputedConfigType = {
  ipv4: ComputedNetworkConfigType;
  ipv6: ComputedNetworkConfigType;
};

export type LeaseType = {
  ipv4: {
    numSlots: number;
  };
  ipv6: {
    numSlots: number;
  };
  expiration: Date;
};

export type DbType = {
  leases: { [key: string]: LeaseType };
  slots: {
    ipv4: { [key: string]: number };
    ipv6: { [key: string]: number };
  };
};

export type ContextType = {
  cfg: ServerConfigType;
  db: DbType;
  cc: ComputedConfigType;
  mut: {
    externalConfigs: { [key: string]: number };
    lastSync: Date | undefined;
    sessions: { [key: string]: { conn: string } };
    cjdns: any;
    coordinatorPublicKey: string;
  };
};

export type IpConnectionType = {
  address: string;
  alloc: number;
  prefix: number;
  numSlots: number;
};

export type LeaseSettingForIpType = {
  address?: string;
  alloc?: number;
  prefix?: number;
};

export type LeaseSettingsType = {
  ipv4: IpConnectionType;
  ipv6: IpConnectionType;
};

export type CjdnsConnectionType = {
  error: string;
  ipv4: LeaseSettingForIpType;
  ipv6: LeaseSettingForIpType;
  key: string;
  outgoing: number;
  txid: string;
  number: string;
  // from the cjdns response:
  err?: string;
};

export type SessionType = {
  ctx: ContextType;
  req: IncomingMessage;
  res: ServerResponse;
  timeout: NodeJS.Timer;
};

export type ErrorType = {
  code: number;
  error: string;
};

export type RequestClientAuthorizationPayloadType = {
  signature: {
    publicKey: string;
  };
};
