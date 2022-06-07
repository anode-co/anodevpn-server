import { promises as fs } from "fs";
import { getIpVersionString } from "./getComputedConfig";
import { DbType, ContextType, IpVersion, LeaseType } from "./types";

// TODO: use sqlite3 and prisma
export function useDatabase() {
  let dbFile = "./db.json";

  let db: DbType = {
    leases: {} as { [publicKey: string]: LeaseType },
    slots: {
      ipv4: {} as { [publicKey: string]: number },
      ipv6: {} as { [publicKey: string]: number },
    },
  };

  const readDatabase = async () => {
    try {
      const data = await fs.readFile(dbFile, "utf8");
      db = JSON.parse(data);
      return db;
    } catch (err) {
      if (err.code === "ENOENT") {
        return;
      }
      throw err;
    }
  };

  const saveDatabase = async ({ context }: { context: ContextType }) => {
    const jsonData = JSON.stringify(context.db, null, "\t");
    fs.writeFile(dbFile, jsonData, "utf8");
  };

  const getLease = ({
    context,
    publicKey,
  }: {
    context: ContextType;
    publicKey: string;
  }) => {
    return context.db.leases[publicKey];
  };

  const removeLease = ({
    context,
    publicKey,
  }: {
    context: ContextType;
    publicKey: string;
  }) => {
    delete context.db.leases[publicKey];
  };

  const getLeaseKeys = ({ context }: { context: ContextType }) => {
    return Object.keys(context.db.leases);
  };

  const setSlots = ({
    context,
    ipVersion,
    publicKey,
    numSlots,
  }: {
    context: ContextType;
    ipVersion: IpVersion;
    publicKey: string;
    numSlots: number;
  }) => {
    const ipVersionKey = getIpVersionString(ipVersion);
    context.db.slots[ipVersionKey][publicKey] = numSlots;
  };

  const removeSlot = ({
    context,
    publicKey,
    ipVersion,
  }: {
    context: ContextType;
    publicKey: string;
    ipVersion: IpVersion;
  }) => {
    const ipVersionKey = getIpVersionString(ipVersion);
    delete context.db.slots[ipVersionKey][publicKey];
  };

  return {
    readDatabase,
    saveDatabase,
    getLease,
    removeLease,
    getLeaseKeys,
    setSlots,
    removeSlot,
  };
}
