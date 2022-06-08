import { ContextType, coordinatorPublicKey } from "./types";
import { getComputedConfig, config } from "./vpnserver/config";
import { syncSessions } from "./vpnserver/session";
import { pruneLeases } from "./vpnserver/leaseManager";
import { useExpress } from "./restapi/express";
import { checkCjdns } from "./vpnserver/cjdns";

const checkLoop = ({ context }: { context: ContextType }) => {
  const loopTimeoutMillis = 10 * 1000; // 10 seconds
  setTimeout(async () => {
    await checkCjdns(context);
  }, loopTimeoutMillis);
  checkLoop({ context });
};

const again = async ({ context }: { context: ContextType }) => {
  const loopTimeoutMillis = 10 * 1000; // 10 seconds
  const syncTimeoutMillis = 10 * 60 * 60 * 1000; // 10 hours
  const now = new Date();
  if (now.getTime() - context.mut.lastSync.getTime() < syncTimeoutMillis) {
    return;
  }
  await syncSessions({ context });
  await pruneLeases({ context });
  setTimeout(() => {
    again({ context });
  }, loopTimeoutMillis);
};
const main = async () => {
  // TODO: convert database to sqlite
  let ctx: ContextType;
  // const { readDatabase } = useDatabase();

  // const db = await readDatabase();
  const context: ContextType = {
    cfg: config,
    db: undefined,
    cc: getComputedConfig(config),
    mut: {
      externalConfigs: {},
      lastSync: undefined,
      sessions: {},
      cjdns: undefined,
      coordinatorPublicKey,
    },
  };
  await checkCjdns(context);
  await syncSessions({ context });

  checkLoop({ context });

  setTimeout(() => {
    again({ context });
  }, 10000);

  const { startServer } = useExpress();
  startServer({ context, port: context.cfg.serverPort });
};

main();
