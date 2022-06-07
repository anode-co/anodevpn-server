import Http from "http";
import { ContextType, coordinatorPublicKey } from "./types";
import { useDatabase } from "./useDatabase";
import { config } from "./config";
import { getComputedConfig } from "./getComputedConfig";
import { syncSessions } from "./syncSessions";
import { useCjdns } from "./useCjdns";
import { Http2ServerRequest } from "http2";
import { pruneLeases } from "./pruneLeases";
const { checkCjdns } = useCjdns();
import { useExpress } from "./useExpress";

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
  const { readDatabase } = useDatabase();

  const db = await readDatabase();
  const context: ContextType = {
    cfg: config,
    db,
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
