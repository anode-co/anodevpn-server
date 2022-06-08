import { ContextType, RequestClientAuthorizationPayloadType } from "../types";
import express from "express";
import { allocateLease, getLease } from "../vpnserver/leaseManager";
const app = express();
app.use(express.json());

const requestClientAuthorization = async ({
  context,
  req,
}: {
  context: ContextType;
  req: express.Request;
}): Promise<{ method: string; expiration: Date }> => {
  // TODO: verify authorization headers: see needsAuth()
  // TODO: verify the data in this request
  const { signature }: RequestClientAuthorizationPayloadType = req.body;
  // check for authorization header
  // TODO: put this in an authorization method
  const authorization = req.headers["authorization"];
  const authDataPair = authorization?.split(" ");
  if (
    !authDataPair ||
    authDataPair.length !== 2 ||
    authDataPair[0] !== "cjdns"
  ) {
    throw new Error("expecting an authorization header");
  }
  const clientPublicKey = authDataPair[1];
  console.log("---- Authorization request ------");
  console.log(`from cjdns pubkey: ${clientPublicKey}`);
  // get request time
  const requestDatetime = new Date(req.headers["date"]);
  const formattedDateTime = new Date(requestDatetime).toLocaleString("en-US");
  console.log(`at datetime: ${formattedDateTime}`);
  // TODO: handle errors
  if (!clientPublicKey) {
    throw new Error("expecting a cjdns public key in authorization header");
  }
  // TODO: get signature
  const coordinatorPublicKey = context.mut.coordinatorPublicKey;
  if (
    signature.publicKey !== clientPublicKey &&
    signature.publicKey !== coordinatorPublicKey
  ) {
    throw new Error(
      `request can only be made (signed) by either ` +
        `client (${clientPublicKey}) or coordinator (${coordinatorPublicKey}) (signed by ${signature.publicKey})`
    );
  }
  const lease = await getLease({ context, publicKey: clientPublicKey });
  console.error(`Request from ${clientPublicKey}`);
  let method: string;
  if (!lease) {
    console.error(`Allocating Request from ${clientPublicKey}`);
    const lease = await allocateLease({ context, publicKey: clientPublicKey });
    method = "add";
  } else {
    const expiration = new Date();
    expiration.setDate(expiration.getDate() + 1); // one day
    lease.expiration = expiration;
    // saveDatabase({ context });
    method = "update";
  }
  return {
    method,
    expiration: lease.expiration,
  };
};

export function useExpress() {
  const startServer = async ({
    context,
    port,
  }: {
    context: ContextType;
    port: number;
  }) => {
    app.get("/", (req: express.Request, res: express.Response) => {
      res.status(404).json({
        error: "No such endpoint",
      });
    });

    app.get(
      "/api/0.3/server/authorize",
      async (req: express.Request, res: express.Response) => {
        return requestClientAuthorization({ context, req });
      }
    );
    app.listen(port, () => {
      console.log(`Listening on port ${port}`);
    });
    return app;
  };

  return { startServer };
}
