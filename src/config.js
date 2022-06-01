module.exports = {
  cfg4: {
    allocSize: parseInt(process.env.CFG4_ALLOC_SIZE) || 32,
    networkSize: parseInt(process.env.CFG4_NETWORK_SIZE) || 0,
    prefix: process.env.CFG4_PREFIX || "10.66.0.0/16",
  },
  cfg6: {
    allocSize: parseInt(process.env.CFG6_ALLOC_SIZE) || 64,
    networkSize: parseInt(process.env.CFG6_NETWORK_SIZE) || 0,
    prefix: process.env.CFG6_PREFIX || "2c0f:f930:0002::/48",
  },
  serverPort: parseInt(process.env.SERVER_PORT) | 8099,
  dryrun: process.env.DRY_RUN.toLowerCase() === "true",
};
