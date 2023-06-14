/*@flow*/
module.exports = {
    cfg4: {
        allocSize: 16,
        networkSize: 0,
        prefix: '10.0.0.0/8',
    },
    cfg6: {
        allocSize: 64,
        networkSize: 0,
        prefix: '2c0f:f930:0002::/48',
    },
    serverPort: process.env.ANODE_SERVER_PORT || 8099,
    dryrun: true,
};