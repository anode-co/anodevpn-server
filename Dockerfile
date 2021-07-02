FROM node:16-alpine

COPY . /anodevpn-server

RUN addgroup -S -g 1001 anodevpn && \
    addgroup node anodevpn && \
    chown -R node /anodevpn-server

WORKDIR /anodevpn-server

USER node:anodevpn

RUN npm install

EXPOSE 8099

CMD ["node", "/anodevpn-server/index.js"]