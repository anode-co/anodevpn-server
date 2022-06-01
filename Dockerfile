FROM alpine:3.9
LABEL co.anode.vpn.image.authors="backupbrain@gmail.com"


# Create app directory
WORKDIR /server

# Install cjdns
# RUN apt-get update && apt-get install -y cjdns
RUN apk add --update nodejs nodejs-npm
RUN apk add --update bash python2 git build-base linux-headers curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN git clone https://github.com/cjdelisle/cjdns
RUN cd cjdns && ./do
RUN ./cjdns/cjdroute --genconf >> /etc/cjdroute.conf
RUN cp cjdroute /usr/bin \
    && cp -r tools/* /usr/bin \
    && cp makekeys \
    mkpasswd \
    privatetopublic \
    publictoip6 \
    randombytes \
    sybilsim /usr/bin
RUN cd ..
RUN cp docker_scripts/entrypoint.sh /
RUN apk del --purge python2 git python2 build-base linux-headers curl

# get cjdns config

# Install app dependencies
# A wildcard is used to ensure both package.json and package-lock.json are installed
# where available (npm@5+)
COPY package*.json ./

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY . .

EXPOSE 8099
CMD [ "/entrypoint.sh" ]

