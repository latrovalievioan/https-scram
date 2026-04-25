FROM node:25-alpine

WORKDIR /app/

COPY ./package.json ./
COPY ./crypto ./crypto/
COPY ./web-client/package.json ./web-client/
COPY ./web-client/src ./web-client/src
COPY ./web-client/vite.config.js ./web-client

WORKDIR ./web-client

RUN npm install

CMD ["npm", "start"]
