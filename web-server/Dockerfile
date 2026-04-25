FROM node:25-alpine

WORKDIR /app/

COPY ./package.json ./
COPY ./crypto ./crypto/
COPY ./web-server/package.json ./web-server/
COPY ./web-server/src ./web-server/src/

WORKDIR ./web-server

RUN npm install

CMD ["npm", "start"]
