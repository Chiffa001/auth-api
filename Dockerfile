FROM node:18.14.1-alpine

WORKDIR /app

COPY package.json yarn.lock ./

RUN yarn install

COPY . .

COPY ./dist ./dist

RUN yarn run generate

CMD ["yarn", "run", "start:dev"]