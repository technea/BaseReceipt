FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=node:node package.json ./
COPY --chown=node:node server.mjs ./server.mjs
COPY --chown=node:node src ./src
USER node
EXPOSE 8080
CMD ["node", "server.mjs"]
