FROM node:20-bookworm-slim

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

EXPOSE 3000 2222 2121 2323 8081 33060

CMD ["pnpm", "start"]
