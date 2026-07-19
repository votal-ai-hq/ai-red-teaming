FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Build React frontend
FROM node:20-slim AS ui-build
WORKDIR /app
COPY dashboard/ui/package.json dashboard/ui/package-lock.json* ./dashboard/ui/
WORKDIR /app/dashboard/ui
RUN npm ci
COPY dashboard/ui/ ./
RUN npm run build

FROM node:20-slim
WORKDIR /app

# Install git (needed for codebaseRepo cloning) and tsx
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN npm i -g tsx

# Copy production dependencies
COPY --from=deps /app/node_modules ./node_modules

# Copy application source
COPY package.json ./
COPY tsconfig.json ./
COPY lib/ ./lib/
COPY attacks/ ./attacks/
COPY attacks-mcp/ ./attacks-mcp/
COPY dashboard/server.ts ./dashboard/
COPY red-team.ts ./
COPY policies/ ./policies/
COPY lib/migrations/ ./lib/migrations/
COPY compliance/ ./compliance/
COPY config.example.json ./
COPY examples/ ./examples/
COPY data/ ./data/
COPY scripts/ ./scripts/
COPY configs/ ./configs/

# Copy React build output
COPY --from=ui-build /app/dashboard/ui/dist ./dashboard/ui/dist

# Create report directories
RUN mkdir -p report reports/litellm-guardrails

EXPOSE 4200

# Run the dashboard server (serves UI + run API)
CMD ["sh", "-c", "tsx dashboard/server.ts ${PORT:-4200}"]
