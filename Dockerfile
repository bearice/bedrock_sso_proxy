# Multi-stage Dockerfile for Bedrock SSO Proxy
# Stage 1: Frontend build
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend package files
COPY frontend/package*.json ./

# Install frontend dependencies
RUN npm ci

# Copy frontend source
COPY frontend/ ./

# Build frontend for production
RUN npm run build

# Stage 2: Rust build
FROM rust:1.87-slim AS rust-builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all required files for the build
COPY Cargo.toml Cargo.lock build.rs ./
COPY typed_cache_macro/ ./typed_cache_macro/

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release && rm -rf src/

COPY src/ ./src/
COPY bedrock_pricing.csv ./

# Copy built frontend from previous stage
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Build the application
RUN cargo build --release --bin bedrock_proxy

# Stage 3: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -m -d /app bedrock

WORKDIR /app

# Copy binary from builder stage
COPY --from=rust-builder /app/target/release/bedrock_proxy ./

# Create data directory with proper permissions
RUN mkdir -p data && chown -R bedrock:bedrock /app

# Switch to non-root user
USER bedrock

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Default configuration
ENV BEDROCK_SERVER__HOST=0.0.0.0
ENV BEDROCK_SERVER__PORT=3000
ENV BEDROCK_DATABASE__URL=sqlite:///app/data/bedrock_sso.db
ENV BEDROCK_CACHE__BACKEND=memory
ENV BEDROCK_JOBS__ENABLED=true
ENV BEDROCK_METRICS__ENABLED=true
ENV BEDROCK_METRICS__PORT=9090

# Run the application
CMD ["./bedrock_proxy"]
