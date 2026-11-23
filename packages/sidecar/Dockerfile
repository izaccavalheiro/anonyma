# anonyma-sidecar: the container image.
#
# Build from the repository root (the image bundles the root build of anonyma):
#   docker build -f packages/sidecar/Dockerfile -t anonyma-sidecar .
# Run, reachable from this host only:
#   docker run --rm -p 127.0.0.1:7878:7878 anonyma-sidecar
#
# Base images are pinned by digest; Dependabot keeps the pins current.

FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /repo
ENV HUSKY=0
COPY package.json package-lock.json tsconfig.json tsup.config.ts ./
COPY packages ./packages
COPY src ./src
RUN npm ci --ignore-scripts --no-audit --no-fund --include-workspace-root --workspace anonyma-sidecar
RUN npm run build && npm run build --workspace anonyma-sidecar

# Runtime: Node.js and the two builds, nothing else (no shell, no package manager).
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e
WORKDIR /app
COPY --from=build /repo/packages/sidecar/package.json ./package.json
COPY --from=build /repo/packages/sidecar/dist ./dist
COPY --from=build /repo/package.json ./node_modules/anonyma/package.json
COPY --from=build /repo/dist ./node_modules/anonyma/dist
ENV NODE_ENV=production \
    ANONYMA_SIDECAR_HOST=0.0.0.0 \
    ANONYMA_SIDECAR_PORT=7878
EXPOSE 7878
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:7878/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["dist/bin.js"]
