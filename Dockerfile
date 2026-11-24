FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web/ web/
COPY client/ client/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/paw .
RUN mkdir -p /out/assets /out/data && \
    wget -q -O /out/assets/OpenSSH-Win64.zip https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip && \
    wget -q -O /out/assets/plink.exe https://the.earth.li/~sgtatham/putty/0.85/w64/plink.exe && \
    printf '%s\n' \
    'b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957  /out/assets/OpenSSH-Win64.zip' \
    '969f36879d5716aa1a9811f43a6a6510e8f08372dbeb9695b810b9c776f39c75  /out/assets/plink.exe' | sha256sum -c -

FROM scratch
COPY --from=build /out/paw /paw
COPY --from=build /out/assets /assets
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080 49222 49223
ENTRYPOINT ["/paw"]
