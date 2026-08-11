FROM alpine:3.23

RUN apk add --no-cache \
    iproute2 \
    nftables \
    openssh \
    python3 \
    socat

COPY --from=network_policy_source . /app/network_policy
COPY scripts /tests

RUN chmod 0755 /tests/*.sh

ENV PYTHONPATH=/app
