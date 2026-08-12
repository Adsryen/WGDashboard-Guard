FROM alpine:3.23

RUN apk add --no-cache \
    iproute2 \
    nftables \
    openssh \
    python3 \
    curl \
    socat

COPY --from=network_policy_source . /app/network_policy
COPY scripts /tests

RUN sed -i 's/\r$//' /tests/*.sh && chmod 0755 /tests/*.sh

ENV PYTHONPATH=/app
