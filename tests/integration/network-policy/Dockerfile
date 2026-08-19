FROM alpine:3.23

RUN apk add --no-cache \
    iproute2 \
    nftables \
    openssh \
    py3-pip \
    py3-sqlalchemy \
    python3 \
    curl \
    socat

RUN pip install --break-system-packages --no-cache-dir pyroute2==0.9.6

COPY --from=network_policy_source . /app/network_policy
COPY --from=network_audit_source . /app/network_audit
COPY scripts /tests

RUN sed -i 's/\r$//' /tests/*.sh && chmod 0755 /tests/*.sh

ENV PYTHONPATH=/app
