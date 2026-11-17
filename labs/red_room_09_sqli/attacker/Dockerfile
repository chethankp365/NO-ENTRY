FROM alpine:3.19

RUN apk add --no-cache \
    bash \
    coreutils \
    procps \
    curl \
    wget \
    python3 \
    py3-pip \
    jq \
    git \
    bind-tools \
    whois \
    netcat-openbsd \
    iproute2 \
    nmap \
    nmap-scripts \
    tcpdump \
    tshark \
    openssh-client \
    samba-client \
    openldap-clients

RUN deluser operator 2>/dev/null || true && adduser -D -u 1000 -h /home/operator -s /bin/bash operator && addgroup operator wireshark 2>/dev/null || true
RUN mkdir -p /var/log && chown -R operator:operator /var/log
WORKDIR /home/operator
USER operator

COPY --chown=operator:operator entrypoint.sh /home/operator/entrypoint.sh
RUN chmod +x /home/operator/entrypoint.sh

ENV TARGET_HOST="10.10.14.90"
ENV TARGET_PORT="8089"

ENTRYPOINT ["/home/operator/entrypoint.sh"]
