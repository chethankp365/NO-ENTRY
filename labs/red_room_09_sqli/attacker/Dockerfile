FROM alpine:3.19

RUN apk add --no-cache \
    bash \
    curl \
    python3 \
    py3-pip \
    jq \
    bind-tools \
    netcat-openbsd \
    iproute2 \
    nmap \
    nmap-scripts \
    tcpdump \
    tshark

RUN deluser operator && adduser -D -u 1000 -h /home/operator -s /bin/sh operator && addgroup operator wireshark
RUN mkdir -p /var/log && chown -R operator:operator /var/log
WORKDIR /home/operator
USER operator

COPY --chown=operator:operator entrypoint.sh /home/operator/entrypoint.sh
RUN chmod +x /home/operator/entrypoint.sh

ENV TARGET_HOST="10.10.14.90"
ENV TARGET_PORT="8089"

ENTRYPOINT ["/home/operator/entrypoint.sh"]

