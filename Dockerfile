FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    suricata \
    suricata-update \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

ENV DATA_DIR=/data
ENV BIND_ADDRESS=0.0.0.0
ENV PORT=8000
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY ohmypcap.py ohmypcap.html ./
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /data && chown -R 1000:1000 /data

USER 1000:1000

VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
