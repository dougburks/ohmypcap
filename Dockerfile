FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    suricata \
    suricata-update \
    tcpdump \
    tshark \
    yara \
    curl \
    unzip \
    file \
    libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

ENV DATA_DIR=/data
ENV BIND_ADDRESS=0.0.0.0
ENV PORT=8000
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY config.py db.py models.py validators.py suricata.py yara_scanner.py file_analyzer.py exif_analyzer.py ohmypcap.py ohmypcap.html ./
COPY static/ static/
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Bake Suricata rules into image for air-gapped deployments
RUN mkdir -p /usr/share/suricata/rules && \
    suricata-update --no-test --data-dir /usr/share/suricata --output /usr/share/suricata/rules

# Bake YARA Forge rules into image for air-gapped deployments
RUN mkdir -p /usr/share/yara-rules && \
    curl -fsSL -o /tmp/yara-forge-full.zip \
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip" && \
    unzip -p /tmp/yara-forge-full.zip "packages/full/yara-rules-full.yar" \
    > /usr/share/yara-rules/yara-rules-full.yar && \
    rm /tmp/yara-forge-full.zip

RUN mkdir -p /data && chown -R 1000:1000 /data

USER 1000:1000

VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
