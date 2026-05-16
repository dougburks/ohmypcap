FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    suricata \
    suricata-update \
    tcpdump \
    tshark \
    yara \
    git \
    && rm -rf /var/lib/apt/lists/*

ENV DATA_DIR=/data
ENV BIND_ADDRESS=0.0.0.0
ENV PORT=8000
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY db.py models.py validators.py suricata.py yara_scanner.py ohmypcap.py ohmypcap.html ./
COPY static/ static/
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Bake Suricata rules into image for air-gapped deployments
RUN mkdir -p /usr/share/suricata/rules && \
    suricata-update --no-test --data-dir /usr/share/suricata --output /usr/share/suricata/rules

# Bake YARA rules into image for air-gapped deployments
RUN mkdir -p /usr/share/yara-rules/neo23x0 && \
    git clone --depth 1 https://github.com/Neo23x0/signature-base /tmp/signature-base && \
    cp /tmp/signature-base/yara/*.yar /usr/share/yara-rules/neo23x0/ && \
    rm -rf /tmp/signature-base && \
    git clone --depth 1 https://github.com/YARA-Rules/rules.git /usr/share/yara-rules/yara-rules && \
    python3 -c "
import os
lines = ['// Auto-generated Neo23x0 YARA rules index', '']
neo_dir = '/usr/share/yara-rules/neo23x0'
for f in sorted(os.listdir(neo_dir)):
    if f.endswith('.yar'):
        lines.append(f'include \"neo23x0/{f}\"')
lines.append('')
with open('/usr/share/yara-rules/neo23x0-index.yar', 'w') as f:
    f.write('\n'.join(lines))
print(f'Generated neo23x0-index.yar with {len(lines)} lines')
"

RUN mkdir -p /data && chown -R 1000:1000 /data

USER 1000:1000

VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
