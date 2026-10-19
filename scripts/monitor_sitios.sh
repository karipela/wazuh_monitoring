#!/usr/bin/env bash
# ==============================================================================
# Monitor simple de sitios web (ejecutado dentro del contenedor Wazuh Manager)
# ==============================================================================

DOMINIOS=(
    "https://google.com"
    "https://facebook.com"
    "https://fcytvirtual.entrerios.gov.ar"
#    "https://mi-dominio2.com"
#    "http://192.168.0.22:8081"
)

LOG_FILE="/var/log/monitor_web.log"

DATE=$(date +"%Y-%m-%d %H:%M:%S")

for DOMAIN in "${DOMINIOS[@]}"; do
    STATUS_CODE=$(curl -k -L -s -o /dev/null -w "%{http_code}" "$DOMAIN" -m 10)
    if [[ "$STATUS_CODE" != "200" ]]; then
        echo "$DATE - sitio $DOMAIN caido (codigo: $STATUS_CODE)" >> "$LOG_FILE"
    fi
done

exit 0
