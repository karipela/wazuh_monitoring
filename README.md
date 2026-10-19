# Wazuh Docker - Monitoreo Web y Alertas por Telegram

Despliegue de **Wazuh v4.9.0** (`wazuh.manager`, `wazuh.indexer` y `wazuh.dashboard`) en contenedores Docker, configurado para el monitoreo automático de disponibilidad de sitios web y el envío de notificaciones en tiempo real a través de **Telegram**.

---

## Arquitectura y Flujo de Funcionamiento

1. **Monitoreo de Sitios (`scripts/monitor_sitios.sh`)**:
   - Un *wodle command* configurado en `wazuh_manager.conf` ejecuta periódicamente (cada 1 minuto) el script `monitor_sitios.sh` dentro del contenedor `wazuh.manager`.
   - El script verifica mediante `curl` el código de respuesta HTTP de los dominios configurados. Si algún sitio no responde con `200 OK`, registra el evento en `/var/log/monitor_web.log`.

2. **Detección y Reglas (`rules/local_rules.xml`)**:
   - Wazuh ingesta `/var/log/monitor_web.log` mediante `<localfile>`.
   - La regla personalizada **`#105005`** (nivel 11) se dispara al detectar la caída de un sitio web.

3. **Notificación por Telegram (`integrations/custom-telegram.py`)**:
   - Cuando se activa la regla `105005`, el módulo `<integration>` de Wazuh invoca `custom-telegram`, que ejecuta `custom-telegram.py` con el entorno Python interno de Wazuh.
   - El script formatea la alerta (URL/registro, código HTTP, regla, nivel y fecha/hora local) y la envía al chat o canal de Telegram mediante la API de Telegram Bot.

---

## Estructura del Proyecto

```text
.
├── config/
│   ├── wazuh_cluster/wazuh_manager.conf   # Configuración principal del Manager (wodle, localfile, integration)
│   ├── wazuh_dashboard/                   # Configuración de OpenSearch Dashboards / Wazuh Dashboard
│   ├── wazuh_indexer/                     # Configuración de Wazuh Indexer y usuarios internos
│   └── wazuh_indexer_ssl_certs/           # Certificados SSL para la comunicación entre servicios
├── integrations/
│   ├── custom-telegram                    # Wrapper shell para el motor de integraciones de Wazuh
│   └── custom-telegram.py                 # Script Python que envía las alertas a Telegram
├── logs/
│   └── monitor_web.log                    # Archivo de registro de caídas detectadas
├── rules/
│   └── local_rules.xml                    # Reglas personalizadas (#100001 y #105005)
├── scripts/
│   └── monitor_sitios.sh                  # Script de chequeo HTTP de sitios web
├── docker-compose.yml                     # Definición de servicios, volúmenes y variables de entorno
└── requirements.txt                       # Dependencias de Python para las integraciones
```

---

## Configuración y Puesta en Marcha

### 1. Variables de Entorno (`.env`)

Definí un archivo `.env` en la raíz del proyecto con las credenciales de los servicios y de tu Bot de Telegram:

```env
INDEXER_USERNAME=admin
INDEXER_PASSWORD=SecretPassword
API_USERNAME=wazuh-wui
API_PASSWORD=MyS3cr37P450r.*-
DASHBOARD_USERNAME=kibanaserver
DASHBOARD_PASSWORD=kibanaserver

TELEGRAM_BOT_TOKEN=tu_bot_token_aqui
TELEGRAM_CHAT_ID=tu_chat_id_aqui
```

### 2. Iniciar el Entorno

```bash
docker compose up -d
```

### 3. Accesos y Puertos Principales

- **Wazuh Dashboard**: `https://localhost:443`
- **Wazuh Indexer**: `https://localhost:9200`
- **Wazuh Manager API**: `https://localhost:55000`
- **Registro y Comunicación de Agentes**: puertos `1514/tcp`, `1515/tcp` y `514/udp`
