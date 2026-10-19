#!/usr/bin/env python3
"""
Wazuh Custom Integration for Telegram
Sends Wazuh alert notifications to a Telegram chat/channel.
"""

import sys
import os
import json
import logging
from datetime import datetime, timezone, timedelta

# Setup logging in Wazuh logs directory
LOG_FILE = "/var/ossec/logs/integrations.log"
try:
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [custom-telegram] %(message)s"
    )
except Exception:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [custom-telegram] %(message)s"
    )

try:
    import requests
except ImportError:
    logging.error("The 'requests' library is not available in the Python environment.")
    sys.exit(1)


def parse_credentials():
    """
    Resolve Telegram Bot Token and Chat ID from environment variables or arguments.
    Wazuh passes:
      sys.argv[1] -> alert file path
      sys.argv[2] -> <api_key> value from ossec.conf
      sys.argv[3] -> <hook_url> value from ossec.conf
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    arg_key = sys.argv[2].strip() if len(sys.argv) > 2 else ""
    arg_hook = sys.argv[3].strip() if len(sys.argv) > 3 else ""

    # Support colon-separated format in api_key: BOT_TOKEN:CHAT_ID
    if ":" in arg_key and not token and not chat_id:
        parts = arg_key.split(":", 1)
        token = parts[0].strip()
        chat_id = parts[1].strip()

    # If hook_url was passed as a full telegram bot url:
    # https://api.telegram.org/bot<TOKEN>/sendMessage
    if "api.telegram.org/bot" in arg_hook:
        try:
            extracted_token = arg_hook.split("api.telegram.org/bot")[1].split("/")[0]
            if extracted_token and not token:
                token = extracted_token
        except Exception:
            pass
        if arg_key and not chat_id:
            chat_id = arg_key
    else:
        # Otherwise arg_hook might be chat_id or generic url
        if arg_key and not token:
            token = arg_key
        if arg_hook and not chat_id and not arg_hook.startswith("http"):
            chat_id = arg_hook

    return token, chat_id


def format_timestamp(raw_ts):
    """
    Convierte el formato ISO 8601 de Wazuh (ej: 2026-10-13T00:04:19.143+0000)
    a formato legible DD/MM/YYYY HH:MM:SS en la zona horaria local (UTC-3 por defecto).
    """
    if not raw_ts:
        return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]

    clean_ts = str(raw_ts).strip()
    dt = None
    for fmt in formats:
        try:
            dt = datetime.strptime(clean_ts, fmt)
            break
        except ValueError:
            continue

    if not dt:
        return clean_ts

    try:
        offset_hours = float(os.environ.get("TIMEZONE_OFFSET", "-3"))
    except ValueError:
        offset_hours = -3.0

    target_tz = timezone(timedelta(hours=offset_hours))

    if dt.tzinfo is not None:
        dt_local = dt.astimezone(target_tz)
    else:
        dt_local = dt.replace(tzinfo=timezone.utc).astimezone(target_tz)

    return dt_local.strftime("%d/%m/%Y %H:%M:%S")


def build_message(alert):
    """
    Build a structured HTML message for Telegram based on alert fields.
    """
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "N/A")
    rule_level = rule.get("level", 0)
    rule_desc = rule.get("description", "Alerta detectada por Wazuh")

    data = alert.get("data", {})
    url = data.get("url") or alert.get("full_log", "N/A")
    http_code = str(data.get("http_code", "N/A"))
    status = str(data.get("status", "N/A")).upper()
    response_time = data.get("response_time", "N/A")
    timestamp = format_timestamp(alert.get("timestamp"))

    full_log = alert.get("full_log", "").strip()

    # Si la alerta proviene de un log simple en texto plano (syslog)
    if full_log and not data:
        header = "🚨 <b>[Monitor] Alerta de Sitio Caído</b>"
        return (
            f"{header}\n\n"
            f"📝 <b>Registro:</b> <code>{full_log}</code>\n"
            f"🛡️ <b>Regla Wazuh:</b> <code>#{rule_id}</code> (Nivel {rule_level})\n"
            f"📋 <b>Detalle:</b> {rule_desc}\n"
            f"🕒 <b>Fecha/Hora:</b> <code>{timestamp}</code>"
        )

    # Determine icon and severity based on status or HTTP code
    if http_code == "200" or status == "UP":
        header = "🟢 <b>[Monitor] Sitio Operativo</b>"
        code_badge = f"<code>{http_code} OK</code>"
    elif http_code.startswith("4"):
        header = "⚠️ <b>[Monitor] Error de Cliente (4xx)</b>"
        code_badge = f"<code>{http_code}</code>"
    elif http_code.startswith("5"):
        header = "🚨 <b>[Monitor] Error de Servidor (5xx)</b>"
        code_badge = f"<code>{http_code}</code>"
    elif http_code == "000" or status == "DOWN":
        header = "🔴 <b>[Monitor] Sitio Inaccesible / Caído</b>"
        code_badge = "<code>000 (Sin respuesta / Timeout)</code>"
    else:
        header = f"ℹ️ <b>[Monitor] Evento HTTP {http_code}</b>"
        code_badge = f"<code>{http_code}</code>"

    msg = (
        f"{header}\n\n"
        f"🌐 <b>URL:</b> {url}\n"
        f"📊 <b>Estado HTTP:</b> {code_badge}\n"
        f"⏱️ <b>Tiempo de Respuesta:</b> <code>{response_time}</code>\n"
        f"🛡️ <b>Regla Wazuh:</b> <code>#{rule_id}</code> (Nivel {rule_level})\n"
        f"📝 <b>Detalle:</b> {rule_desc}\n"
        f"🕒 <b>Fecha/Hora:</b> <code>{timestamp}</code>"
    )
    return msg


def main():
    if len(sys.argv) < 2:
        logging.error("Missing arguments: Alert file path is required as argv[1].")
        sys.exit(1)

    alert_file = sys.argv[1]
    bot_token, chat_id = parse_credentials()

    if not bot_token or not chat_id:
        logging.error(
            "Telegram Bot Token or Chat ID not configured. "
            "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in environment variables or ossec.conf."
        )
        sys.exit(1)

    # Read alert JSON
    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read or parse alert file '{alert_file}': {e}")
        sys.exit(1)

    message_text = build_message(alert)

    # Send message to Telegram API
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message_text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }

    try:
        res = requests.post(api_url, json=payload, timeout=10)
        if res.status_code == 200:
            logging.info(f"Telegram notification sent successfully (Rule: {alert.get('rule', {}).get('id')}).")
        else:
            logging.error(f"Telegram API responded with HTTP {res.status_code}: {res.text}")
    except Exception as e:
        logging.error(f"Exception while sending request to Telegram API: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
