import os
import time
from threading import Lock

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "").rstrip("/")
CLIENT_ID = os.getenv("WEBEX_CLIENT_ID")
CLIENT_SECRET = os.getenv("WEBEX_CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("WEBEX_REFRESH_TOKEN")
INITIAL_ACCESS_TOKEN = os.getenv("WEBEX_ACCESS_TOKEN")

token_lock = Lock()
access_token = INITIAL_ACCESS_TOKEN
access_token_expires_at = 0


def cors_origin():
    return ALLOWED_ORIGIN if ALLOWED_ORIGIN else "*"


CORS(
    app,
    resources={
        r"/api/*": {
            "origins": cors_origin(),
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
        }
    },
)


def webex_error(response):
    try:
        data = response.json()
    except ValueError:
        data = {"raw": response.text[:500]}
    return data


def refresh_access_token():
    global access_token, access_token_expires_at, REFRESH_TOKEN

    if not CLIENT_ID or not CLIENT_SECRET or not REFRESH_TOKEN:
        raise RuntimeError(
            "Faltan WEBEX_CLIENT_ID, WEBEX_CLIENT_SECRET o WEBEX_REFRESH_TOKEN."
        )

    response = requests.post(
        "https://webexapis.com/v1/access_token",
        data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": REFRESH_TOKEN,
        },
        timeout=20,
    )

    data = webex_error(response)

    if not response.ok or not data.get("access_token"):
        raise RuntimeError(
            f"Webex rechazó el refresh token ({response.status_code}): {data}"
        )

    access_token = data["access_token"]
    access_token_expires_at = time.time() + int(data.get("expires_in", 120)) - 30

    # Webex puede devolver un nuevo refresh token.
    # Se conserva en memoria para las siguientes peticiones de este proceso.
    # Si el proveedor rota el refresh token, conviene persistirlo en un
    # secret manager/variable de entorno administrada por el hosting.
    global REFRESH_TOKEN
    if data.get("refresh_token"):
        REFRESH_TOKEN = data["refresh_token"]

    return access_token


def get_service_app_token(force_refresh=False):
    global access_token

    with token_lock:
        if (
            not force_refresh
            and access_token
            and time.time() < access_token_expires_at
        ):
            return access_token

        if not force_refresh and access_token and not CLIENT_ID:
            return access_token

        return refresh_access_token()


def webex_post(path, payload, retry=True):
    token = get_service_app_token()

    response = requests.post(
        f"https://webexapis.com{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )

    if response.status_code in (401, 403) and retry:
        token = get_service_app_token(force_refresh=True)
        response = requests.post(
            f"https://webexapis.com{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )

    return response


@app.get("/api/health")
def health():
    return jsonify({"status": "online"})


@app.post("/api/webex/config")
def webex_config():
    try:
        payload = request.get_json(silent=True) or {}

        guest_name = payload.get("guestName") or "soporte web"
        called_number = payload.get("calledNumber") or "0676"

        guest_response = webex_post(
            "/v1/guests/token",
            {
                "subject": "Webex Click To Call Demo",
                "displayName": guest_name,
            },
        )

        guest_data = webex_error(guest_response)

        if not guest_response.ok or not guest_data.get("accessToken"):
            return jsonify({
                "error": "No se pudo obtener el guest token",
                "status": guest_response.status_code,
                "details": guest_data,
            }), 502

        call_response = webex_post(
            "/v1/telephony/click2call/callToken",
            {
                "calledNumber": called_number,
                "guestName": guest_name,
            },
        )

        call_data = webex_error(call_response)

        if not call_response.ok or not call_data.get("callToken"):
            return jsonify({
                "error": "No se pudo obtener el call token",
                "status": call_response.status_code,
                "details": call_data,
            }), 502

        return jsonify({
            "guestToken": guest_data["accessToken"],
            "callToken": call_data["callToken"],
            "expiresIn": call_data.get(
                "expiresIn",
                guest_data.get("expiresIn")
            ),
        })

    except Exception as exc:
        app.logger.exception("Error generando tokens Webex")
        return jsonify({
            "error": "Error interno generando credenciales temporales de Webex",
            "details": str(exc),
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
