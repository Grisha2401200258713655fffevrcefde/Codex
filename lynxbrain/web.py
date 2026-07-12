from __future__ import annotations

import json
import logging
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .core import Engine
from .security import token_valid

LOG = logging.getLogger("lynxbrain.web")

DASHBOARD = r'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LynxBrain</title><style>
:root{color-scheme:dark;--bg:#080b12;--panel:#111827;--line:#273244;--text:#e5e7eb;--muted:#94a3b8;--good:#22c55e;--warn:#f59e0b;--bad:#ef4444;--accent:#8b5cf6}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% -10%,#25164d 0,transparent 35%),var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif}main{max-width:1280px;margin:auto;padding:28px}.top{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:22px}.brand h1{margin:0;font-size:30px}.brand p{margin:4px 0;color:var(--muted)}.pill{border:1px solid var(--line);border-radius:999px;padding:8px 13px;background:#0d1320}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:15px}.card{background:linear-gradient(180deg,#131c2b,#0e1521);border:1px solid var(--line);border-radius:16px;padding:17px;box-shadow:0 14px 45px #0005}.host-head{display:flex;justify-content:space-between;gap:12px}.host-name{font-size:19px;font-weight:750}.muted{color:var(--muted)}.state{font-weight:700}.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.metrics{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:16px}.metric{background:#0a101a;border:1px solid #202a3a;border-radius:11px;padding:10px}.metric b{display:block;font-size:18px}.metric span{font-size:12px;color:var(--muted)}section{margin-top:25px}h2{font-size:18px;margin:0 0 12px}.incident{border-left:4px solid var(--bad);padding:12px 14px;background:#1b1117;border-radius:8px;margin-bottom:10px}.action{border-left:4px solid var(--accent);padding:10px 14px;background:#111425;border-radius:8px;margin-bottom:8px}button{background:var(--accent);color:white;border:0;border-radius:10px;padding:10px 14px;cursor:pointer;font-weight:700}button:disabled{opacity:.5;cursor:wait}code{color:#c4b5fd}.empty{color:var(--muted);padding:15px;border:1px dashed var(--line);border-radius:12px}@media(max-width:600px){main{padding:16px}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><main>
<div class="top"><div class="brand"><h1>🐾 LynxBrain</h1><p>Автономный мозг домашней лаборатории</p></div><div><span class="pill" id="cycle">загрузка…</span> <button id="refresh">Обновить</button></div></div>
<div id="hosts" class="grid"></div><section><h2>Активные инциденты</h2><div id="incidents"></div></section><section><h2>Последние действия</h2><div id="actions"></div></section></main>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const val=(m,n,d='—')=>m[n]?Number(m[n].value):d; const pct=x=>typeof x==='number'?x.toFixed(1)+'%':'—';
async function load(){const b=document.querySelector('#refresh');b.disabled=true;try{const r=await fetch('/api/status',{cache:'no-store'});const d=await r.json();document.querySelector('#cycle').textContent='цикл: '+(d.last_cycle||'ещё не завершён')+(d.auto_remediation?' · AUTO':' · наблюдение');document.querySelector('#hosts').innerHTML=d.hosts.map(h=>{const m=h.metrics||{},reachable=val(m,'reachable',0)===1,inc=h.incident;const state=inc?`<span class="state bad">INCIDENT ${inc.priority}/100</span>`:(reachable?'<span class="state good">ONLINE</span>':'<span class="state warn">WAIT</span>');return `<article class="card"><div class="host-head"><div><div class="host-name">${esc(h.name)}</div><div class="muted">${esc(h.address)}</div></div>${state}</div><div class="metrics"><div class="metric"><b>${pct(val(m,'ram_used_pct'))}</b><span>RAM</span></div><div class="metric"><b>${pct(val(m,'root_used_pct'))}</b><span>ROOT</span></div><div class="metric"><b>${val(m,'load1','—')}</b><span>LOAD 1m</span></div><div class="metric"><b>${val(m,'uptime_seconds','—')}</b><span>UPTIME, sec</span></div></div>${inc?`<p class="bad">${esc(inc.summary)}</p><small class="muted">Причина: <code>${esc(inc.root_cause)}</code>${inc.recommended_action?` · совет: <code>${esc(inc.recommended_action)}</code>`:''}</small>`:''}</article>`}).join('');document.querySelector('#incidents').innerHTML=d.open_incidents.length?d.open_incidents.map(i=>`<div class="incident"><b>${esc(i.host)} · ${i.priority}/100</b><div>${esc(i.summary)}</div><small class="muted">${esc(i.root_cause)} · уверенность ${(i.confidence*100).toFixed(0)}% · ${esc(i.updated_at)}</small></div>`).join(''):'<div class="empty">Активных инцидентов нет.</div>';document.querySelector('#actions').innerHTML=d.recent_actions.length?d.recent_actions.slice(0,10).map(a=>`<div class="action"><b>${esc(a.host)} · ${esc(a.action_key)}</b><div class="${a.status==='success'?'good':a.status==='failed'?'bad':'warn'}">${esc(a.status)}</div><small class="muted">${esc(a.started_at)}</small></div>`).join(''):'<div class="empty">Действий ещё не было.</div>'}catch(e){document.querySelector('#cycle').textContent='ошибка загрузки';console.error(e)}finally{b.disabled=false}}
document.querySelector('#refresh').onclick=load;load();setInterval(load,15000);
</script></body></html>'''


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address: tuple[str, int], engine: Engine, api_token: str):
        super().__init__(address, Handler); self.engine = engine; self.api_token = api_token


class Handler(BaseHTTPRequestHandler):
    server: AppServer
    def log_message(self, fmt: str, *args: object) -> None: LOG.info("%s - %s", self.address_string(), fmt % args)
    def _json(self, payload: object, status: int = 200) -> None:
        raw=json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode();self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(raw)));self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff");self.end_headers();self.wfile.write(raw)
    def _html(self, body: str) -> None:
        raw=body.encode();self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8");self.send_header("Content-Length",str(len(raw)));self.send_header("Content-Security-Policy","default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'");self.send_header("X-Frame-Options","DENY");self.end_headers();self.wfile.write(raw)
    def _authorized(self) -> bool:
        header=self.headers.get("Authorization","");supplied=header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else "";return token_valid(self.server.api_token,supplied)
    def _read_json(self) -> dict:
        length=int(self.headers.get("Content-Length","0"));
        if length<=0 or length>65536: raise ValueError("Invalid request size")
        payload=json.loads(self.rfile.read(length));
        if not isinstance(payload,dict): raise ValueError("JSON object expected")
        return payload
    def do_GET(self) -> None:
        p=urlparse(self.path)
        if p.path=="/": self._html(DASHBOARD)
        elif p.path=="/health": self._json({"status":"ok","last_cycle":self.server.engine.last_cycle})
        elif p.path=="/api/status": self._json(self.server.engine.status())
        elif p.path=="/api/incidents": self._json(self.server.engine.db.incidents(status=parse_qs(p.query).get("status",[None])[0]))
        else: self._json({"error":"not found"},HTTPStatus.NOT_FOUND)
    def do_POST(self) -> None:
        if not self._authorized(): self._json({"error":"unauthorized"},HTTPStatus.UNAUTHORIZED);return
        try:
            if self.path=="/api/run-cycle": threading.Thread(target=self.server.engine.run_cycle,daemon=True).start();self._json({"accepted":True},HTTPStatus.ACCEPTED)
            elif self.path=="/api/action":
                b=self._read_json();self._json(self.server.engine.manual_action(str(b.get("host","")),str(b.get("action","")),b.get("incident_id")))
            else:self._json({"error":"not found"},HTTPStatus.NOT_FOUND)
        except PermissionError as e:self._json({"error":str(e)},HTTPStatus.FORBIDDEN)
        except (ValueError,KeyError,RuntimeError) as e:self._json({"error":str(e)},HTTPStatus.BAD_REQUEST)
        except Exception:LOG.exception("Request failed");self._json({"error":"internal error"},HTTPStatus.INTERNAL_SERVER_ERROR)
