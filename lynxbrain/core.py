from __future__ import annotations

import json, logging, os, re, shlex, sqlite3, statistics, subprocess, threading, time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG = logging.getLogger("lynxbrain")
SAFE = re.compile(r"^[A-Za-z0-9_.@:-]+$")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Metric:
    name: str
    value: float
    detail: str = ""


@dataclass
class Anomaly:
    metric: str
    value: float
    score: float
    severity: int
    reason: str


@dataclass
class IncidentCandidate:
    host: str
    root_cause: str
    confidence: float
    severity: int
    priority: int
    summary: str
    fingerprint: str
    anomalies: list[Any]
    recommended_action: str | None = None


class ConfigError(RuntimeError): pass


class Config:
    def __init__(self, path: str): self.path = Path(path); self.reload()
    def reload(self):
        try: data = json.loads(self.path.read_text())
        except Exception as e: raise ConfigError(f"Config error: {e}") from e
        if not isinstance(data.get("hosts"), list): raise ConfigError("hosts must be a list")
        names=set()
        for h in data["hosts"]:
            n=str(h.get("name", ""))
            if not SAFE.fullmatch(n) or n in names: raise ConfigError(f"Unsafe/duplicate host: {n}")
            names.add(n)
            for key in ("containers","services"):
                for x in h.get(key,[]):
                    if not SAFE.fullmatch(str(x)): raise ConfigError(f"Unsafe target: {x}")
            for a in h.get("allowed_actions",[]):
                if ":" not in a or a.split(":",1)[0] not in {"restart_container","restart_service","journal_vacuum"} or not SAFE.fullmatch(a.split(":",1)[1]):
                    raise ConfigError(f"Unsafe action: {a}")
            h.setdefault("enabled",True); h.setdefault("mode","ssh"); h.setdefault("importance",5)
            h.setdefault("ssh_port",22); h.setdefault("http_checks",[]); h.setdefault("containers",[])
            h.setdefault("services",[]); h.setdefault("allowed_actions",[]); h.setdefault("strict_host_key_checking",True)
        self.data=data; self.poll_interval=int(data.get("poll_interval_seconds",60)); self.history_window=int(data.get("history_window",1440))
        self.min_samples=int(data.get("minimum_baseline_samples",20)); self.verify_delay=int(data.get("verification_delay_seconds",20))
        self.auto_remediation=bool(data.get("auto_remediation",False)); self.max_auto_level=int(data.get("max_automatic_action_level",1)); self.ntfy=data.get("ntfy",{})
    @property
    def hosts(self): return [h for h in self.data["hosts"] if h.get("enabled",True)]
    def host(self,name): return next((h for h in self.hosts if h["name"]==name),None)


class Database:
    def __init__(self,path): self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self._init()
    def con(self):
        c=sqlite3.connect(self.path,timeout=15); c.row_factory=sqlite3.Row; c.execute("PRAGMA journal_mode=WAL"); return c
    def _init(self):
        with self.con() as c: c.executescript("""
        CREATE TABLE IF NOT EXISTS telemetry(id INTEGER PRIMARY KEY,ts TEXT,host TEXT,metric TEXT,value REAL,detail TEXT);
        CREATE INDEX IF NOT EXISTS tele_idx ON telemetry(host,metric,id DESC);
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,fingerprint TEXT UNIQUE,host TEXT,root_cause TEXT,status TEXT,confidence REAL,severity INT,priority INT,summary TEXT,recommended_action TEXT,opened_at TEXT,updated_at TEXT,closed_at TEXT);
        CREATE TABLE IF NOT EXISTS actions(id INTEGER PRIMARY KEY,incident_id INT,host TEXT,action_key TEXT,status TEXT,started_at TEXT,finished_at TEXT,output TEXT);
        CREATE TABLE IF NOT EXISTS action_stats(action_key TEXT PRIMARY KEY,alpha REAL DEFAULT 1,beta REAL DEFAULT 1,successes INT DEFAULT 0,failures INT DEFAULT 0);
        CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value TEXT);
        """)
    def insert_metrics(self,host,metrics):
        with self.con() as c: c.executemany("INSERT INTO telemetry(ts,host,metric,value,detail) VALUES(?,?,?,?,?)",[(now(),host,m.name,float(m.value),m.detail[:1000]) for m in metrics])
    def history(self,host,metric,limit):
        with self.con() as c: return [r[0] for r in reversed(c.execute("SELECT value FROM telemetry WHERE host=? AND metric=? ORDER BY id DESC LIMIT ?",(host,metric,limit)).fetchall())]
    def latest_metrics(self,host):
        with self.con() as c:
            rows=c.execute("SELECT metric,value,detail,ts FROM telemetry WHERE id IN(SELECT MAX(id) FROM telemetry WHERE host=? GROUP BY metric)",(host,)).fetchall()
        return {r["metric"]:{"value":r["value"],"detail":r["detail"],"ts":r["ts"]} for r in rows}
    def upsert_incident(self,i):
        t=now()
        with self.con() as c:
            r=c.execute("SELECT id,status FROM incidents WHERE fingerprint=?",(i.fingerprint,)).fetchone()
            if not r:
                q=c.execute("INSERT INTO incidents(fingerprint,host,root_cause,status,confidence,severity,priority,summary,recommended_action,opened_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(i.fingerprint,i.host,i.root_cause,"open",i.confidence,i.severity,i.priority,i.summary,i.recommended_action,t,t)); return q.lastrowid,True
            fresh=r["status"]=="closed"; c.execute("UPDATE incidents SET status='open',confidence=?,severity=?,priority=?,summary=?,recommended_action=?,updated_at=?,closed_at=NULL WHERE id=?",(i.confidence,i.severity,i.priority,i.summary,i.recommended_action,t,r["id"])); return r["id"],fresh
    def close_other_incidents(self,host,active):
        with self.con() as c:
            rows=c.execute("SELECT * FROM incidents WHERE host=? AND status='open'",(host,)).fetchall(); closed=[]
            for r in rows:
                if r["fingerprint"] not in active: c.execute("UPDATE incidents SET status='closed',closed_at=?,updated_at=? WHERE id=?",(now(),now(),r["id"])); closed.append(dict(r))
            return closed
    def incidents(self,limit=50,status=None):
        with self.con() as c:
            q="SELECT * FROM incidents"+(" WHERE status=?" if status else "")+" ORDER BY priority DESC,updated_at DESC LIMIT ?"; args=(status,limit) if status else (limit,); return [dict(r) for r in c.execute(q,args)]
    def recent_actions(self,limit=30):
        with self.con() as c: return [dict(r) for r in c.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?",(limit,))]
    def action_probability(self,a):
        with self.con() as c: r=c.execute("SELECT alpha,beta FROM action_stats WHERE action_key=?",(a,)).fetchone()
        return r[0]/(r[0]+r[1]) if r else .5
    def action_in_cooldown(self,host,a,seconds=1800):
        with self.con() as c: r=c.execute("SELECT started_at FROM actions WHERE host=? AND action_key=? ORDER BY id DESC LIMIT 1",(host,a)).fetchone()
        if not r:return False
        return (datetime.now(timezone.utc)-datetime.fromisoformat(r[0])).total_seconds()<seconds
    def start_action(self,incident_id,host,a):
        with self.con() as c: return c.execute("INSERT INTO actions(incident_id,host,action_key,status,started_at,output) VALUES(?,?,?,?,?,?)",(incident_id,host,a,"running",now(),"")).lastrowid
    def finish_action(self,aid,success,out):
        with self.con() as c:
            c.execute("UPDATE actions SET status=?,finished_at=?,output=? WHERE id=?",("success" if success else "failed",now(),out[-4000:],aid)); c.execute("INSERT OR IGNORE INTO action_stats(action_key) SELECT action_key FROM actions WHERE id=?",(aid,)); c.execute("UPDATE action_stats SET alpha=alpha+?,beta=beta+?,successes=successes+?,failures=failures+? WHERE action_key=(SELECT action_key FROM actions WHERE id=?)",(1 if success else 0,0 if success else 1,1 if success else 0,0 if success else 1,aid))
    def set_kv(self,k,v):
        with self.con() as c: c.execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,v))
    def get_kv(self,k):
        with self.con() as c:r=c.execute("SELECT value FROM kv WHERE key=?",(k,)).fetchone(); return r[0] if r else ""


class Collector:
    def _run(self,h,cmd,timeout=12):
        if h.get("mode")=="local": return subprocess.run(["bash","-lc",cmd],text=True,capture_output=True,timeout=timeout)
        target=f"{h.get('ssh_user','')}@{h['address']}"; args=["ssh","-o","BatchMode=yes","-o",f"ConnectTimeout={timeout}","-p",str(h.get("ssh_port",22))]
        if not h.get("strict_host_key_checking",True): args += ["-o","StrictHostKeyChecking=no"]
        if h.get("ssh_key"): args += ["-i",h["ssh_key"]]
        return subprocess.run(args+[target,cmd],text=True,capture_output=True,timeout=timeout+3)
    def collect(self,h):
        metrics=[]
        cmd="""set +e; echo LOAD=$(cut -d' ' -f1 /proc/loadavg); free -b | awk '/Mem:/{print "RAM=" $3*100/$2} /Swap:/{if($2>0)print "SWAP=" $3*100/$2;else print "SWAP=0"}'; df -P / | awk 'NR==2{gsub(/%/,"",$5);print "DISK=" $5}'; echo UPTIME=$(cut -d. -f1 /proc/uptime); journalctl -k --since '-10 min' --no-pager 2>/dev/null | grep -ci 'out of memory\|killed process' | xargs echo OOM="""
        try:r=self._run(h,cmd); ok=r.returncode==0
        except Exception as e:r=None;ok=False;metrics.append(Metric("reachable",0,str(e)))
        if r is not None: metrics.append(Metric("reachable",1 if ok else 0,r.stderr[-500:])); metrics.append(Metric("ssh_reachable",1 if ok else 0))
        if ok:
            for line in r.stdout.splitlines():
                if "=" in line:
                    k,v=line.split("=",1)
                    try: metrics.append(Metric({"LOAD":"load1","RAM":"ram_used_pct","SWAP":"swap_used_pct","DISK":"root_used_pct","UPTIME":"uptime_seconds","OOM":"oom_events"}[k],float(v)))
                    except Exception: pass
            try:
                d=self._run(h,"docker info >/dev/null 2>&1",8); metrics.append(Metric("docker_up",1 if d.returncode==0 else 0,d.stderr[-300:]))
            except Exception: metrics.append(Metric("docker_up",0))
            for c in h.get("containers",[]):
                q=self._run(h,f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(c)} 2>/dev/null",8); metrics.append(Metric(f"container.{c}.running",1 if q.stdout.strip()=="true" else 0,q.stderr[-300:]))
            for s in h.get("services",[]):
                q=self._run(h,f"systemctl is-active {shlex.quote(s)}",8); metrics.append(Metric(f"service.{s}.active",1 if q.stdout.strip()=="active" else 0,q.stderr[-300:]))
        for chk in h.get("http_checks",[]):
            start=time.monotonic()
            try:
                with urllib.request.urlopen(chk["url"],timeout=chk.get("timeout",5)) as resp: code=resp.status
                metrics += [Metric(f"http.{chk['name']}.up",1 if 200<=code<500 else 0,str(code)),Metric(f"http.{chk['name']}.latency_ms",(time.monotonic()-start)*1000)]
            except Exception as e: metrics += [Metric(f"http.{chk['name']}.up",0,str(e)),Metric(f"http.{chk['name']}.latency_ms",(time.monotonic()-start)*1000)]
        return metrics
    def execute(self,h,a):
        verb,target=a.split(":",1)
        if not SAFE.fullmatch(target): raise ValueError("unsafe target")
        commands={"restart_container":f"docker restart {shlex.quote(target)}","restart_service":f"sudo -n systemctl restart {shlex.quote(target)}","journal_vacuum":"sudo -n journalctl --vacuum-time=14d"}
        return self._run(h,commands[verb],60)


class Analyzer:
    def __init__(self,db,history_window=1440,min_samples=20): self.db=db; self.history_window=history_window; self.min_samples=min_samples
    @staticmethod
    def robust_zscore(value,history):
        if len(history)<3:return 0
        med=statistics.median(history); mad=statistics.median(abs(x-med) for x in history); scale=max(1.4826*mad,max(abs(med)*.05,1)); return abs(value-med)/scale
    def detect(self,host,metrics):
        out=[]
        for m in metrics:
            score=self.robust_zscore(m.value,self.db.history(host,m.name,self.history_window)); sev=0; reason=""
            hard=(m.name in {"reachable","ssh_reachable","docker_up"} or m.name.endswith(".running") or m.name.endswith(".active") or m.name.endswith(".up")) and m.value<1
            if hard: sev=9; reason="недоступно"
            elif m.name=="root_used_pct" and m.value>=90: sev=10 if m.value>=95 else 7; reason="заполняется диск"
            elif m.name in {"ram_used_pct","swap_used_pct"} and m.value>=90: sev=8; reason="нехватка памяти"
            elif m.name=="oom_events" and m.value>0: sev=10; reason="OOM"
            elif score>=3 and len(self.db.history(host,m.name,self.history_window))>=self.min_samples: sev=min(8,max(3,int(score))); reason="отклонение от личной нормы"
            if sev: out.append(Anomaly(m.name,m.value,score,sev,reason))
        return out
    def correlate(self,h,metrics,anoms):
        if not anoms:return None
        vals={m.name:m.value for m in metrics}; names={a.metric for a in anoms}; cause="metric_anomaly"; conf=.65; summary="Обнаружено необычное состояние"
        if vals.get("reachable",1)==0: cause,conf,summary="host_unreachable",.98,"Узел недоступен"
        elif vals.get("ssh_reachable",1)==0: cause,conf,summary="ssh_unavailable",.95,"SSH недоступен"
        elif vals.get("root_used_pct",0)>=95: cause,conf,summary="disk_pressure",.97,"Корневой диск почти заполнен"
        elif vals.get("oom_events",0)>0 or vals.get("ram_used_pct",0)>=95: cause,conf,summary="memory_pressure",.93,"Нехватка оперативной памяти"
        elif vals.get("docker_up",1)==0: cause,conf,summary="docker_engine_down",.95,"Docker Engine недоступен"
        elif any(x.startswith("container.") for x in names): cause,conf,summary="container_failure",.9,"Один или несколько контейнеров остановлены"
        elif any(x.startswith("service.") for x in names): cause,conf,summary="systemd_failure",.88,"Systemd-сервис остановлен"
        elif any(x.startswith("http.") and x.endswith(".up") for x in names): cause,conf,summary="http_service_failure",.85,"Веб-сервис не отвечает"
        severity=max(a.severity for a in anoms); blast=min(10,len(anoms)); priority=round(min(100,severity*3+blast*2+conf*20+int(h.get("importance",5))*3))
        return IncidentCandidate(h["name"],cause,conf,severity,priority,summary,f"{h['name']}:{cause}",anoms)


class ActionPlanner:
    LEVELS={"restart_container":1,"journal_vacuum":1,"restart_service":2}
    def __init__(self,db):self.db=db
    def candidates(self,i,h):
        s=[]
        if i.root_cause=="container_failure": s=[f"restart_container:{a.metric.split('.')[1]}" for a in i.anomalies if a.metric.startswith("container.")]
        elif i.root_cause=="docker_engine_down":s=["restart_service:docker"]
        elif i.root_cause=="systemd_failure":s=[f"restart_service:{a.metric.split('.')[1]}" for a in i.anomalies if a.metric.startswith("service.")]
        elif i.root_cause=="disk_pressure":s=["journal_vacuum:logs"]
        return [x for x in s if x in h.get("allowed_actions",[])]
    def choose(self,i,h):
        scored=[]
        for a in self.candidates(i,h):
            verb=a.split(":",1)[0]; score=self.db.action_probability(a)*{"restart_container":80,"restart_service":85,"journal_vacuum":70}[verb]-{"restart_container":11,"restart_service":33,"journal_vacuum":14}[verb]-(40 if self.db.action_in_cooldown(h["name"],a) else 0); scored.append((score,a))
        return max(scored)[1] if scored and max(scored)[0]>0 else None
    def level(self,a):return self.LEVELS[a.split(":",1)[0]]


class Engine:
    def __init__(self,config,db): self.config=config; self.db=db; self.collector=Collector(); self.analyzer=Analyzer(db,config.history_window,config.min_samples); self.planner=ActionPlanner(db); self.stop_event=threading.Event(); self.cycle_lock=threading.Lock(); self.last_cycle=db.get_kv("last_cycle") or None; self.last_error=None
    def run_forever(self):
        self.stop_event.wait(2)
        while not self.stop_event.is_set():
            t=time.monotonic()
            try:self.run_cycle();self.last_error=None
            except Exception as e:LOG.exception("cycle failed");self.last_error=str(e)
            self.stop_event.wait(max(1,self.config.poll_interval-(time.monotonic()-t)))
    def run_cycle(self):
        if not self.cycle_lock.acquire(False):return
        try:
            self.config.reload()
            for h in self.config.hosts:self._process(h)
            self.last_cycle=now();self.db.set_kv("last_cycle",self.last_cycle)
        finally:self.cycle_lock.release()
    def _process(self,h):
        m=self.collector.collect(h); a=self.analyzer.detect(h["name"],m); self.db.insert_metrics(h["name"],m); i=self.analyzer.correlate(h,m,a); active=set()
        if i:
            i.recommended_action=self.planner.choose(i,h); iid,_=self.db.upsert_incident(i);active.add(i.fingerprint)
            if i.recommended_action and self.config.auto_remediation and self.planner.level(i.recommended_action)<=self.config.max_auto_level and not self.db.action_in_cooldown(h["name"],i.recommended_action):self._act(h,iid,i)
        self.db.close_other_incidents(h["name"],active)
    def _act(self,h,iid,i):
        aid=self.db.start_action(iid,h["name"],i.recommended_action)
        try:r=self.collector.execute(h,i.recommended_action);out=(r.stdout+"\n"+r.stderr).strip();ok=r.returncode==0
        except Exception as e:out=str(e);ok=False
        if ok:time.sleep(self.config.verify_delay);m=self.collector.collect(h);self.db.insert_metrics(h["name"],m);ok=self.analyzer.correlate(h,m,self.analyzer.detect(h["name"],m)) is None
        self.db.finish_action(aid,ok,out);return {"success":ok,"output":out}
    def manual_action(self,host,action,incident_id=None):
        h=self.config.host(host)
        if not h:raise KeyError("unknown host")
        if action not in h.get("allowed_actions",[]):raise PermissionError("not allowlisted")
        i=IncidentCandidate(host,"manual",1,1,1,"Manual",f"{host}:manual",[],action);return self._act(h,incident_id,i)
    def status(self):
        inc=self.db.incidents(200,"open"); by={x["host"]:x for x in inc}; hosts=[]
        for h in self.config.hosts:hosts.append({"name":h["name"],"address":h.get("address",""),"importance":h.get("importance",5),"metrics":self.db.latest_metrics(h["name"]),"incident":by.get(h["name"])})
        return {"version":"0.1.0","last_cycle":self.last_cycle,"last_error":self.last_error,"auto_remediation":self.config.auto_remediation,"hosts":hosts,"open_incidents":inc,"recent_actions":self.db.recent_actions()}
