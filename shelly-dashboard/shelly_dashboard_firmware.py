#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, sys, time, threading, ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request, render_template_string
import requests
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    HAS_ZEROCONF=True
except Exception:
    HAS_ZEROCONF=False
app=Flask(__name__)
class State:
    devices={}; lock=threading.Lock(); refreshing=False; fw=False; last_refresh=None; last_fw=None
    cfg={'timeout':3,'refresh':15,'mdns_timeout':5,'user':None,'password':None,'devices':[],'network':None,'use_mdns':True}
s=State()
def now(): return datetime.now().isoformat(timespec='seconds')
def auth1(): return (s.cfg['user'],s.cfg['password']) if s.cfg.get('user') and s.cfg.get('password') else None
def auth2(): return requests.auth.HTTPDigestAuth('admin',s.cfg['password']) if s.cfg.get('password') else None
def gen(ip):
    try:
        r=requests.get(f'http://{ip}/shelly',timeout=s.cfg['timeout'])
        if r.status_code==200: return int(r.json().get('gen',1))
    except Exception: pass
    return 0
class Listener(ServiceListener):
    def __init__(self): self.found={}
    def add_service(self,zc,t,n):
        info=zc.get_service_info(t,n)
        if info and info.parsed_scoped_addresses():
            ip=info.parsed_scoped_addresses()[0]; self.found[ip]={'ip':ip}
    def remove_service(self,zc,t,n): pass
    def update_service(self,zc,t,n): pass
def mdns():
    if not HAS_ZEROCONF: return {}
    z=Zeroconf(); l=Listener(); b=ServiceBrowser(z,'_shelly._tcp.local.',l)
    time.sleep(s.cfg['mdns_timeout']); b.cancel(); z.close(); return l.found
def scan(cidr):
    out={}; timeout=min(float(s.cfg['timeout']),1.5)
    def one(ip):
        try:
            r=requests.get(f'http://{ip}/shelly',timeout=timeout)
            if r.status_code==200: return ip,{'ip':ip}
        except Exception: pass
        return None,None
    with ThreadPoolExecutor(max_workers=64) as ex:
        futures=[ex.submit(one,str(ip)) for ip in ipaddress.IPv4Network(cidr,strict=False).hosts()]
        for f in as_completed(futures):
            ip,d=f.result()
            if ip: out[ip]=d
    return out
def fw_status(cur=None,latest=None,err=None,has=None):
    d={'firmware_current':cur,'firmware_latest':latest,'firmware_checked_at':now()}
    if err: d.update({'firmware_status':'error','firmware_error':err,'has_update':None})
    elif has is True or (latest and cur and str(latest)!=str(cur)): d.update({'firmware_status':'update_available','has_update':True})
    elif has is False or cur: d.update({'firmware_status':'latest','has_update':False})
    else: d.update({'firmware_status':'unknown','has_update':None})
    return d
def check_fw(ip,dev=None):
    dev=dev or {}; g=int(dev.get('generation') or gen(ip) or 1); cur=dev.get('firmware_current') or dev.get('firmware')
    if g>=2:
        try:
            r=requests.get(f'http://{ip}/rpc/Shelly.CheckForUpdate',timeout=s.cfg['timeout'],auth=auth2())
            if r.status_code!=200: return fw_status(cur,err=f'HTTP {r.status_code}')
            stable=(r.json().get('stable') or {}); latest=stable.get('version') or stable.get('ver') or stable.get('fw_id')
            return fw_status(cur,latest,has=(True if latest and str(latest)!=str(cur) else False))
        except Exception as e: return fw_status(cur,err=str(e))
    else:
        latest=None; has=None
        try:
            try: requests.get(f'http://{ip}/ota/check',timeout=s.cfg['timeout'],auth=auth1())
            except Exception: pass
            for url in (f'http://{ip}/ota',f'http://{ip}/status'):
                try:
                    r=requests.get(url,timeout=s.cfg['timeout'],auth=auth1())
                    if r.status_code==200:
                        data=r.json(); upd=data.get('update',data) if isinstance(data,dict) else {}
                        latest=upd.get('new_version') or upd.get('version') or latest
                        cur=upd.get('old_version') or upd.get('current_version') or cur
                        if 'has_update' in upd: has=bool(upd.get('has_update'))
                except Exception: pass
            return fw_status(cur,latest,has=has)
        except Exception as e: return fw_status(cur,err=str(e))
def compute_health(d):
    score=0; issues=[]
    if d.get('online'): score+=35
    else: issues.append('offline')
    ws=d.get('web_status')
    if ws=='ok' and not d.get('web_auth_required'): score+=15
    elif ws=='ok' and d.get('web_auth_required'): score+=10; issues.append('web_auth')
    elif ws=='timeout': issues.append('web_timeout')
    elif ws=='error': issues.append('web_error')
    elif ws is None: pass
    fs=d.get('firmware_status')
    if fs=='latest': score+=15
    elif fs=='update_available': score+=7; issues.append('fw_update')
    elif fs=='error': issues.append('fw_check_error')
    rssi=d.get('wifi_rssi')
    if rssi is None: pass
    elif rssi>-60: score+=10
    elif rssi>-70: score+=7
    elif rssi>-80: score+=3; issues.append('wifi_weak')
    else: issues.append('wifi_poor')
    wifi_ok=rssi is not None
    eth_ok=bool(d.get('eth_connected'))
    if wifi_ok or eth_ok: score+=10
    else: issues.append('no_connectivity')
    if d.get('error'): issues.append('api_error')
    else: score+=5
    up=d.get('uptime')
    if up is None: pass
    elif up>=300: score+=5
    else: issues.append('recent_reboot')
    lat=d.get('web_latency_ms')
    if lat is None: pass
    elif lat<500: score+=5
    elif lat<1000: score+=3
    elif lat<2000: score+=1; issues.append('web_slow')
    else: issues.append('web_slow')
    score=max(0,min(100,score))
    level='good' if score>=85 else ('warn' if score>=60 else 'bad')
    return {'health_score':score,'health_level':level,'health_issues':issues}
def check_web(ip):
    t0=time.time()
    try:
        r=requests.get(f'http://{ip}/',timeout=s.cfg['timeout'],auth=auth1(),allow_redirects=True)
        ms=int((time.time()-t0)*1000)
        ok=200<=r.status_code<400 or r.status_code==401
        return {'web_status':'ok' if ok else 'error','web_code':r.status_code,'web_latency_ms':ms,'web_auth_required':r.status_code==401,'web_checked_at':now()}
    except requests.exceptions.Timeout:
        return {'web_status':'timeout','web_code':None,'web_latency_ms':int((time.time()-t0)*1000),'web_checked_at':now()}
    except Exception as e:
        return {'web_status':'error','web_code':None,'web_error':str(e)[:120],'web_latency_ms':int((time.time()-t0)*1000),'web_checked_at':now()}
def query(ip):
    g=gen(ip); d={'ip':ip,'generation':g or 1,'online':False}
    try:
        if g>=2:
            info=requests.get(f'http://{ip}/rpc/Shelly.GetDeviceInfo',timeout=s.cfg['timeout'],auth=auth2()).json()
            d.update({'online':True,'model':info.get('model') or info.get('app'),'firmware':info.get('ver') or info.get('fw_id'),'firmware_current':info.get('ver') or info.get('fw_id'),'generation':info.get('gen',2),'hostname':info.get('id') or info.get('hostname')})
            try:
                st=requests.get(f'http://{ip}/rpc/Shelly.GetStatus',timeout=s.cfg['timeout'],auth=auth2()).json(); w=st.get('wifi',{}); sys=st.get('sys',{}); eth=st.get('eth') or {}
                d.update({'wifi_rssi':w.get('rssi'),'wifi_ssid':w.get('ssid'),'uptime':sys.get('uptime'),'switches':[],'total_power_w':0,'eth_ip':eth.get('ip'),'eth_connected':bool(eth.get('ip')),'eth_supported':'eth' in st})
                for k,v in st.items():
                    if k.startswith('switch:'):
                        p=v.get('apower',0) or 0; d['switches'].append({'id':k.split(':')[1],'is_on':v.get('output',False),'power_w':p}); d['total_power_w']+=p
                d['total_power_w']=round(d['total_power_w'],2)
            except Exception: pass
            try:
                cfg=requests.get(f'http://{ip}/rpc/Shelly.GetConfig',timeout=s.cfg['timeout'],auth=auth2()).json(); dev=((cfg.get('sys')or{}).get('device')or{}); d['device_name']=dev.get('name'); d['hostname']=d.get('hostname') or dev.get('hostname') or dev.get('mac')
                names={}
                for k,v in cfg.items():
                    if k.startswith(('switch:','input:','cover:','light:')) and isinstance(v,dict): names[k]=v.get('name')
                for swx in d.get('switches',[]):
                    nm=names.get(f"switch:{swx['id']}")
                    if nm: swx['name']=nm
                d['channel_names']={k:v for k,v in names.items() if v}
            except Exception: pass
            if not d.get('device_name'):
                try:
                    sc=requests.get(f'http://{ip}/rpc/Sys.GetConfig',timeout=s.cfg['timeout'],auth=auth2()).json(); d['device_name']=((sc.get('device') or {}).get('name'))
                except Exception: pass
            if not d.get('device_name'): d['device_name']=d.get('hostname') or d.get('model')
        else:
            info=requests.get(f'http://{ip}/shelly',timeout=s.cfg['timeout'],auth=auth1()).json()
            d.update({'online':True,'model':info.get('type'),'firmware':info.get('fw'),'firmware_current':info.get('fw'),'hostname':info.get('hostname') or info.get('mac')})
            try:
                st=requests.get(f'http://{ip}/status',timeout=s.cfg['timeout'],auth=auth1()).json(); w=st.get('wifi_sta',{})
                d.update({'wifi_rssi':w.get('rssi'),'switches':[{'id':i,'is_on':x.get('ison',False)} for i,x in enumerate(st.get('relays',[]))]})
                m=st.get('meters',[]); d['total_power_w']=round(sum(x.get('power',0) or 0 for x in m),2)
            except Exception: pass
            try:
                sett=requests.get(f'http://{ip}/settings',timeout=s.cfg['timeout'],auth=auth1()).json(); d['device_name']=sett.get('name'); d['hostname']=((sett.get('device') or {}).get('hostname')) or d.get('hostname')
                rel_names={i:(r.get('name') if isinstance(r,dict) else None) for i,r in enumerate(sett.get('relays') or [])}
                for swx in d.get('switches',[]):
                    nm=rel_names.get(int(swx['id'])) if str(swx['id']).isdigit() else None
                    if nm: swx['name']=nm
                d['channel_names']={f'switch:{i}':n for i,n in rel_names.items() if n}
            except Exception: pass
            if not d.get('device_name'): d['device_name']=d.get('hostname') or d.get('model')
        d.update(check_fw(ip,d)); d.update(check_web(ip)); d.update(compute_health(d)); return d
    except Exception as e:
        d['error']=str(e); d.update(check_web(ip)); d.update(compute_health(d)); return d
def refresh():
    s.refreshing=True
    with s.lock: ips=list(s.devices.keys())
    res={}
    with ThreadPoolExecutor(max_workers=24) as ex:
        for f in as_completed([ex.submit(query,ip) for ip in ips]):
            q=f.result(); res[q['ip']]=q
    with s.lock: s.devices.update(res); s.last_refresh=now()
    s.refreshing=False
def discover():
    found={ip:{'ip':ip} for ip in s.cfg['devices']}
    if s.cfg['use_mdns']: found.update(mdns())
    if s.cfg['network']: found.update(scan(s.cfg['network']))
    with s.lock:
        for ip in found: s.devices.setdefault(ip,{'ip':ip,'online':False,'error':'waiting'})
    refresh()
def fw_all():
    s.fw=True
    with s.lock: snap=dict(s.devices)
    with ThreadPoolExecutor(max_workers=24) as ex:
        futs={ex.submit(check_fw,ip,d):ip for ip,d in snap.items()}
        for f in as_completed(futs):
            ip=futs[f]
            with s.lock:
                s.devices.setdefault(ip,{'ip':ip}).update(f.result())
                s.devices[ip].update(compute_health(s.devices[ip]))
    s.last_fw=now(); s.fw=False
def relay(ip,rid,act):
    try:
        if gen(ip)>=2:
            url=f"http://{ip}/rpc/Switch.Set?id={rid}&on={'true' if act=='on' else 'false'}" if act!='toggle' else f'http://{ip}/rpc/Switch.Toggle?id={rid}'
            r=requests.get(url,timeout=s.cfg['timeout'],auth=auth2())
        else: r=requests.get(f'http://{ip}/relay/{rid}?turn={act}',timeout=s.cfg['timeout'],auth=auth1())
        return r.status_code==200,r.text
    except Exception as e: return False,str(e)
@app.route('/')
def home(): return render_template_string(HTML,refresh=s.cfg['refresh'])
@app.get('/api/devices')
def api_devices():
    with s.lock: return jsonify({'devices':list(s.devices.values()),'last_refresh':s.last_refresh,'last_firmware_check':s.last_fw,'refreshing':s.refreshing,'firmware_checking':s.fw})
@app.get('/api/summary')
def api_summary():
    with s.lock: ds=list(s.devices.values())
    return jsonify({'total':len(ds),'online':sum(1 for d in ds if d.get('online')),'offline':sum(1 for d in ds if not d.get('online')),'power':round(sum(d.get('total_power_w',0) or 0 for d in ds),2),'updates':sum(1 for d in ds if d.get('has_update') is True),'latest':sum(1 for d in ds if d.get('firmware_status')=='latest'),'web_ok':sum(1 for d in ds if d.get('web_status')=='ok'),'web_bad':sum(1 for d in ds if d.get('web_status') in ('error','timeout')),'health_avg':round(sum(d.get('health_score',0) or 0 for d in ds)/len(ds),1) if ds else 0,'health_issues':sum(1 for d in ds if d.get('health_level')!='good')})
@app.post('/api/refresh')
def api_refresh(): threading.Thread(target=refresh,daemon=True).start(); return jsonify(ok=True)
@app.post('/api/discover')
def api_discover(): threading.Thread(target=discover,daemon=True).start(); return jsonify(ok=True)
@app.post('/api/firmware/check')
def api_fw_all(): threading.Thread(target=fw_all,daemon=True).start(); return jsonify(ok=True)
@app.post('/api/device/<ip>/firmware/check')
def api_fw_one(ip):
    with s.lock: dev=s.devices.get(ip,{'ip':ip})
    fw=check_fw(ip,dev)
    with s.lock:
        s.devices.setdefault(ip,{'ip':ip}).update(fw)
        s.devices[ip].update(compute_health(s.devices[ip]))
    return jsonify(fw)
@app.post('/api/device/<ip>/web/check')
def api_web_one(ip):
    w=check_web(ip)
    with s.lock:
        s.devices.setdefault(ip,{'ip':ip}).update(w)
        s.devices[ip].update(compute_health(s.devices[ip]))
    return jsonify(w)
@app.post('/api/devices/add')
def api_add():
    ip=(request.json or {}).get('ip','').strip()
    if not ip: return jsonify(error='missing ip'),400
    with s.lock: s.devices[ip]={'ip':ip,'online':False,'error':'waiting'}
    threading.Thread(target=lambda: s.devices.update({ip:query(ip)}),daemon=True).start(); return jsonify(ok=True)
@app.post('/api/device/<ip>/relay/<rid>/<act>')
def api_relay(ip,rid,act):
    ok,msg=relay(ip,rid,act)
    if ok:
        with s.lock: s.devices[ip]=query(ip)
    return jsonify(success=ok,message=msg)
def loop():
    while True:
        time.sleep(s.cfg['refresh'])
        try: refresh()
        except Exception: pass
HTML=r"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shelly Dashboard</title>
<style>
:root{
  --bg:#0b1020; --panel:#151b2e; --panel2:#111a31; --border:#26314f;
  --text:#e8eefc; --mut:#93a4c7; --accent:#3b82f6; --ok:#22c55e;
  --warn:#f59e0b; --bad:#ef4444; --shadow:0 6px 24px rgba(0,0,0,.25);
}
html[data-theme="light"]{
  --bg:#f4f6fb; --panel:#ffffff; --panel2:#ffffff; --border:#e2e8f0;
  --text:#0f172a; --mut:#64748b; --shadow:0 6px 24px rgba(15,23,42,.08);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,Arial,sans-serif;min-height:100vh}
.top{position:sticky;top:0;z-index:10;padding:14px 22px;background:var(--panel2);
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px;flex-wrap:wrap;box-shadow:var(--shadow)}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:1.1rem}
.brand .logo{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,#3b82f6,#22c55e);
  display:grid;place-items:center;color:white;font-weight:900}
.spacer{flex:1}
.btn{cursor:pointer;border:0;border-radius:10px;padding:9px 14px;background:var(--accent);color:#fff;
  font-weight:700;display:inline-flex;align-items:center;gap:6px;transition:transform .08s,opacity .15s}
.btn:hover{opacity:.9} .btn:active{transform:scale(.97)}
.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
.btn.warn{background:var(--warn)} .btn.ok{background:var(--ok)} .btn.bad{background:var(--bad)}
.btn.sm{padding:6px 10px;font-size:.8rem;border-radius:8px}
.wrap{padding:22px;max-width:1400px;margin:0 auto}
.stats{display:flex;flex-wrap:nowrap;gap:8px;margin-bottom:14px;overflow-x:auto;padding-bottom:4px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px 12px;box-shadow:var(--shadow);
  display:flex;align-items:center;gap:8px;flex:1 1 0;min-width:120px;white-space:nowrap}
.stat .v{font-size:1.15rem;font-weight:800;line-height:1}
.stat .l{color:var(--mut);font-size:.7rem;margin:0;text-transform:uppercase;letter-spacing:.03em}
.stat .ico{float:none;font-size:1.05rem;opacity:.7;margin:0}
.stat .col{display:flex;flex-direction:column;min-width:0}
@media (max-width:900px){.stats{flex-wrap:wrap}.stat{flex:1 1 calc(33% - 8px);min-width:0}}
.bar{display:flex;gap:10px;margin:8px 0 18px;flex-wrap:wrap;align-items:center}
.inp{padding:10px 12px;border-radius:10px;background:var(--panel);color:var(--text);
  border:1px solid var(--border);min-width:160px;outline:none;transition:border-color .15s}
.inp:focus{border-color:var(--accent)}
.search{flex:1;min-width:220px}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{cursor:pointer;padding:6px 12px;border-radius:999px;border:1px solid var(--border);
  background:transparent;color:var(--mut);font-size:.85rem;font-weight:600}
.chip.active{background:var(--accent);color:#fff;border-color:transparent}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}
.grid.view-small{grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.grid.view-small .card{padding:12px;gap:6px;font-size:.85rem}
.grid.view-small .card h3{font-size:.95rem}
.grid.view-small .row{padding:3px 0;font-size:.78rem}
.grid.view-small .actions{margin-top:2px}
.grid.view-small .btn.sm{padding:4px 8px;font-size:.72rem}
.grid.view-list{display:flex;flex-direction:column;gap:6px}
.grid.view-list .card{flex-direction:row;align-items:center;gap:14px;padding:10px 14px;flex-wrap:wrap}
.grid.view-list .card:hover{transform:none}
.grid.view-list .head{flex:1 1 220px;min-width:200px}
.grid.view-list .row{border:0;padding:0;font-size:.82rem;display:flex;gap:4px}
.grid.view-list .row .k{display:none}
.grid.view-list .switches{flex:0 0 auto;flex-direction:row;gap:8px;margin:0}
.grid.view-list .actions{margin:0}
.grid.view-list .l-cell{display:flex;flex-direction:column;min-width:80px}
.grid.view-list .l-cell .lbl{color:var(--mut);font-size:.65rem;text-transform:uppercase;letter-spacing:.04em}
.grid.view-list .l-cell .val{font-weight:600;font-size:.85rem}
.view-btns{display:inline-flex;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.view-btns button{background:transparent;border:0;color:var(--mut);padding:7px 10px;cursor:pointer;font-size:1rem}
.view-btns button.active{background:var(--accent);color:#fff}
.health{display:flex;align-items:center;gap:8px;margin:2px 0 4px}
.health .hbar{flex:1;height:8px;border-radius:6px;background:rgba(148,163,184,.25);overflow:hidden;position:relative}
.health .hfill{height:100%;border-radius:6px;transition:width .4s}
.health.good .hfill{background:var(--ok)}
.health.warn .hfill{background:var(--warn)}
.health.bad .hfill{background:var(--bad)}
.health .hval{font-weight:800;font-size:.85rem;min-width:48px;text-align:right}
.health.good .hval{color:var(--ok)} .health.warn .hval{color:var(--warn)} .health.bad .hval{color:var(--bad)}
.issues{display:flex;gap:4px;flex-wrap:wrap;margin-top:-2px}
.issues .pill{font-size:.66rem;padding:2px 7px;border-radius:999px;background:rgba(245,158,11,.15);color:var(--warn);font-weight:700}
.issues .pill.bad{background:rgba(239,68,68,.15);color:var(--bad)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px;
  box-shadow:var(--shadow);display:flex;flex-direction:column;gap:10px;transition:transform .12s}
.card:hover{transform:translateY(-2px)}
.card h3{margin:0;font-size:1.05rem;display:flex;align-items:center;gap:8px}
.card .ip{color:var(--mut);font-size:.8rem;font-family:ui-monospace,Consolas,monospace}
.head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.badge{display:inline-block;border-radius:999px;padding:3px 9px;font-size:.7rem;font-weight:800;letter-spacing:.02em}
.b-ok{background:rgba(34,197,94,.15);color:var(--ok)}
.b-bad{background:rgba(239,68,68,.15);color:var(--bad)}
.b-warn{background:rgba(245,158,11,.15);color:var(--warn)}
.b-info{background:rgba(59,130,246,.15);color:var(--accent)}
.row{display:flex;justify-content:space-between;gap:8px;padding:6px 0;border-bottom:1px dashed var(--border);font-size:.88rem}
.row:last-child{border-bottom:0}
.row .k{color:var(--mut)} .row .vv{font-weight:600}
.switches{display:flex;flex-direction:column;gap:6px;margin-top:4px}
.sw-row{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;
  background:rgba(0,0,0,.15);border-radius:8px}
html[data-theme="light"] .sw-row{background:rgba(15,23,42,.04)}
.toggle{width:44px;height:24px;border-radius:20px;background:#475569;position:relative;cursor:pointer;
  transition:background .2s;flex-shrink:0}
.toggle:before{content:'';position:absolute;width:18px;height:18px;border-radius:50%;background:#fff;
  top:3px;left:3px;transition:left .2s}
.toggle.on{background:var(--ok)} .toggle.on:before{left:23px}
.actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.empty{text-align:center;padding:60px 20px;color:var(--mut)}
.empty .big{font-size:3rem;margin-bottom:10px}
.foot{margin-top:18px;color:var(--mut);font-size:.8rem;text-align:center}
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.3);
  border-top-color:#fff;border-radius:50%;animation:sp 1s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--panel);
  border:1px solid var(--border);color:var(--text);padding:10px 16px;border-radius:10px;
  box-shadow:var(--shadow);opacity:0;pointer-events:none;transition:opacity .2s;z-index:50}
.toast.show{opacity:1}
</style>
</head>
<body>
<div class="top">
  <div class="brand"><div class="logo">S</div>Shelly Dashboard</div>
  <div class="spacer"></div>
  <select class="inp" id="langSel" onchange="setLang(this.value)" style="padding:6px 8px;min-width:auto">
    <option value="auto">🌐 Auto</option>
    <option value="pl">🇵🇱 Polski</option>
    <option value="en">🇬🇧 English</option>
  </select>
  <span class="view-btns" role="group" aria-label="View">
    <button id="vw-large" onclick="setView('large')" title="Large">▣</button>
    <button id="vw-small" onclick="setView('small')" title="Small">▦</button>
    <button id="vw-list" onclick="setView('list')" title="List">☰</button>
  </span>
  <button class="btn ghost sm" id="themeBtn" onclick="toggleTheme()">🌓 <span data-i18n="theme">Motyw</span></button>
  <button class="btn" onclick="call('api/discover','msg_discovering')">🔍 <span data-i18n="discover">Odkryj</span></button>
  <button class="btn ghost" onclick="call('api/refresh','msg_refreshing')">🔄 <span data-i18n="refresh">Odśwież</span></button>
  <button class="btn warn" onclick="call('api/firmware/check','msg_checking_fw')">⬆ <span data-i18n="firmware">Firmware</span></button>
</div>

<div class="wrap">
  <div class="stats">
    <div class="stat"><span class="ico">📦</span><span class="col"><span class="v" id="total">-</span><span class="l" data-i18n="devices">Urządzenia</span></span></div>
    <div class="stat"><span class="ico">🟢</span><span class="col"><span class="v" id="online">-</span><span class="l" data-i18n="online">Online</span></span></div>
    <div class="stat"><span class="ico">🔴</span><span class="col"><span class="v" id="offline">-</span><span class="l" data-i18n="offline">Offline</span></span></div>
    <div class="stat"><span class="ico">⚡</span><span class="col"><span class="v" id="power">-</span><span class="l" data-i18n="total_power">Moc (W)</span></span></div>
    <div class="stat"><span class="ico">⬆</span><span class="col"><span class="v" id="updates">-</span><span class="l" data-i18n="updates">Aktualizacje</span></span></div>
    <div class="stat"><span class="ico">✅</span><span class="col"><span class="v" id="latest">-</span><span class="l" data-i18n="up_to_date">Aktualne</span></span></div>
    <div class="stat"><span class="ico">🌐</span><span class="col"><span class="v" id="web_ok">-</span><span class="l" data-i18n="web_ok_stat">Web OK</span></span></div>
    <div class="stat"><span class="ico">⚠️</span><span class="col"><span class="v" id="web_bad">-</span><span class="l" data-i18n="web_bad_stat">Web błąd</span></span></div>
    <div class="stat"><span class="ico">❤️</span><span class="col"><span class="v" id="health_avg">-</span><span class="l" data-i18n="health_avg">Kondycja</span></span></div>
    <div class="stat"><span class="ico">🚨</span><span class="col"><span class="v" id="health_issues">-</span><span class="l" data-i18n="health_issues_stat">Problemy</span></span></div>
  </div>

  <div class="bar">
    <input class="inp search" id="q" data-i18n-ph="search_ph" placeholder="🔎 Szukaj po nazwie / IP / modelu..." oninput="render()">
    <input class="inp" id="ip" data-i18n-ph="ip_ph" placeholder="np. 192.168.1.50" style="max-width:180px">
    <button class="btn ok" onclick="add()">＋ <span data-i18n="add">Dodaj</span></button>
    <div class="chips">
      <span class="chip active" data-f="all" onclick="setFilter('all')" data-i18n="all">Wszystkie</span>
      <span class="chip" data-f="online" onclick="setFilter('online')" data-i18n="online">Online</span>
      <span class="chip" data-f="offline" onclick="setFilter('offline')" data-i18n="offline">Offline</span>
      <span class="chip" data-f="update" onclick="setFilter('update')">⬆ <span data-i18n="updates">Aktualizacje</span></span>
      <span class="chip" data-f="issues" onclick="setFilter('issues')">🚨 <span data-i18n="issues_filter">Problemy</span></span>
    </div>
  </div>

  <div id="grid" class="grid"></div>
  <div class="foot" id="foot" data-i18n="loading">Ładowanie...</div>
</div>

<div class="toast" id="toast"></div>

<script>
const I18N={
  pl:{theme:'Motyw',discover:'Odkryj',refresh:'Odśwież',firmware:'Firmware',devices:'Urządzenia',online:'Online',offline:'Offline',
     total_power:'Moc (W)',updates:'Aktualizacje',up_to_date:'Aktualne',all:'Wszystkie',add:'Dodaj',
     search_ph:'🔎 Szukaj po nazwie / IP / modelu...',ip_ph:'np. 192.168.1.50',loading:'Ładowanie...',
     last_refresh:'Ostatnie odświeżenie',refreshing_status:'⏳ odświeżanie...',
     model:'Model',hostname:'Hostname',fw:'Firmware',wifi:'WiFi',eth:'Ethernet',uptime:'Czas pracy',power:'Moc',channel:'Kanał',
     check_fw:'⬆ Sprawdź FW',web:'🔗 Panel',check_web:'🌐 Test Web',no_devices:'Brak urządzeń pasujących do filtra',
     eth_na:'N/A',eth_none:'brak',eth_disc:'odłączony',eth_conn:'połączony',
     web_label:'Web UI',web_ok:'OK',web_timeout:'timeout',web_error:'błąd',web_auth:'wymaga logowania',web_never:'nie sprawdzano',
     web_ok_stat:'Web OK',web_bad_stat:'Web błąd',
     health:'Kondycja',health_avg:'Kondycja',health_issues_stat:'Problemy',issues_filter:'Problemy',
     iss_offline:'Offline',iss_web_auth:'Web: wymaga logowania',iss_web_timeout:'Web: timeout',iss_web_error:'Web: błąd',
     iss_fw_update:'Dostępna aktualizacja FW',iss_fw_check_error:'Błąd sprawdzania FW',iss_wifi_weak:'Słaby sygnał WiFi',iss_wifi_poor:'Bardzo słaby sygnał WiFi',
     iss_no_connectivity:'Brak łączności',iss_api_error:'Błąd API',iss_recent_reboot:'Niedawny restart',iss_web_slow:'Wolny Web UI',
     b_offline:'Offline',b_update:'⬆ Aktualizacja',b_latest:'Aktualne',b_online:'Online',
     msg_discovering:'Skanowanie sieci...',msg_refreshing:'Odświeżanie...',msg_checking_fw:'Sprawdzanie firmware...',
     msg_check_one:'Sprawdzam FW...',msg_check_web:'Sprawdzam Web UI...',msg_on:'Włączanie...',msg_off:'Wyłączanie...',msg_add:'Dodano',msg_need_ip:'Podaj IP'},
  en:{theme:'Theme',discover:'Discover',refresh:'Refresh',firmware:'Firmware',devices:'Devices',online:'Online',offline:'Offline',
     total_power:'Power (W)',updates:'Updates',up_to_date:'Up to date',all:'All',add:'Add',
     search_ph:'🔎 Search by name / IP / model...',ip_ph:'e.g. 192.168.1.50',loading:'Loading...',
     last_refresh:'Last refresh',refreshing_status:'⏳ refreshing...',
     model:'Model',hostname:'Hostname',fw:'Firmware',wifi:'WiFi',eth:'Ethernet',uptime:'Uptime',power:'Power',channel:'Channel',
     check_fw:'⬆ Check FW',web:'🔗 Panel',check_web:'🌐 Test Web',no_devices:'No devices matching filter',
     eth_na:'N/A',eth_none:'none',eth_disc:'disconnected',eth_conn:'connected',
     web_label:'Web UI',web_ok:'OK',web_timeout:'timeout',web_error:'error',web_auth:'auth required',web_never:'not checked',
     web_ok_stat:'Web OK',web_bad_stat:'Web error',
     health:'Health',health_avg:'Health',health_issues_stat:'Issues',issues_filter:'Issues',
     iss_offline:'Offline',iss_web_auth:'Web: auth required',iss_web_timeout:'Web: timeout',iss_web_error:'Web: error',
     iss_fw_update:'Firmware update available',iss_fw_check_error:'Firmware check failed',iss_wifi_weak:'Weak WiFi signal',iss_wifi_poor:'Very poor WiFi signal',
     iss_no_connectivity:'No connectivity',iss_api_error:'API error',iss_recent_reboot:'Recently rebooted',iss_web_slow:'Slow Web UI',
     b_offline:'Offline',b_update:'⬆ Update',b_latest:'Up to date',b_online:'Online',
     msg_discovering:'Scanning network...',msg_refreshing:'Refreshing...',msg_checking_fw:'Checking firmware...',
     msg_check_one:'Checking FW...',msg_check_web:'Checking Web UI...',msg_on:'Turning on...',msg_off:'Turning off...',msg_add:'Added',msg_need_ip:'Enter IP'}
};
let LANG='pl';
function detectLang(){const s=localStorage.getItem('lang')||'auto';if(s==='pl'||s==='en')return s;const n=(navigator.language||'pl').toLowerCase();return n.startsWith('pl')?'pl':'en'}
function t(k){return (I18N[LANG]&&I18N[LANG][k])||I18N.pl[k]||k}
function applyI18n(){document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=t(el.dataset.i18n)});document.querySelectorAll('[data-i18n-ph]').forEach(el=>{el.placeholder=t(el.dataset.i18nPh)});document.documentElement.lang=LANG}
function setLang(v){localStorage.setItem('lang',v);LANG=v==='auto'?detectLang():v;applyI18n();render()}
(function(){const s=localStorage.getItem('lang')||'auto';LANG=s==='auto'?detectLang():s})();
let DEVS=[], FILTER='all', VIEW=(localStorage.getItem('view')||'large');
const BASE=(location.pathname.endsWith('/')?location.pathname:location.pathname+'/').replace(/\/+$/,'/');
const api=p=>BASE+p.replace(/^\/+/,'');
const $=id=>document.getElementById(id);
const j=(u,o)=>fetch(u,o).then(r=>r.json()).catch(()=>({}));
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');clearTimeout(toast._t);toast._t=setTimeout(()=>t.classList.remove('show'),2200)}
function toggleTheme(){const h=document.documentElement;const cur=h.getAttribute('data-theme')==='light'?'dark':'light';h.setAttribute('data-theme',cur);localStorage.setItem('theme',cur)}
(function(){const t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)})();
function setFilter(f){FILTER=f;document.querySelectorAll('.chip').forEach(c=>c.classList.toggle('active',c.dataset.f===f));render()}
function setView(v){VIEW=v;localStorage.setItem('view',v);applyView();render()}
function applyView(){const g=$('grid');if(!g)return;g.classList.remove('view-large','view-small','view-list');g.classList.add('view-'+VIEW);['large','small','list'].forEach(k=>{const b=$('vw-'+k);if(b)b.classList.toggle('active',k===VIEW)})}
async function load(){
  const sum=await j(api('api/summary'));
  $('total').textContent=sum.total??'-'; $('online').textContent=sum.online??'-';
  $('offline').textContent=sum.offline??'-'; $('power').textContent=(sum.power??0).toFixed(1);
  $('updates').textContent=sum.updates??'-'; $('latest').textContent=sum.latest??'-';
  $('web_ok').textContent=sum.web_ok??'-'; $('web_bad').textContent=sum.web_bad??'-';
  $('health_avg').textContent=sum.health_avg!=null?sum.health_avg+'%':'-';
  $('health_issues').textContent=sum.health_issues??'-';
  const d=await j(api('api/devices')); DEVS=d.devices||[];
  $('foot').textContent=`${t('last_refresh')}: ${d.last_refresh||'-'} · ${t('fw')}: ${d.last_firmware_check||'-'}${d.refreshing?' · '+t('refreshing_status'):''}`;
  render();
}
function statusBadge(d){
  if(!d.online) return `<span class="badge b-bad">${t('b_offline')}</span>`;
  if(d.has_update===true) return `<span class="badge b-warn">${t('b_update')}</span>`;
  if(d.firmware_status==='latest') return `<span class="badge b-ok">${t('b_latest')}</span>`;
  return `<span class="badge b-info">${t('b_online')}</span>`;
}
function rssiIcon(r){if(!r) return '📶';if(r>-60)return '📶 ●●●';if(r>-75)return '📶 ●●○';return '📶 ●○○'}
function ethStatus(d){if(d.generation&&d.generation<2) return `<span class="badge b-info">${t('eth_na')}</span>`;if(d.eth_supported===false) return `<span class="badge b-info">${t('eth_none')}</span>`;if(d.eth_connected) return `<span class="badge b-ok">🔌 ${d.eth_ip||t('eth_conn')}</span>`;if(d.eth_supported) return `<span class="badge b-bad">${t('eth_disc')}</span>`;return '<span class="badge b-info">-</span>'}
function webStatus(d){
  if(!d.web_status) return `<span class="badge b-info">${t('web_never')}</span>`;
  const lat=d.web_latency_ms!=null?` · ${d.web_latency_ms} ms`:'';
  const code=d.web_code?` (${d.web_code})`:'';
  if(d.web_status==='ok'&&d.web_auth_required) return `<span class="badge b-warn">🔐 ${t('web_auth')}${lat}</span>`;
  if(d.web_status==='ok') return `<span class="badge b-ok">✅ ${t('web_ok')}${code}${lat}</span>`;
  if(d.web_status==='timeout') return `<span class="badge b-bad">⏱ ${t('web_timeout')}${lat}</span>`;
  return `<span class="badge b-bad">❌ ${t('web_error')}${code}</span>`;
}
function uptime(s){if(!s) return '-';s=+s;const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);return (d?d+'d ':'')+(h?h+'h ':'')+m+'m'}
function row(k,v){return `<div class="row"><span class="k">${k}</span><span class="vv">${v??'-'}</span></div>`}
function matches(d,q){if(!q) return true;q=q.toLowerCase();return (d.ip||'').toLowerCase().includes(q)||(d.device_name||'').toLowerCase().includes(q)||(d.model||'').toLowerCase().includes(q)||(d.hostname||'').toLowerCase().includes(q)}
function passFilter(d){if(FILTER==='online')return d.online;if(FILTER==='offline')return !d.online;if(FILTER==='update')return d.has_update===true;if(FILTER==='issues')return d.health_level&&d.health_level!=='good';return true}
function healthBar(d){
  if(d.health_score==null) return '';
  const lvl=d.health_level||'good';
  const iss=(d.health_issues||[]).map(k=>{const bad=['offline','web_timeout','web_error','no_connectivity','api_error','wifi_poor'].includes(k);return `<span class="pill ${bad?'bad':''}">${t('iss_'+k)||k}</span>`}).join('');
  return `<div class="health ${lvl}" title="${t('health')}: ${d.health_score}%">
    <div class="hbar"><div class="hfill" style="width:${d.health_score}%"></div></div>
    <div class="hval">${d.health_score}%</div>
  </div>${iss?`<div class="issues">${iss}</div>`:''}`;
}
function render(){
  const q=$('q').value.trim();
  const list=DEVS.filter(d=>passFilter(d)&&matches(d,q)).sort((a,b)=>(a.device_name||a.hostname||a.ip).localeCompare(b.device_name||b.hostname||b.ip));
  const g=$('grid');
  if(!list.length){g.innerHTML=`<div class="empty" style="grid-column:1/-1"><div class="big">📬</div><div>${t('no_devices')}</div></div>`;applyView();return}
  if(VIEW==='list'){
    g.innerHTML=list.map(d=>{
      const fw=(d.firmware_current||d.firmware||'?')+(d.firmware_latest&&d.firmware_latest!=d.firmware_current?` <span class="badge b-warn">→ ${d.firmware_latest}</span>`:'');
      return `<div class="card">
        <div class="head">
          <div><h3>${d.device_name||d.hostname||d.model||'Shelly'}</h3><div class="ip">${d.ip} · ${d.hostname||d.model||'-'} · Gen ${d.generation||1}</div></div>
          ${statusBadge(d)}
        </div>
        <div class="l-cell"><span class="lbl">${t('health')}</span><span class="val" style="color:var(--${d.health_level==='good'?'ok':d.health_level==='warn'?'warn':'bad'})">${d.health_score!=null?d.health_score+'%':'-'}</span></div>
        <div class="l-cell"><span class="lbl">${t('fw')}</span><span class="val">${fw}</span></div>
        <div class="l-cell"><span class="lbl">${t('wifi')}</span><span class="val">${d.wifi_rssi?d.wifi_rssi+' dBm':'-'}</span></div>
        <div class="l-cell"><span class="lbl">${t('eth')}</span><span class="val">${ethStatus(d)}</span></div>
        <div class="l-cell"><span class="lbl">${t('web_label')}</span><span class="val">${webStatus(d)}</span></div>
        <div class="l-cell"><span class="lbl">${t('power')}</span><span class="val">${d.total_power_w!=null?d.total_power_w+' W':'-'}</span></div>
        <div class="l-cell"><span class="lbl">${t('uptime')}</span><span class="val">${uptime(d.uptime)}</span></div>
        <div class="actions">
          <button class="btn sm ghost" onclick="call('api/device/${d.ip}/firmware/check','msg_check_one')">⬆</button>
          <button class="btn sm ghost" onclick="call('api/device/${d.ip}/web/check','msg_check_web')">🌐</button>
          <a class="btn sm ghost" href="http://${d.ip}" target="_blank" rel="noopener">🔗</a>
        </div>
      </div>`;
    }).join('');
    applyView();return;
  }
  g.innerHTML=list.map(d=>{
    const fw=(d.firmware_current||d.firmware||'?')+(d.firmware_latest&&d.firmware_latest!=d.firmware_current?` <span class="badge b-warn">→ ${d.firmware_latest}</span>`:'');
    const sw=(d.switches||[]).map(x=>`<div class="sw-row"><span>${x.name?x.name+' <span style="color:var(--mut)">('+t('channel')+' '+x.id+')</span>':t('channel')+' '+x.id}${x.power_w!=null?` · <span style="color:var(--mut)">${x.power_w} W</span>`:''}</span>
      <span class="toggle ${x.is_on?'on':''}" onclick="tog('${d.ip}','${x.id}',${x.is_on})"></span></div>`).join('');
    return `<div class="card">
      <div class="head">
        <div><h3>${d.device_name||d.hostname||d.model||'Shelly'}</h3><div class="ip">${d.ip} · ${d.hostname||d.model||'-'} · Gen ${d.generation||1}</div></div>
        ${statusBadge(d)}
      </div>
      ${healthBar(d)}
      ${row(t('model'),d.model||'-')}
      ${row(t('hostname'),d.hostname?`<span style="font-family:ui-monospace,Consolas,monospace">${d.hostname}</span>`:'-')}
      ${row(t('fw'),fw)}
      ${row(t('wifi'),d.wifi_rssi?`${rssiIcon(d.wifi_rssi)} ${d.wifi_rssi} dBm`:'-')}
      ${row(t('eth'), ethStatus(d))}
      ${row(t('web_label'), webStatus(d))}
      ${row(t('uptime'),uptime(d.uptime))}
      ${row(t('power'),d.total_power_w!=null?d.total_power_w+' W':'-')}
      ${sw?`<div class="switches">${sw}</div>`:''}
      <div class="actions">
        <button class="btn sm ghost" onclick="call('api/device/${d.ip}/firmware/check','msg_check_one')">${t('check_fw')}</button>
        <button class="btn sm ghost" onclick="call('api/device/${d.ip}/web/check','msg_check_web')">${t('check_web')}</button>
        <a class="btn sm ghost" href="http://${d.ip}" target="_blank" rel="noopener">${t('web')}</a>
      </div>
    </div>`;
  }).join('');
  applyView();
}
async function call(u,msgKey){if(msgKey)toast(t(msgKey)||msgKey);await j(api(u),{method:'POST'});setTimeout(load,1500)}
async function tog(ip,id,on){await call(`api/device/${ip}/relay/${id}/${on?'off':'on'}`, on?'msg_off':'msg_on')}
async function add(){const ip=$('ip').value.trim();if(!ip){toast(t('msg_need_ip'));return}
  await j(api('api/devices/add'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  $('ip').value='';toast(`${t('msg_add')} ${ip}`);setTimeout(load,1200)}
$('ip').addEventListener('keydown',e=>{if(e.key==='Enter')add()});
$('langSel').value=localStorage.getItem('lang')||'auto';
applyI18n();
applyView();
load();setInterval(load,{{refresh}}*1000);
</script>
</body>
</html>"""
def main():
    p=argparse.ArgumentParser(); p.add_argument('--host',default='0.0.0.0'); p.add_argument('--port',type=int,default=5000); p.add_argument('--devices',default=''); p.add_argument('--network'); p.add_argument('--no-mdns',action='store_true'); p.add_argument('--timeout',type=float,default=3); p.add_argument('--mdns-timeout',type=float,default=5); p.add_argument('--refresh',type=int,default=15); p.add_argument('--user'); p.add_argument('--password')
    a=p.parse_args(); s.cfg.update({'timeout':a.timeout,'refresh':a.refresh,'mdns_timeout':a.mdns_timeout,'user':a.user,'password':a.password,'devices':[x.strip() for x in a.devices.split(',') if x.strip()],'network':a.network,'use_mdns':not a.no_mdns})
    print('Shelly Dashboard Add-on listening on',a.host,a.port)
    threading.Thread(target=discover,daemon=True).start(); threading.Thread(target=loop,daemon=True).start(); app.run(host=a.host,port=a.port,threaded=True,debug=False)
if __name__=='__main__': main()
