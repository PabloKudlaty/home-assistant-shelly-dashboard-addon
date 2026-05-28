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
def query(ip):
    g=gen(ip); d={'ip':ip,'generation':g or 1,'online':False}
    try:
        if g>=2:
            info=requests.get(f'http://{ip}/rpc/Shelly.GetDeviceInfo',timeout=s.cfg['timeout'],auth=auth2()).json()
            d.update({'online':True,'model':info.get('model') or info.get('app'),'firmware':info.get('ver') or info.get('fw_id'),'firmware_current':info.get('ver') or info.get('fw_id'),'generation':info.get('gen',2)})
            try:
                st=requests.get(f'http://{ip}/rpc/Shelly.GetStatus',timeout=s.cfg['timeout'],auth=auth2()).json(); w=st.get('wifi',{}); sys=st.get('sys',{})
                d.update({'wifi_rssi':w.get('rssi'),'uptime':sys.get('uptime'),'switches':[],'total_power_w':0})
                for k,v in st.items():
                    if k.startswith('switch:'):
                        p=v.get('apower',0) or 0; d['switches'].append({'id':k.split(':')[1],'is_on':v.get('output',False),'power_w':p}); d['total_power_w']+=p
                d['total_power_w']=round(d['total_power_w'],2)
            except Exception: pass
            try:
                cfg=requests.get(f'http://{ip}/rpc/Shelly.GetConfig',timeout=s.cfg['timeout'],auth=auth2()).json(); d['device_name']=((cfg.get('sys')or{}).get('device')or{}).get('name') or d['model']
            except Exception: d['device_name']=d.get('model')
        else:
            info=requests.get(f'http://{ip}/shelly',timeout=s.cfg['timeout'],auth=auth1()).json()
            d.update({'online':True,'model':info.get('type'),'firmware':info.get('fw'),'firmware_current':info.get('fw')})
            try:
                st=requests.get(f'http://{ip}/status',timeout=s.cfg['timeout'],auth=auth1()).json(); w=st.get('wifi_sta',{})
                d.update({'wifi_rssi':w.get('rssi'),'switches':[{'id':i,'is_on':x.get('ison',False)} for i,x in enumerate(st.get('relays',[]))]})
                m=st.get('meters',[]); d['total_power_w']=round(sum(x.get('power',0) or 0 for x in m),2)
            except Exception: pass
            try: d['device_name']=requests.get(f'http://{ip}/settings',timeout=s.cfg['timeout'],auth=auth1()).json().get('name') or d.get('model')
            except Exception: d['device_name']=d.get('model')
        d.update(check_fw(ip,d)); return d
    except Exception as e:
        d['error']=str(e); return d
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
            with s.lock: s.devices.setdefault(futs[f],{'ip':futs[f]}).update(f.result())
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
    return jsonify({'total':len(ds),'online':sum(1 for d in ds if d.get('online')),'offline':sum(1 for d in ds if not d.get('online')),'power':round(sum(d.get('total_power_w',0) or 0 for d in ds),2),'updates':sum(1 for d in ds if d.get('has_update') is True),'latest':sum(1 for d in ds if d.get('firmware_status')=='latest')})
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
    with s.lock: s.devices.setdefault(ip,{'ip':ip}).update(fw)
    return jsonify(fw)
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
HTML="""<!doctype html><html lang='pl'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Shelly Dashboard</title><style>body{margin:0;background:#0b1020;color:#e8eefc;font-family:Segoe UI,Arial}.top{padding:18px;background:#111a31;display:flex;justify-content:space-between;flex-wrap:wrap}.btn{border:0;border-radius:9px;padding:9px 12px;background:#3b82f6;color:white;font-weight:700;margin:2px}.yel{background:#f59e0b}.green{background:#22c55e}.wrap{padding:18px}.stats,.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.grid{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}.stat,.card{background:#151b2e;border:1px solid #26314f;border-radius:14px;padding:14px}.v{font-size:1.8rem;font-weight:800}.mut{color:#93a4c7}.badge{border-radius:999px;padding:3px 8px;font-size:.75rem;font-weight:800}.ok{background:#143d28;color:#22c55e}.bad{background:#421b24;color:#ef4444}.warn{background:#493415;color:#f59e0b}.row{display:flex;justify-content:space-between;border-bottom:1px solid #26314f;padding:6px 0}.bar{display:flex;gap:8px;margin:14px 0;flex-wrap:wrap}.inp{padding:10px;border-radius:9px;background:#0f172a;color:#e8eefc;border:1px solid #26314f}.search{flex:1}.toggle{width:44px;height:23px;border-radius:20px;background:#334155;display:inline-block;position:relative;cursor:pointer}.toggle:before{content:'';position:absolute;width:17px;height:17px;border-radius:50%;background:white;top:3px;left:3px}.toggle.on{background:#22c55e}.toggle.on:before{left:24px}</style></head><body><div class='top'><h2>🏠 Shelly Dashboard + Firmware</h2><div><button class='btn' onclick="call('/api/discover')">🔍 Odkryj</button><button class='btn' onclick="call('/api/refresh')">🔄 Odśwież</button><button class='btn yel' onclick="call('/api/firmware/check')">⬆ Firmware</button></div></div><div class='wrap'><div class='stats'><div class='stat'><div id='total' class='v'>-</div><div class='mut'>Urządzenia</div></div><div class='stat'><div id='online' class='v'>-</div><div class='mut'>Online</div></div><div class='stat'><div id='power' class='v'>-</div><div class='mut'>Moc W</div></div><div class='stat'><div id='updates' class='v'>-</div><div class='mut'>Update FW</div></div></div><div class='bar'><input id='q' class='inp search' placeholder='Szukaj...' oninput='render()'><input id='ip' class='inp' placeholder='192.168.1.100'><button class='btn green' onclick='add()'>Dodaj IP</button><span id='st' class='mut'></span></div><div id='grid' class='grid'></div></div><script>let dev=[];async function j(u,o){return (await fetch(u,o)).json()}async function load(){let d=await j('/api/devices');dev=d.devices||[];st.textContent='Odśw: '+(d.last_refresh||'-')+' FW: '+(d.last_firmware_check||'-');let s=await j('/api/summary');total.textContent=s.total;online.textContent=s.online;power.textContent=s.power;updates.textContent=s.updates;render()}function fw(d){return d.firmware_status==='update_available'?'<span class="badge warn">UPDATE</span>':d.firmware_status==='latest'?'<span class="badge ok">LATEST</span>':'<span class="badge">FW?</span>'}function row(a,b){return `<div class='row'><span class='mut'>${a}</span><b>${b??'-'}</b></div>`}function render(){let q=document.getElementById('q').value.toLowerCase();let h='';dev.filter(d=>(`${d.device_name||''} ${d.model||''} ${d.ip}`).toLowerCase().includes(q)).forEach(d=>{h+=`<div class='card'><h3>${d.device_name||d.model||d.ip}</h3>${fw(d)} <span class='badge ${d.online?'ok':'bad'}'>${d.online?'ONLINE':'OFFLINE'}</span>${row('IP',d.ip)}${row('Model',d.model)}${row('FW',(d.firmware_current||d.firmware||'?')+(d.firmware_latest?' → '+d.firmware_latest:''))}${row('WiFi',d.wifi_rssi?d.wifi_rssi+' dBm':'N/A')}${row('Moc',d.total_power_w?d.total_power_w+' W':'-')}`;(d.switches||[]).forEach(sw=>h+=`<div class='row'><span>Kanał ${sw.id}</span><span onclick="tog('${d.ip}','${sw.id}',${sw.is_on})" class='toggle ${sw.is_on?'on':''}'></span></div>`);h+=`<p><button class='btn' onclick="call('/api/device/${d.ip}/firmware/check')">Sprawdź FW</button></p></div>`});grid.innerHTML=h||'<p>Brak urządzeń</p>'}async function call(u){await j(u,{method:'POST'});setTimeout(load,1500)}async function tog(ip,id,on){await call(`/api/device/${ip}/relay/${id}/${on?'off':'on'}`)}async function add(){let ip=document.getElementById('ip').value.trim(); if(!ip)return; await j('/api/devices/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); document.getElementById('ip').value=''; setTimeout(load,1500)}load();setInterval(load,{{refresh}}*1000)</script></body></html>"""
def main():
    p=argparse.ArgumentParser(); p.add_argument('--host',default='0.0.0.0'); p.add_argument('--port',type=int,default=5000); p.add_argument('--devices',default=''); p.add_argument('--network'); p.add_argument('--no-mdns',action='store_true'); p.add_argument('--timeout',type=float,default=3); p.add_argument('--mdns-timeout',type=float,default=5); p.add_argument('--refresh',type=int,default=15); p.add_argument('--user'); p.add_argument('--password')
    a=p.parse_args(); s.cfg.update({'timeout':a.timeout,'refresh':a.refresh,'mdns_timeout':a.mdns_timeout,'user':a.user,'password':a.password,'devices':[x.strip() for x in a.devices.split(',') if x.strip()],'network':a.network,'use_mdns':not a.no_mdns})
    print('Shelly Dashboard Add-on listening on',a.host,a.port)
    threading.Thread(target=discover,daemon=True).start(); threading.Thread(target=loop,daemon=True).start(); app.run(host=a.host,port=a.port,threaded=True,debug=False)
if __name__=='__main__': main()
