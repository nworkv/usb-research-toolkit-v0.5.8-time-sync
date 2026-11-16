#!/usr/bin/env python3
"""Seeded USB filter fuzzing: mutate device identity/class and interface layouts.

Designed for an isolated, owned USB test bench. Every generated input is saved
verbatim with a manifest; gadget-side observations are not presented as proof
of Windows driver binding/filter acceptance.
"""
from __future__ import annotations
import argparse, copy, hashlib, html, json, os, random, signal, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TEMPLATES=ROOT/'profiles'/'templates'
# Controlled descriptor values: standard classes and a lab-only vendor class.
DEVICE_CLASSES=[0x00,0x02,0x03,0x08,0xEF,0xFF]
INTERFACE_CLASSES=[(0x02,0x02,0x01),(0x0A,0,0),(0x03,0,0),(0x08,0x06,0x50),(0xFF,0,0)]
VID_POOL=[0x1209,0x1D6B,0xCafe,0xF00D]
PID_POOL=[0x0001,0x1001,0x2001,0xBEEF]

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def describe(doc):
 d=doc['device']; out=[]
 for ci,c in enumerate(doc.get('configurations',[])):
  for it in c.get('interfaces',[]):
   out.append({'configuration':c.get('bConfigurationValue',ci+1),'interface':it.get('bInterfaceNumber'), 'alternate':it.get('bAlternateSetting',0),'class':it.get('bInterfaceClass',0),'subclass':it.get('bInterfaceSubClass',0),'protocol':it.get('bInterfaceProtocol',0),'endpoints':len(it.get('endpoints',[]))})
 return {'vid':d.get('idVendor'),'pid':d.get('idProduct'),'device_class':d.get('bDeviceClass'),'device_subclass':d.get('bDeviceSubClass'),'device_protocol':d.get('bDeviceProtocol'),'interfaces':out}
def change(doc,rng,ops):
 d=doc['device']; op=rng.choice(['vidpid','device_class','interface_class','interface_protocol','interface_layout'])
 if op=='vidpid':
  old=(d['idVendor'],d['idProduct']); d['idVendor']=rng.choice(VID_POOL); d['idProduct']=rng.choice(PID_POOL); ops.append(f'VID/PID: {old[0]:04X}:{old[1]:04X} -> {d["idVendor"]:04X}:{d["idProduct"]:04X}')
 elif op=='device_class':
  old=(d['bDeviceClass'],d['bDeviceSubClass'],d['bDeviceProtocol']); d['bDeviceClass']=rng.choice(DEVICE_CLASSES); d['bDeviceSubClass']=rng.choice([0,0,2,6]); d['bDeviceProtocol']=rng.choice([0,0,1,2]); ops.append(f'bDeviceClass tuple: {old} -> {(d["bDeviceClass"],d["bDeviceSubClass"],d["bDeviceProtocol"])}')
 elif op in ('interface_class','interface_protocol'):
  choices=[(c,i) for c,cfg in enumerate(doc['configurations']) for i in cfg['interfaces']]
  if choices:
   _,it=rng.choice(choices); old=(it['bInterfaceClass'],it['bInterfaceSubClass'],it['bInterfaceProtocol'])
   if op=='interface_class': it['bInterfaceClass'],it['bInterfaceSubClass'],it['bInterfaceProtocol']=rng.choice(INTERFACE_CLASSES)
   else: it['bInterfaceProtocol']=rng.choice([0,1,2,0x50,0xFF])
   ops.append(f'interface {it["bInterfaceNumber"]} class tuple: {old} -> {(it["bInterfaceClass"],it["bInterfaceSubClass"],it["bInterfaceProtocol"])}')
 elif op=='interface_layout':
  # Switch to a different corpus member: this changes interface count/composition
  # while retaining a known-good descriptor set rather than inventing endpoints.
  ops.append('interface layout selected from seed corpus (interface count/composition may change)')
 return doc,op

def trace_summary(path):
 ev=[]
 if path.exists():
  for line in path.read_text(errors='replace').splitlines():
   try: ev.append(json.loads(line))
   except: pass
 names=[x.get('event','') for x in ev]
 return {'event_count':len(ev),'control_requests':names.count('CONTROL_REQUEST'),'set_configuration':sum(x.get('event')=='SET_CONFIGURATION' for x in ev),'stalls':sum('STALL' in x for x in names),'errors':sum('ERROR' in x for x in names),'events':names}

def main():
 ap=argparse.ArgumentParser(description='Seed-corpus USB filter fuzzing with exact input/output reports')
 ap.add_argument('--count',type=int,default=30); ap.add_argument('--seed',type=int,default=20261116); ap.add_argument('--mutations',type=int,default=1)
 ap.add_argument('--out-dir',default='runs/filter-fuzz'); ap.add_argument('--dwell-seconds',type=float,default=8); ap.add_argument('--settle-seconds',type=float,default=2)
 ap.add_argument('--udc-driver'); ap.add_argument('--udc-device'); ap.add_argument('--speed',choices=['low','full','high'],default='high'); ap.add_argument('--run',action='store_true'); ap.add_argument('--confirm-lab',action='store_true')
 a=ap.parse_args()
 if not 1<=a.count<=1000 or not 1<=a.mutations<=10: ap.error('count 1..1000, mutations 1..10')
 if a.run and (not a.confirm_lab or not a.udc_driver or not a.udc_device): ap.error('--run requires --confirm-lab, --udc-driver and --udc-device')
 if a.run and (os.name!='posix' or os.geteuid()!=0): ap.error('real execution requires Linux root on the Raspberry Pi')
 out=Path(a.out_dir).resolve()
 if out.exists() and any(out.iterdir()): ap.error(f'output directory is not empty: {out}')
 casesdir=out/'inputs'; traces=out/'traces'; casesdir.mkdir(parents=True,exist_ok=True); traces.mkdir(parents=True,exist_ok=True)
 corpus=sorted(TEMPLATES.glob('*.json'))
 if not corpus: ap.error('no seed profiles in profiles/templates')
 docs=[json.loads(p.read_text()) for p in corpus]; rng=random.Random(a.seed); rows=[]
 for n in range(1,a.count+1):
  base_idx=rng.randrange(len(docs)); doc=copy.deepcopy(docs[base_idx]); ops=[]
  for _ in range(a.mutations):
   if rng.random()<0.25:
    alt=rng.randrange(len(docs)); doc=copy.deepcopy(docs[alt]); ops.append(f'base profile switched: {corpus[alt].name}')
   doc,kind=change(doc,rng,ops)
  doc['profile_name']=f'filter-fuzz-{n:05d}'; doc.setdefault('validation',{})['mode']='research'; doc['validation']['calculated_fields']='manual'
  p=casesdir/f'case-{n:05d}.json'; p.write_text(json.dumps(doc,indent=2,ensure_ascii=False)+'\n')
  row={'case':n,'seed_profile':corpus[base_idx].name,'input_file':str(p.relative_to(out)),'sha256':digest(p),'changes':ops,'input':describe(doc),'execution':'GENERATED_ONLY'}
  if a.run:
   tr=traces/f'case-{n:05d}.device.jsonl'; log=traces/f'case-{n:05d}.log'; cmd=[str(ROOT/'build/usb-connect'),'run',str(p),'--backend','raw-gadget','--udc-driver',a.udc_driver,'--udc-device',a.udc_device,'--speed',a.speed,'--trace',str(tr),'--run-id',f'filter-fuzz-{n:05d}','--allow-research']
   start=time.monotonic()
   with log.open('w') as f:
    proc=subprocess.Popen(cmd,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+a.dwell_seconds
    while time.monotonic()<deadline and proc.poll() is None: time.sleep(.2)
    if proc.poll() is None:
     proc.send_signal(signal.SIGINT)
     try: proc.wait(timeout=5)
     except subprocess.TimeoutExpired: proc.terminate(); proc.wait(timeout=3)
   obs=trace_summary(tr); row.update(execution='COMPLETED' if proc.returncode==0 else 'DEVICE_OR_BACKEND_FAILURE',returncode=proc.returncode,duration_seconds=round(time.monotonic()-start,2),observed=obs,trace=str(tr.relative_to(out)),log=str(log.relative_to(out)))
   if proc.returncode!=0: row['verdict']='DEVICE_OR_BACKEND_FAILURE'
   elif not obs['control_requests']: row['verdict']='NO_HOST_CONTACT_OBSERVED'
   elif not obs['set_configuration']: row['verdict']='HOST_CONTACT_NO_CONFIGURATION'
   elif obs['stalls'] or obs['errors']: row['verdict']='CONFIGURED_WITH_ERRORS'
   else: row['verdict']='CONFIGURED_OBSERVED_REVIEW_HOST_CAPTURE'
   if a.settle_seconds: time.sleep(a.settle_seconds)
  else: row['verdict']='NOT_EXECUTED'
  rows.append(row); print(f'[{n}/{a.count}] {row["verdict"]} {p.name}',flush=True)
 binary=ROOT/'build'/'usb-connect'
 binary_hash=digest(binary) if binary.is_file() else None
 report={'created_utc':datetime.now(timezone.utc).isoformat(),'toolkit_version':'0.5.7','usb_connect_sha256':binary_hash,'seed':a.seed,'mutations_per_case':a.mutations,'executed':a.run,'execution_settings':{'speed':a.speed,'dwell_seconds':a.dwell_seconds,'settle_seconds':a.settle_seconds,'udc_driver':a.udc_driver,'udc_device':a.udc_device},'input_root':'inputs','results':rows,'interpretation':'Device-side SET_CONFIGURATION is not proof that Windows accepted every interface, bound drivers, or passed a filter. Correlate each case with Windows USBPcap and Device Manager; import capture separately in the report workflow.'}
 (out/'campaign.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
 lines=['<!doctype html><meta charset="utf-8"><title>USB Filter Fuzz Report</title><style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:7px;text-align:left;vertical-align:top}pre{white-space:pre-wrap;max-width:55rem}.ok{background:#e7f4e8}.warn{background:#fff2d6}</style>',f'<h1>USB Filter Fuzz Report</h1><p>Seed: {a.seed}; cases: {len(rows)}; executed: {a.run}</p><p><b>Важно:</b> SET_CONFIGURATION не доказывает привязку драйвера Windows или прохождение фильтра.</p><table><tr><th>Case</th><th>Вход: VID:PID / bDeviceClass</th><th>Вход: интерфейсы</th><th>Изменения</th><th>Выход / вердикт</th><th>SHA-256</th></tr>']
 for r in rows:
  x=r['input']; ifs='<br>'.join(f"#{i['interface']} class={i['class']:02X}/{i['subclass']:02X}/{i['protocol']:02X}" for i in x['interfaces']) or '—'; observed=r.get('observed',{}); outtxt=f"{r['verdict']}<br>requests={observed.get('control_requests','—')}, SET_CONFIGURATION={observed.get('set_configuration','—')}, STALL={observed.get('stalls','—')}, errors={observed.get('errors','—')}"
  lines.append(f"<tr><td>{r['case']}</td><td>{x['vid']:04X}:{x['pid']:04X}<br>bDeviceClass={x['device_class']:02X}/{x['device_subclass']:02X}/{x['device_protocol']:02X}</td><td>{ifs}</td><td><pre>{html.escape('; '.join(r['changes']))}</pre></td><td>{outtxt}</td><td><code>{r['sha256']}</code></td></tr>")
 lines.append('</table>'); (out/'report.html').write_text('\n'.join(lines),encoding='utf-8')
 (out/'report.txt').write_text('\n'.join(f"CASE {r['case']:05d} {r['verdict']} | VID:PID={r['input']['vid']:04X}:{r['input']['pid']:04X} | bDeviceClass={r['input']['device_class']:02X} | interfaces={len(r['input']['interfaces'])} | input={r['input_file']} | sha256={r['sha256']} | changes={'; '.join(r['changes'])}" for r in rows)+'\n',encoding='utf-8')
 print(f'Reports: {out}/report.html, report.txt, campaign.json')
 return 0
if __name__=='__main__': raise SystemExit(main())
