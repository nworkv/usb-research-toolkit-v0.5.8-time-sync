#!/usr/bin/env python3
"""Corpus-based USB descriptor fuzz-case generator with auditable input/output reports.

Generation is offline by default. Hardware execution is opt-in and limited to
scalar descriptor mutations; structural interface mutations are generated but
not executed because runtime endpoint/class workers must be updated consistently.
"""
from __future__ import annotations
import argparse, copy, html, json, random, signal, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CORPUS=ROOT/'profiles'/'templates'
CLASS_TRIPLES={
 'hid':(0x03,0x00,0x00), 'hid-boot-keyboard':(0x03,0x01,0x01),
 'hid-boot-mouse':(0x03,0x01,0x02), 'cdc-control':(0x02,0x02,0x01),
 'cdc-data':(0x0a,0x00,0x00), 'msc-bot':(0x08,0x06,0x50), 'ccid':(0x0b,0x00,0x00),
 'vendor':(0xff,0x00,0x00), 'audio':(0x01,0x01,0x00),
 'printer':(0x07,0x01,0x02), 'hub':(0x09,0x00,0x00)
}

def all_ifaces(doc):
 return [(ci,ii,x) for ci,c in enumerate(doc.get('configurations',[])) for ii,x in enumerate(c.get('interfaces',[]))]
def summary(doc):
 d=doc['device']; return {'vid':d.get('idVendor'),'pid':d.get('idProduct'),'device_class':d.get('bDeviceClass'),'device_subclass':d.get('bDeviceSubClass'),'device_protocol':d.get('bDeviceProtocol'),'configurations':[{'value':c.get('bConfigurationValue'),'interfaces':[{'number':i.get('bInterfaceNumber'),'alt':i.get('bAlternateSetting',0),'class':i.get('bInterfaceClass'),'subclass':i.get('bInterfaceSubClass'),'protocol':i.get('bInterfaceProtocol')} for i in c.get('interfaces',[])]} for c in doc.get('configurations',[])]}
def interfaces_flat(doc):
 return [{'configuration':c.get('bConfigurationValue'),'number':i.get('bInterfaceNumber'),'class':i.get('bInterfaceClass'),'subclass':i.get('bInterfaceSubClass'),'protocol':i.get('bInterfaceProtocol')} for c in doc.get('configurations',[]) for i in c.get('interfaces',[])]
def mutate(doc, rng, op):
 d=doc['device']; changes=[]
 if op=='device-class':
  before=[d.get(k,0) for k in ('bDeviceClass','bDeviceSubClass','bDeviceProtocol')]
  triple=rng.choice([(0,0,0),(0xef,2,1),(0xff,0,0),(3,1,1),(8,6,0x50)])
  for k,v in zip(('bDeviceClass','bDeviceSubClass','bDeviceProtocol'),triple): d[k]=v
  changes.append({'field':'device.bDeviceClass/SubClass/Protocol','before':before,'after':list(triple)})
 elif op=='vid-pid':
  for k in ('idVendor','idProduct'):
   old=d[k]; new=rng.choice([0x1209,0x1d6b,0xffff,0xCafe,0x2345,0x5678]) if k=='idVendor' else rng.randint(1,0xfffe)
   d[k]=new; changes.append({'field':'device.'+k,'before':old,'after':new})
 elif op=='interface-class':
  entries=all_ifaces(doc)
  if not entries: return None
  ci,ii,iface=rng.choice(entries); before=[iface.get(k,0) for k in ('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol')]
  label,triple=rng.choice(list(CLASS_TRIPLES.items()))
  for k,v in zip(('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol'),triple): iface[k]=v
  changes.append({'field':f'configuration[{ci}].interfaces[{ii}].class-triplet','before':before,'after':list(triple),'target':label})
 elif op=='add-interface':
  configs=doc.get('configurations',[])
  if not configs: return None
  ci=rng.randrange(len(configs)); cfg=configs[ci]; existing=cfg.get('interfaces',[])
  if not existing: return None
  source=rng.choice(existing); clone=copy.deepcopy(source)
  used={int(x.get('bInterfaceNumber',0)) for x in existing}; number=0
  while number in used: number+=1
  clone['bInterfaceNumber']=number; clone['bAlternateSetting']=0
  # This is intentionally a descriptor-level candidate. Runtime endpoint workers
  # and class-specific maps are not synthesized by this generator.
  cfg['interfaces'].append(clone); cfg['bNumInterfaces']=len({int(x.get('bInterfaceNumber',0)) for x in cfg['interfaces']})
  changes.append({'field':f'configuration[{ci}].interfaces','operation':'append cloned interface','source_interface':source.get('bInterfaceNumber'),'new_interface':number,'class_triplet':[clone.get('bInterfaceClass'),clone.get('bInterfaceSubClass'),clone.get('bInterfaceProtocol')],'execution_compatibility':'descriptor-only; runtime worker mapping not synthesized'})
 elif op=='remove-interface':
  candidates=[(ci,c) for ci,c in enumerate(doc.get('configurations',[])) if len(c.get('interfaces',[]))>1]
  if not candidates:return None
  ci,cfg=rng.choice(candidates); target=rng.choice(cfg['interfaces']); cfg['interfaces'].remove(target)
  # Renumber the remaining interfaces in order to retain a valid basic layout.
  old=target.get('bInterfaceNumber'); cfg['bNumInterfaces']=len({int(x.get('bInterfaceNumber',0)) for x in cfg['interfaces']})
  changes.append({'field':f'configuration[{ci}].interfaces','operation':'remove interface','removed_interface':old,'execution_compatibility':'descriptor-only; runtime worker mapping not synthesized'})
 return changes

def main():
 ap=argparse.ArgumentParser(description='Generate reproducible USB descriptor fuzz cases from a profile corpus')
 ap.add_argument('--corpus',nargs='*',default=['hid-keyboard.json','hid-mouse.json','hid-gamepad.json','cdc-acm-serial.json','msc-bot-disk.json','ccid-smartcard.json','composite-ccid-hid-keyboard.json','composite-cdc-hid-keyboard.json','composite-msc-hid-gamepad.json','composite-cdc-msc-hid-gamepad.json'])
 ap.add_argument('--iterations',type=int,default=50); ap.add_argument('--seed',type=int,default=20261116)
 ap.add_argument('--mutations',nargs='+',choices=['device-class','vid-pid','interface-class','add-interface','remove-interface'],default=['device-class','vid-pid','interface-class','add-interface','remove-interface'])
 ap.add_argument('--out-dir',default='runs/usb-fuzz')
 ap.add_argument('--execute',action='store_true',help='execute compatible scalar-mutation cases on Raw Gadget (requires root and explicit lab confirmation)')
 ap.add_argument('--confirm-lab',action='store_true'); ap.add_argument('--udc-driver'); ap.add_argument('--udc-device'); ap.add_argument('--speed',choices=['low','full','high'],default='high'); ap.add_argument('--dwell-seconds',type=float,default=8)
 a=ap.parse_args()
 if a.iterations<1: ap.error('--iterations must be >= 1')
 if a.execute and (not a.confirm_lab or not a.udc_driver or not a.udc_device): ap.error('--execute requires --confirm-lab --udc-driver and --udc-device')
 if a.execute and (not __import__('os').geteuid()==0): ap.error('--execute must run as root')
 rng=random.Random(a.seed); out=(ROOT/a.out_dir).resolve() if not Path(a.out_dir).is_absolute() else Path(a.out_dir); cases=out/'cases'; traces=out/'traces'; cases.mkdir(parents=True,exist_ok=True); traces.mkdir(parents=True,exist_ok=True)
 corpus=[]
 for name in a.corpus:
  p=Path(name); p=p if p.is_absolute() else CORPUS/p
  if p.exists(): corpus.append((p,json.loads(p.read_text())))
 if not corpus: ap.error('no readable corpus profiles found')
 rows=[]
 for attempt in range(1,a.iterations*20+1):
  if len(rows)>=a.iterations: break
  source,base=rng.choice(corpus); op=rng.choice(a.mutations); doc=copy.deepcopy(base); before=summary(doc); changes=mutate(doc,rng,op)
  if changes is None: continue
  cid=f'case-{len(rows)+1:05d}'; doc['profile_name']=f'fuzz-{cid}-{source.stem}'; dest=cases/(cid+'.json'); dest.write_text(json.dumps(doc,indent=2,ensure_ascii=False)+'\n')
  after=summary(doc); structural=op in ('add-interface','remove-interface'); row={'case_id':cid,'seed':a.seed,'corpus_profile':source.name,'mutation':op,'changes':changes,'input':before,'output':after,'profile_file':str(dest),'execution':'NOT_REQUESTED','observed':None,'verdict':'GENERATED_ONLY'}
  if a.execute:
   if structural: row['execution']='SKIPPED_RUNTIME_MAPPING_NOT_SYNTHESIZED'; row['verdict']='GENERATED_STRUCTURAL_CASE_NOT_EXECUTED'
   else:
    binary=ROOT/'build/usb-connect'; trace=traces/(cid+'.jsonl'); log=traces/(cid+'.log')
    cmd=[str(binary),'run',str(dest),'--backend','raw-gadget','--udc-driver',a.udc_driver,'--udc-device',a.udc_device,'--speed',a.speed,'--trace',str(trace),'--run-id',cid]
    start=time.monotonic()
    try:
     with log.open('w') as f:
      proc=subprocess.Popen(cmd,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
      try: proc.wait(timeout=a.dwell_seconds)
      except subprocess.TimeoutExpired: proc.send_signal(signal.SIGINT); proc.wait(timeout=5)
     ev=[]
     if trace.exists():
      for line in trace.read_text(errors='replace').splitlines():
       try: ev.append(json.loads(line))
       except ValueError: pass
     names=[x.get('event','') for x in ev]; configured=any(x=='SET_CONFIGURATION' for x in names); requests=names.count('CONTROL_REQUEST'); stalls=sum(x in ('CONTROL_STALL','ENDPOINT_STALL') for x in names); errors=sum('ERROR' in x for x in names)
     row['execution']='EXECUTED'; row['observed']={'return_code':proc.returncode,'duration_seconds':round(time.monotonic()-start,2),'host_control_requests':requests,'set_configuration':configured,'stalls':stalls,'backend_error_events':errors,'event_names':names,'trace':str(trace),'log':str(log)}
     row['verdict']='NO_HOST_CONTACT_OBSERVED' if not requests else ('HOST_CONFIGURED_OBSERVED' if configured and not stalls and not errors else 'HOST_CONTACT_WITH_ERRORS_OR_NO_CONFIGURATION')
    except Exception as e: row['execution']='LAUNCH_ERROR'; row['observed']={'error':str(e)}; row['verdict']='DEVICE_OR_BACKEND_FAILURE'
  rows.append(row)
 report={'generated_at':datetime.now(timezone.utc).isoformat(),'seed':a.seed,'iterations_requested':a.iterations,'cases_generated':len(rows),'corpus':[p.name for p,_ in corpus],'mutations':a.mutations,'execution_enabled':a.execute,'interpretation':'HOST_CONFIGURED_OBSERVED means SET_CONFIGURATION was seen in device trace; it does not prove Windows bound every interface driver. Correlate with Windows USBPcap and Device Manager. Structural add/remove interface cases are generated offline and skipped during --execute because matching runtime endpoint/class-worker mappings are not synthesized.','results':rows}
 (out/'fuzz-report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
 with (out/'fuzz-report.txt').open('w') as f:
  f.write('USB FUZZ REPORT — INPUT → MUTATION → OBSERVED OUTPUT\n'); f.write(f"Seed: {a.seed} | generated: {len(rows)} / requested: {a.iterations}\n\n")
  for r in rows:
   f.write(f"{r['case_id']} | corpus={r['corpus_profile']} | mutation={r['mutation']} | verdict={r['verdict']}\n")
   f.write('  INPUT: '+json.dumps(r['input'],ensure_ascii=False)+'\n'); f.write('  CHANGE: '+json.dumps(r['changes'],ensure_ascii=False)+'\n'); f.write('  OUTPUT: '+json.dumps(r['output'],ensure_ascii=False)+'\n'); f.write('  OBSERVED: '+json.dumps(r['observed'],ensure_ascii=False)+'\n  FILE: '+r['profile_file']+'\n\n')
 def j(x): return html.escape(json.dumps(x,ensure_ascii=False,indent=2))
 cards=[]
 for r in rows:
  cards.append(f"<details><summary><b>{html.escape(r['case_id'])}</b> · {html.escape(r['mutation'])} · {html.escape(r['verdict'])}</summary><h3>Вход до мутации</h3><pre>{j(r['input'])}</pre><h3>Что изменено</h3><pre>{j(r['changes'])}</pre><h3>Получившийся USB-профиль</h3><pre>{j(r['output'])}</pre><h3>Наблюдаемый результат</h3><pre>{j(r['observed'])}</pre><p>Файл: {html.escape(r['profile_file'])}</p></details>" )
 html_doc='<!doctype html><html lang="ru"><meta charset="utf-8"><title>USB fuzz report</title><style>body{font:15px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#222}details{border:1px solid #bbb;border-radius:8px;padding:12px;margin:12px 0}summary{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:12px;border-radius:6px}h1{margin-bottom:.2rem}.muted{color:#555}</style><h1>USB Fuzz Report</h1><p class="muted">Seed: '+str(a.seed)+' · Cases: '+str(len(rows))+' · Mode: '+('hardware execution' if a.execute else 'offline generation')+'</p><p>Каждая карточка показывает входной профиль, точную мутацию, сформированный выходной профиль и наблюдение (если запускался).</p>'+''.join(cards)+'</html>'
 (out/'fuzz-report.html').write_text(html_doc)
 print(f'Generated {len(rows)} cases. Reports: {out}/fuzz-report.html, fuzz-report.txt, fuzz-report.json')
 return 0
if __name__=='__main__': raise SystemExit(main())
