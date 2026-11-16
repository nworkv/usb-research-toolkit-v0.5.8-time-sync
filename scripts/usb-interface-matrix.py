#!/usr/bin/env python3
"""Run a deterministic class/interface acceptance matrix (no descriptor mutation)."""
from __future__ import annotations
import argparse, json, os, signal, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = [
 'hid-keyboard.json','hid-mouse.json','hid-gamepad.json','hid-joystick.json','hid-consumer-control.json',
 'cdc-acm-serial.json','msc-bot-disk.json','ccid-smartcard.json','composite-ccid-hid-keyboard.json','composite-cdc-hid-keyboard.json',
 'composite-msc-hid-gamepad.json','composite-hid-keyboard-mouse-consumer.json',
 'composite-cdc-msc-hid-gamepad.json','multi-config-keyboard-mouse.json','vendor-bulk.json'
]

def read_trace(path: Path):
    events=[]
    if path.exists():
        for line in path.read_text(errors='replace').splitlines():
            try: events.append(json.loads(line))
            except ValueError: pass
    names=[e.get('event','') for e in events]
    req=sum(n=='CONTROL_REQUEST' for n in names)
    configured=[e for e in events if e.get('event')=='SET_CONFIGURATION']
    stalls=sum(n in ('CONTROL_STALL','ENDPOINT_STALL') for n in names)
    resets=sum(n in ('USB_RESET','RESET') for n in names)
    errors=sum('ERROR' in n for n in names)
    return {'events':len(events),'host_control_requests':req,'configured':bool(configured),
      'configuration_values':[e.get('configuration_value') for e in configured],
      'stalls':stalls,'resets':resets,'backend_error_events':errors,'event_names':names}

def interfaces(profile):
    found=[]
    for ci,cfg in enumerate(profile.get('configurations',[])):
      for iface in cfg.get('interfaces',[]):
        found.append({'configuration_index':ci,'configuration_value':cfg.get('bConfigurationValue'),
          'interface':iface.get('bInterfaceNumber'),'alternate':iface.get('bAlternateSetting',0),
          'class_code':iface.get('bInterfaceClass'),'subclass':iface.get('bInterfaceSubClass'),
          'protocol':iface.get('bInterfaceProtocol')})
    return found

def main():
    ap=argparse.ArgumentParser(description='Sequential known-profile USB interface acceptance matrix; no fuzz mutations')
    ap.add_argument('--udc-driver',required=True); ap.add_argument('--udc-device',required=True)
    ap.add_argument('--profiles',nargs='*',default=DEFAULTS,help='profile JSON filenames under profiles/templates')
    ap.add_argument('--dwell-seconds',type=float,default=10); ap.add_argument('--settle-seconds',type=float,default=3)
    ap.add_argument('--speed',choices=['low','full','high'],default='high')
    ap.add_argument('--out-dir',default='runs/interface-matrix'); ap.add_argument('--confirm-lab',action='store_true')
    ap.add_argument('--allow-research',action='store_true')
    a=ap.parse_args()
    if not a.confirm_lab: ap.error('real USB execution requires --confirm-lab')
    if os.name!='posix' or os.geteuid()!=0: ap.error('run on Linux as root (e.g. sudo -E python3 ...)')
    if a.dwell_seconds<1 or a.settle_seconds<0: ap.error('invalid dwell/settle duration')
    binary=ROOT/'build/usb-connect'
    if not binary.exists(): ap.error('build/usb-connect not found; build the project first')
    out=Path(a.out_dir).resolve(); traces=out/'traces'; traces.mkdir(parents=True,exist_ok=True)
    rows=[]; print('USB INTERFACE ACCEPTANCE MATRIX — NO MUTATIONS')
    print(f'UDC driver={a.udc_driver} device={a.udc_device}; output={out}')
    for i,name in enumerate(a.profiles,1):
      p=Path(name); p=p if p.is_absolute() else ROOT/'profiles/templates'/p
      if not p.is_file(): print(f'[{i}] SKIP: profile not found: {p}'); continue
      doc=json.loads(p.read_text()); ifaces=interfaces(doc); trace=traces/f'case-{i:03}.device.jsonl'
      log=traces/f'case-{i:03}.log'; cmd=[str(binary),'run',str(p),'--backend','raw-gadget','--udc-driver',a.udc_driver,'--udc-device',a.udc_device,'--speed',a.speed,'--trace',str(trace),'--run-id',f'interface-matrix-{i:03}']
      if a.allow_research: cmd.append('--allow-research')
      print(f'\n[{i}/{len(a.profiles)}] {name}: interfaces={len(ifaces)} classes='+','.join(f"0x{x['class_code']:02x}" for x in ifaces),flush=True)
      start=time.time(); status='LAUNCH_ERROR'; proc=None
      try:
        with log.open('w') as f:
          proc=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,text=True,cwd=ROOT)
          deadline=time.monotonic()+a.dwell_seconds
          while time.monotonic()<deadline and proc.poll() is None: time.sleep(.2)
          if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.terminate(); proc.wait(timeout=3)
          status='COMPLETED' if proc.returncode==0 else ('START_FAILED' if time.time()-start<2 else 'DEVICE_EXITED')
      except Exception as e:
        log.write_text(str(e)); status='LAUNCH_ERROR'
      obs=read_trace(trace)
      if status=='COMPLETED' and not obs['host_control_requests']: verdict='NO_HOST_CONTACT_OBSERVED'
      elif status!='COMPLETED': verdict='DEVICE_OR_BACKEND_FAILURE'
      elif not obs['configured']: verdict='HOST_CONTACT_NO_CONFIGURATION'
      elif obs['stalls'] or obs['backend_error_events']: verdict='CONFIGURED_WITH_ERRORS'
      else: verdict='CONFIGURED_OBSERVED_REVIEW_HOST_CAPTURE'
      row={'case':i,'profile':str(p),'profile_name':doc.get('profile_name',p.stem),'interfaces_expected':ifaces,
        'process_status':status,'verdict':verdict,'trace':str(trace),'log':str(log),'duration_seconds':round(time.time()-start,3),**obs}
      rows.append(row); print(f"  process={status}; verdict={verdict}; host requests={obs['host_control_requests']}; SET_CONFIGURATION={obs['configured']}; STALL={obs['stalls']}; reset={obs['resets']}",flush=True)
      if i<len(a.profiles) and a.settle_seconds: time.sleep(a.settle_seconds)
    report={'generated_at':datetime.now(timezone.utc).isoformat(),'mode':'descriptor-preserving acceptance matrix; no fuzz mutations',
      'note':'SET_CONFIGURATION confirms that the host selected a configuration, not that every interface driver bound or that all class data paths work. Confirm interface/driver acceptance in Windows Device Manager and inspect USBPcap.', 'results':rows}
    (out/'interface-matrix.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    with (out/'interface-matrix.txt').open('w') as f:
      f.write('USB INTERFACE ACCEPTANCE MATRIX\n\n')
      for r in rows:
        f.write(f"CASE {r['case']:03} {r['profile_name']} | {r['verdict']} | host_requests={r['host_control_requests']} configured={r['configured']} stalls={r['stalls']} resets={r['resets']}\n")
        for x in r['interfaces_expected']: f.write(f"  cfg={x['configuration_value']} iface={x['interface']} class=0x{x['class_code']:02x} subclass=0x{x['subclass']:02x} protocol=0x{x['protocol']:02x}\n")
        f.write(f"  trace={r['trace']}\n  log={r['log']}\n\n")
    print(f'\nReport: {out}/interface-matrix.txt and interface-matrix.json')
    return 0
if __name__=='__main__': raise SystemExit(main())
