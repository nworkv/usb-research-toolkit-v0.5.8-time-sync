#!/usr/bin/env python3
"""Replay an existing USB filter fuzz campaign from its saved JSON inputs.

The replay never regenerates profiles or reuses the PRNG. It executes the exact
saved input JSON files, in campaign order, after SHA-256 verification.
"""
from __future__ import annotations
import argparse, hashlib, html, json, os, signal, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def trace_summary(path: Path) -> dict:
    events=[]
    if path.exists():
        for line in path.read_text(errors='replace').splitlines():
            try: events.append(json.loads(line))
            except json.JSONDecodeError: pass
    names=[e.get('event','') for e in events]
    return {'event_count':len(events),'control_requests':names.count('CONTROL_REQUEST'),
            'set_configuration':names.count('SET_CONFIGURATION'),'stalls':sum('STALL' in n for n in names),
            'errors':sum('ERROR' in n for n in names),'events':names}

def main() -> int:
    ap=argparse.ArgumentParser(description='Replay exact saved USB fuzz campaign inputs in original order')
    ap.add_argument('--campaign',required=True,help='path to original campaign.json')
    ap.add_argument('--out-dir',required=True,help='new, empty directory for replay results')
    ap.add_argument('--udc-driver',required=True); ap.add_argument('--udc-device',required=True)
    ap.add_argument('--speed',choices=['low','full','high'],help='defaults to original campaign setting, else high for legacy campaigns')
    ap.add_argument('--dwell-seconds',type=float,help='defaults to original campaign setting, else 8 for legacy campaigns')
    ap.add_argument('--settle-seconds',type=float,help='defaults to original campaign setting, else 2 for legacy campaigns')
    ap.add_argument('--dry-run',action='store_true',help='verify all exact inputs and print replay plan; do not touch USB')
    ap.add_argument('--confirm-lab',action='store_true',help='required for real hardware replay')
    ap.add_argument('--allow-binary-mismatch',action='store_true',help='allow replay with a different usb-connect binary (reduces strict reproducibility)')
    a=ap.parse_args()
    campaign_path=Path(a.campaign).resolve()
    if not campaign_path.is_file(): ap.error(f'campaign file not found: {campaign_path}')
    try: campaign=json.loads(campaign_path.read_text(encoding='utf-8'))
    except Exception as e: ap.error(f'cannot read campaign JSON: {e}')
    results=campaign.get('results')
    if not isinstance(results,list) or not results: ap.error('campaign has no ordered results[]')
    if campaign.get('executed') is False or campaign.get('execution_enabled') is False:
        ap.error('source campaign was generation-only; there is no previous hardware run to repeat. Run the original campaign once on the lab host first.')
    base=campaign_path.parent
    out=Path(a.out_dir).resolve()
    if out.exists() and any(out.iterdir()): ap.error(f'output directory is not empty: {out}')
    speed=a.speed or campaign.get('execution_settings',{}).get('speed') or 'high'
    dwell=a.dwell_seconds if a.dwell_seconds is not None else campaign.get('execution_settings',{}).get('dwell_seconds',8)
    settle=a.settle_seconds if a.settle_seconds is not None else campaign.get('execution_settings',{}).get('settle_seconds',2)
    if dwell<=0 or settle<0: ap.error('dwell must be > 0 and settle must be >= 0')
    plan=[]
    for idx,row in enumerate(results,1):
        rel=row.get('input_file') or row.get('profile_file')
        if not rel: ap.error(f'case #{idx} has no input_file/profile_file; exact replay impossible')
        p=Path(rel); p=p if p.is_absolute() else (base/p).resolve()
        if not p.is_file(): ap.error(f'case #{idx} input missing: {p}')
        actual=sha256(p); expected=row.get('sha256')
        if expected and actual.lower()!=str(expected).lower(): ap.error(f'case #{idx} SHA-256 mismatch: expected {expected}, got {actual}')
        # Older fuzz-generator reports stored absolute profile_file and no digest.
        try: doc=json.loads(p.read_text(encoding='utf-8'))
        except Exception as e: ap.error(f'case #{idx} profile JSON unreadable: {e}')
        plan.append({'order':idx,'case':row.get('case',row.get('case_id',idx)),
                     'input_file':str(p),'sha256':actual,'profile_name':doc.get('profile_name'),
                     'vid':doc.get('device',{}).get('idVendor'),'pid':doc.get('device',{}).get('idProduct'),
                     'interfaces':sum(len(c.get('interfaces',[])) for c in doc.get('configurations',[])),
                     'original_execution':row.get('execution','UNKNOWN'),
                     'skip_replay':str(row.get('execution','')).startswith('SKIPPED_RUNTIME_MAPPING')})
    settings={'udc_driver':a.udc_driver,'udc_device':a.udc_device,'speed':speed,
              'dwell_seconds':dwell,'settle_seconds':settle}
    print(f"Verified {len(plan)} exact saved inputs; order preserved. Settings: {settings}")
    for item in plan:
        print(f"{item['order']:04d}. {item['case']} {item['profile_name']} VID:PID={item['vid']:04X}:{item['pid']:04X} interfaces={item['interfaces']} sha256={item['sha256']}")
    if a.dry_run:
        print('DRY RUN: no USB device was touched.')
        return 0
    if not a.confirm_lab: ap.error('real replay requires --confirm-lab')
    if os.name!='posix' or os.geteuid()!=0: ap.error('real replay requires Linux root on the Raspberry Pi')
    binary=ROOT/'build'/'usb-connect'
    if not binary.is_file(): ap.error(f'usb-connect binary not found: {binary}; build the toolkit first')
    original_binary_hash=campaign.get('usb_connect_sha256')
    current_binary_hash=sha256(binary)
    if original_binary_hash and original_binary_hash.lower()!=current_binary_hash.lower() and not a.allow_binary_mismatch:
        ap.error(f'usb-connect binary differs from original campaign (original {original_binary_hash}, current {current_binary_hash}); use the same build or explicitly pass --allow-binary-mismatch')
    out.mkdir(parents=True,exist_ok=True); traces=out/'traces'; traces.mkdir()
    rows=[]; started=datetime.now(timezone.utc).isoformat()
    for item in plan:
        n=item['order']; case=str(item['case'])
        if item['skip_replay']:
            rows.append({**item,'returncode':None,'timed_out_by_dwell':False,'duration_seconds':0,
                         'observed':{},'verdict':'NOT_REPLAYED_ORIGINAL_WAS_SKIPPED','trace':None,'log':None})
            print(f"[{n}/{len(plan)}] {case}: preserved original skip (no runtime mapping)",flush=True)
            continue
        trace=traces/f'case-{n:05d}.device.jsonl'; log=traces/f'case-{n:05d}.log'
        cmd=[str(binary),'run',item['input_file'],'--backend','raw-gadget','--udc-driver',a.udc_driver,
             '--udc-device',a.udc_device,'--speed',speed,'--trace',str(trace),'--run-id',f'replay-{n:05d}','--allow-research']
        t0=time.monotonic(); returncode=None; timed_out=False
        with log.open('w') as f:
            proc=subprocess.Popen(cmd,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+dwell
            while time.monotonic()<deadline and proc.poll() is None: time.sleep(.2)
            if proc.poll() is None:
                timed_out=True; proc.send_signal(signal.SIGINT)
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try: proc.wait(timeout=3)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            returncode=proc.returncode
        obs=trace_summary(trace)
        if returncode!=0: verdict='DEVICE_OR_BACKEND_FAILURE'
        elif not obs['control_requests']: verdict='NO_HOST_CONTACT_OBSERVED'
        elif not obs['set_configuration']: verdict='HOST_CONTACT_NO_CONFIGURATION'
        elif obs['stalls'] or obs['errors']: verdict='CONFIGURED_WITH_ERRORS'
        else: verdict='CONFIGURED_OBSERVED_REVIEW_HOST_CAPTURE'
        rows.append({**item,'returncode':returncode,'timed_out_by_dwell':timed_out,
                     'duration_seconds':round(time.monotonic()-t0,2),'observed':obs,
                     'verdict':verdict,'trace':str(trace.relative_to(out)), 'log':str(log.relative_to(out))})
        print(f"[{n}/{len(plan)}] {case}: {verdict}",flush=True)
        if settle: time.sleep(settle)
    report={'replay_of':str(campaign_path),'original_campaign_seed':campaign.get('seed'),
            'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),
            'exact_inputs_verified':True,'case_order_preserved':True,'original_skipped_cases_preserved':True,'original_usb_connect_sha256':original_binary_hash,'replay_usb_connect_sha256':current_binary_hash,'binary_match':(not original_binary_hash or original_binary_hash.lower()==current_binary_hash.lower()),'execution_settings':settings,
            'results':rows,
            'interpretation':'Replay used the exact saved JSON input files, not regenerated seed output. Gadget-side SET_CONFIGURATION does not prove Windows filter acceptance or driver binding; correlate with Windows USBPcap and Device Manager.'}
    (out/'replay.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    txt=['USB CAMPAIGN REPLAY — EXACT INPUTS','Original: '+str(campaign_path),'Settings: '+json.dumps(settings,ensure_ascii=False),'']
    for r in rows: txt.append(f"{r['order']:04d} {r['case']} {r['verdict']} | SHA256={r['sha256']} | VID:PID={r['vid']:04X}:{r['pid']:04X} | interfaces={r['interfaces']} | return={r['returncode']} | trace={r['trace']}")
    (out/'replay.txt').write_text('\n'.join(txt)+'\n',encoding='utf-8')
    cards=[]
    for r in rows:
        obs=r.get('observed',{})
        cards.append(f"<tr><td>{r['order']}</td><td>{html.escape(str(r['case']))}</td><td>{r['vid']:04X}:{r['pid']:04X}</td><td>{r['interfaces']}</td><td>{html.escape(r['verdict'])}</td><td>{obs.get('control_requests','—')}</td><td>{obs.get('set_configuration','—')}</td><td>{obs.get('stalls','—')}</td><td><code>{r['sha256']}</code></td></tr>")
    page='<!doctype html><html lang="ru"><meta charset="utf-8"><title>Повтор кампании USB</title><style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #aaa;padding:7px;text-align:left}code{font-size:11px;overflow-wrap:anywhere}</style><h1>Повтор USB-кампании</h1><p>Воспроизведены сохранённые JSON-входы с проверкой SHA-256 и исходным порядком. Это не новая генерация по seed.</p><p>'+html.escape(json.dumps(settings,ensure_ascii=False))+'</p><table><tr><th>#</th><th>Case</th><th>VID:PID</th><th>IF</th><th>Вердикт</th><th>Requests</th><th>SET_CONFIGURATION</th><th>STALL</th><th>SHA-256 входа</th></tr>'+''.join(cards)+'</table><p>SET_CONFIGURATION не доказывает прохождение фильтра или привязку драйвера Windows. Сопоставьте с USBPcap и Диспетчером устройств.</p></html>'
    (out/'replay.html').write_text(page,encoding='utf-8')
    print(f'Replay reports: {out}/replay.html, replay.txt, replay.json')
    return 0
if __name__=='__main__': raise SystemExit(main())
