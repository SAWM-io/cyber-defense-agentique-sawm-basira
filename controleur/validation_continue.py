#!/usr/bin/env python3
"""Essai réel borné de la veille déjà supervisée (aucun appel SAWM direct).

Redémarre seulement la veille, démarre une copie bénigne localhost pendant au
plus 90s, observe les décisions de la veille, nettoie et conserve tous résultats.
"""
import json,os,pathlib,signal,sys,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from controleur.vm_labo import json_code,commands

def get(path):
 with urllib.request.urlopen('http://127.0.0.1:8899'+path,timeout=5) as r:return json.load(r)

def main():
 run='continue-'+time.strftime('%Y%m%dT%H%M%S')
 report={'schema':'sawm-validation-continue/v1','run_id':run,'debut_ms':int(time.time()*1000)}
 state=ROOT/'releves/veille/etat.json'
 before=json.loads(state.read_text());report['avant_redemarrage']=before
 if before.get('analyse_en_cours'):raise RuntimeError('analyse en cours; pas de coupure du worker')
 os.kill(before['pid'],signal.SIGKILL)
 for _ in range(40):
  time.sleep(1)
  after=json.loads(state.read_text())
  if after.get('pid')!=before['pid'] and time.time()*1000-after['mur_epoch_ms']<3000:
   report['apres_redemarrage']=after;break
 else:raise RuntimeError('veille non reprise')
 report['reprise_supervisee']=True
 report['budget_conserve_apres_reprise']=after.get('analyses_reservees_derniere_heure') >= before.get('analyses_reservees_derniere_heure', 0)
 # Give the restarted reader one complete reference load before stimulus.
 report['securite_avant']=get('/api/securite')
 unit='''[Unit]
Description=Copie bornée de documents du laboratoire
[Service]
Slice=sawm-charge.slice
ExecStart=/usr/bin/python3 /opt/sawm-labo/charges_test/transfert.py --source-id source-b --run-id RUN --bytes 16777216 --duration 90 --rate-bps 131072
Restart=no
RuntimeMaxSec=95
MemoryMax=128M
CPUQuota=30%
TimeoutStopSec=3
'''.replace('RUN',run)
 try:
  report['demarrage_charge']=json_code('''import pathlib,subprocess,json,fcntl
with open('/opt/sawm-labo/.executeur.lock','a') as f:
 fcntl.flock(f,fcntl.LOCK_EX)
 subprocess.run(['systemctl','stop','labo-copie-b.service'],check=True)
 pathlib.Path('/run/sawm-labo/gardes/labo-copie-b.service.stop').unlink(missing_ok=True)
 d=pathlib.Path('/run/systemd/system/labo-copie-b.service.d')
 if d.exists():
  for p in d.glob('90-sawm-*.conf'):p.unlink()
 pathlib.Path('/etc/systemd/system/labo-copie-b.service').write_text(UNIT)
 subprocess.run(['systemctl','daemon-reload'],check=True)
 subprocess.run(['systemctl','start','labo-copie-b.service'],check=True)
print(json.dumps({'unite':'labo-copie-b.service','demarree':True}))'''.replace('UNIT',repr(unit)))
  report['observations']=[]
  for _ in range(75):
   time.sleep(1)
   e=get('/api/etat?n=1');guest=e['invite'][-1] if e['invite'] else {}
   inc=[i for i in e['incidents'] if i.get('mur_epoch_ms',0)>=report['debut_ms'] and 'labo-copie-b.service' in json.dumps(i.get('faits', []))]
   ids={i['id'] for i in inc}
   decisions=[d for d in e['decisions'] if d.get('mur_epoch_ms',0)>=report['debut_ms'] and d.get('incident_id') in ids]
   report['observations'].append({'mur_epoch_ms':int(time.time()*1000),'temoin':guest.get('service_temoin'),
    'telemetrie':e['telemetrie_invite'],'decisions':decisions,'incidents':inc})
   if any(d.get('statut') in ('verifie','echec','inconclusif','non_executee') for d in decisions):break
 finally:
  report['nettoyage_operateur']=commands([['systemctl','stop','labo-copie-b.service']])
  report['securite_apres']=get('/api/securite');report['fin_ms']=int(time.time()*1000)
  report['limites']=['Charge bénigne locale; aucune démonstration malware universel.',
   'Seules les décisions exécutées puis vérifiées par la veille comptent; le nettoyage ne lui est pas attribué.']
  dest=ROOT/'releves/rapports'/f'experience-{run}.json';dest.write_text(json.dumps(report,ensure_ascii=False,indent=2))
  print(json.dumps({'rapport':str(dest),'reprise_supervisee':report.get('reprise_supervisee'),
    'decisions':report.get('observations',[{}])[-1].get('decisions',[])},ensure_ascii=False),flush=True)
if __name__=='__main__':main()
