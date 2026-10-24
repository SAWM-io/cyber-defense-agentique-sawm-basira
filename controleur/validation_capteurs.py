"""Mesures OS locales : fichiers cachés, CPU borné, collecte interrompue.
Aucune de ces opérations de provisionnement n'est créditée à SAWM.
"""
import json,time,uuid,urllib.request
from controleur import vm_labo as vm
from controleur.validation import ROOT,REPORTS,save,now,post,marker

def live():
 x=json.load(urllib.request.urlopen('http://127.0.0.1:8899/api/etat?n=1'))
 return x['invite'][-1] if x.get('invite') else {}
def cpu(s):return s.get('tranches',{}).get('charge',{}).get('cpu_usage_usec')
def rate(a,b):
 x,y=cpu(a),cpu(b);dt=(b.get('monotone_ns',0)-a.get('monotone_ns',0))/1e9
 return (y-x)/1e6/dt*100 if x is not None and y is not None and dt>0 and y>=x else None

def main():
 run='capteurs-'+time.strftime('%Y%m%dT%H%M%S');out={'run_id':run,'type':'capteurs','debut':now(),'origine_actions':'operateur de test, pas SAWM'}
 units={}
 for name,script,args in [('labo-fichiers','fichiers','--source-id ordinaire'),('labo-caches','fichiers','--source-id cache --hidden'),('labo-calcul','cpu','--source-id calcul --duty-pct 75')]:
  units[name+'.service']=f'[Unit]\nDescription=Mesure locale bornee\n[Service]\nSlice=sawm-charge.slice\nExecStart=/usr/bin/python3 /opt/sawm-labo/charges_test/{script}.py {args} --run-id {run} --duration 40\nMemoryMax=128M\nCPUQuota=85%\nRuntimeMaxSec=45\nKillMode=control-group\nTimeoutStopSec=3\n'
 vm.json_code("import pathlib,subprocess,json\na="+repr(units)+"\nfor n,s in a.items():\n p=pathlib.Path('/etc/systemd/system')/n;p.write_text(s)\nsubprocess.run(['systemctl','daemon-reload'],check=True)\nsubprocess.run(['systemctl','start',*a],check=True)\nprint('{}')")
 marker('charge','Mesure CPU et opérations fichiers ordinaires/cachés',run)
 observations=[]
 try:
  time.sleep(2);a=live()
  for _ in range(12):observations.append(live());time.sleep(1)
  b=live()
  out['pose_quota']=vm.commands([['systemctl','set-property','--runtime','labo-calcul.service','CPUQuota=15%']])
  time.sleep(2);c=live()
  for _ in range(12):observations.append(live());time.sleep(1)
  d=live();out['cpu_pct_un_coeur']={'avant_quota':rate(a,b),'apres_quota15':rate(c,d)}
  events={}
  for s in observations:
   for e in s.get('fichiers',{}).get('evenements',[]):
    if run in e['chemin']:events[(e['mur_epoch_ms'],e['chemin'],str(e['operations']))]=e
  out['evenements_fichiers']=list(events.values())
  out['fichiers_caches_vus']=any(e['chemin'].startswith('.') for e in events.values())
  out['fichiers_ordinaires_vus']=any(not e['chemin'].startswith('.') for e in events.values())
  out['pertes_inotify']=[s.get('fichiers',{}).get('pertes_file') for s in observations]
  out['temoin_disponible']=all(s.get('service_temoin',{}).get('disponible') is True for s in observations)
  out['mesures']={'fichiers_caches_vus':out['fichiers_caches_vus'],'fichiers_ordinaires_vus':out['fichiers_ordinaires_vus'],'cpu':out['cpu_pct_un_coeur'],'temoin_disponible':out['temoin_disponible']}
  out['succes_mesure']=bool(out['fichiers_caches_vus'] and out['fichiers_ordinaires_vus'] and out['temoin_disponible'] and rate(c,d) is not None and rate(c,d)<25 and rate(a,b)>45)
 finally:
  out['nettoyage_operateur']=vm.commands([['systemctl','stop',*units]])
  out['fin']=now();path=REPORTS/('experience-'+run+'.json');save(path,out)
  post('/api/marqueur',{'phase':'validation','texte':json.dumps(out.get('mesures',{}),ensure_ascii=False),'run_id':run,'preuves':['releves/rapports/'+path.name]})
 print(json.dumps({'rapport':str(path),'succes_mesure':out.get('succes_mesure'),'mesures':out.get('mesures')},ensure_ascii=False))
if __name__=='__main__':main()
