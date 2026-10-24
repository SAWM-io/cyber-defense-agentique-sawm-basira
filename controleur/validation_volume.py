"""Référence sans intervention : copie locale réelle 5 Gio de fixture répétée."""
import json,time,urllib.request
from controleur import vm_labo as vm
from controleur.validation import REPORTS,save,now,marker

def main():
 run='volume-'+time.strftime('%Y%m%dT%H%M%S');n=5*1024**3
 out={'run_id':run,'type':'volume','debut':now(),'volume_annonce':n,'origine_actions':'reference operateur, sans defense SAWM','corpus_unique_octets':None}
 unit=f'[Unit]\nDescription=Copie locale de reference bornee\n[Service]\nSlice=sawm-legitime.slice\nExecStart=/usr/bin/python3 /opt/sawm-labo/charges_test/transfert.py --source-id reference-volume --run-id {run} --bytes {n} --duration 120 --rate-bps {100*1024**2}\nMemoryMax=128M\nCPUQuota=90%\nRuntimeMaxSec=125\nTimeoutStopSec=3\n'
 vm.json_code("import pathlib,subprocess,json\np=pathlib.Path('/etc/systemd/system/labo-volume.service');p.write_text("+repr(unit)+");subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','start','labo-volume.service'],check=True);print('{}')")
 marker('reference','Copie locale 5 Gio, sans intervention, corpus répété',run)
 try:
  start=time.monotonic();probes=[]
  while time.monotonic()-start<130:
   d=json.load(urllib.request.urlopen('http://127.0.0.1:8899/api/etat?n=1'))['invite'][-1]
   probes.append(d['service_temoin']['disponible'])
   flows=[f for f in (d.get('recepteur') or {}).get('flux',{}).values() if f['run_id']==run]
   if flows and flows[0]['etat']!='en_cours':break
   time.sleep(1)
  snap=vm.snapshot();flow=next((f for f in snap['recepteur']['flux'].values() if f['run_id']==run),{})
  state=snap['charges'].get('reference-volume',{})
  out['mesures']={'annonces':n,'recus':flow.get('recus'),'etat':flow.get('etat'),'duree_s':state.get('ecoule_s'),'fin_naturelle':state.get('cause_fin'),'sondes_temoin':len(probes),'temoin_200':all(probes),'octets_uniques_fixture':state.get('octets_uniques_fixture')}
  out['succes_mesure']=flow.get('recus')==n and flow.get('etat')=='complet' and all(probes)
 finally:
  out['nettoyage_operateur']=vm.commands([['systemctl','stop','labo-volume.service']]);out['fin']=now()
  path=REPORTS/('experience-'+run+'.json');save(path,out)
 print(json.dumps({'rapport':str(path),'succes_mesure':out.get('succes_mesure'),'mesures':out.get('mesures')},ensure_ascii=False))
if __name__=='__main__':main()
