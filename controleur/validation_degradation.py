"""Interruption bornée de la seule télémétrie, restauration dans finally."""
import json,time,urllib.request
from controleur import vm_labo as vm
from controleur.validation import REPORTS,save,now,marker

def etat():
 x=json.load(urllib.request.urlopen('http://127.0.0.1:8899/api/etat?n=1'))
 return {'etat':x['telemetrie_invite'],'dernier_cpu':x['invite'][-1]['cpu'] if x['invite'] else None}
def main():
 run='degradation-'+time.strftime('%Y%m%dT%H%M%S');o={'run_id':run,'type':'degradation','debut':now(),'origine_actions':'operateur de test'}
 o['avant']=etat();marker('degradation','Coupure de télémétrie bornée à huit secondes',run)
 try:
  vm.commands([['systemctl','stop','labo-telemetrie']]);time.sleep(8);o['pendant']=etat();o['service_reel']=vm.snapshot()['temoin']
 finally:
  o['restauration']=vm.commands([['systemctl','start','labo-telemetrie']])
 time.sleep(2);o['apres']=etat()
 o['succes_mesure']=bool(o['avant']['etat']['connectee'] and not o['pendant']['etat']['connectee'] and o['apres']['etat']['connectee'] and o['service_reel']['code']==200 and o['pendant']['dernier_cpu'] is not None)
 o['mesures']={'deconnexion_signalee':not o['pendant']['etat']['connectee'],'age_pendant_ms':o['pendant']['etat']['age_ms'],'retour_connecte':o['apres']['etat']['connectee'],'temoin_code':o['service_reel']['code']};o['fin']=now()
 save(REPORTS/('experience-'+run+'.json'),o);print(json.dumps(o['mesures']))
if __name__=='__main__':main()
