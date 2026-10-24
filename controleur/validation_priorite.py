"""Mesure l'API ODVL sur un lot contrôlé, sans événement ni action sur la VM."""
import json,pathlib,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from connecteur.pont_memoire import PontMemoire
from controleur.priorite_incidents import prioriser_incidents
from controleur.validation import save,post,now

def main():
    tick=int(time.time()*1000)
    incidents=[{'id':'controle-disponible','unite':'labo-db-available.service','survenu_observe_ms':tick,
                'analysable':True,'faits':[{'sqlite':{'read_available':True,'write_available':True,'reference_matches':True}}]},
               {'id':'controle-verrou','unite':'labo-db-locked.service','survenu_observe_ms':tick,
                'analysable':True,'faits':[{'sqlite':{'read_available':False,'write_available':False,'reference_matches':True}}]},
               {'id':'controle-integrite','unite':'labo-db-integrity.service','survenu_observe_ms':tick,
                'analysable':True,'faits':[{'sqlite':{'read_available':True,'write_available':True,'reference_matches':False}}]}]
    pont=PontMemoire(campagne='priorite-controlee-20260923')
    start=time.monotonic()
    try: result=prioriser_incidents(pont,incidents,maintenant_ms=tick)
    finally:pont.close()
    report={'schema':'sawm-priority-validation/v1','generated_at':now(),'mode':'lot_controle_non_incident',
            'scope':'Trois états fictifs fournis à la vraie API ODVL ; aucun capteur, choix SAWM ou arrêt VM.',
            'duration_ms':round((time.monotonic()-start)*1000,3),'trace':result['trace'],
            'conservation':sorted(incidents,key=lambda x:x['id'])==sorted(result['incidents'],key=lambda x:x['id']),
            'limits':'Un rang est consultatif. Ce test ne démontre aucun gain de détection ni de délai global.'}
    save(ROOT/'releves/rapports/priorite-controlee-20260923.json',report)
    post('/api/marqueur',{'phase':'priorite_incidents','texte':json.dumps(report,ensure_ascii=False)[:3900],
                        'run_id':'priorite-controlee-20260923','origine':'Lot contrôlé, vraie API ODVL ; aucune attaque ni décision SAWM'})
    print(json.dumps(report,ensure_ascii=False))
if __name__=='__main__':main()
