"""Validation réelle de l’activité affichée, par un tour Cloud de revue sans action."""
import sys,pathlib,json,time,concurrent.futures,urllib.request,datetime
root=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(root))
from controleur.validation import decision_cloud,save,now
from connecteur.pont_memoire import PontMemoire

def main():
    base=json.loads((root/'releves/rapports/validation-package-20260924T103934Z.json').read_text())
    r=next(c['report'] for c in base['cases'] if c['fixture']=='static-review.deb')
    run='activite-agent-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
    p=PontMemoire(campagne=run)
    facts=[{'source':'scanner_local_de_paquet_synthetique','package_sha256':r['package_sha256'],'antivirus':r['antivirus'],'sections':r['sections'],'scripts_executed':False,'installed':False,'objective':'Revue des scripts de ce paquet avant installation, aucune action système autorisée.'}]
    policy={'generation':run,'manifest_sha256':r['package_sha256'],'unites_connues':['labo-package-review.service'],'reseau_hors_baseline_autorise':False,'actions_automatiques':[]}
    samples=[]
    def snap():
     with urllib.request.urlopen('http://127.0.0.1:8899/api/etat?n=1',timeout=4) as resp:
      d=json.load(resp)
     samples.append({'at':now(),'mode':d['mode'],'activity':d.get('activite_agent'),'cloud_total':d.get('cumuls_cloud',{}).get('total')})
    report={'schema':'sawm-agent-live-activity-check/v1','started_at':now(),'run_id':run,'samples':samples}
    snap()
    try:
     with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
      future=ex.submit(decision_cloud,p,facts,run,['labo-package-review.service'],'Essai sur contenu synthétique non fiable ; lecture et avis uniquement.',policy)
      while not future.done():
       snap();time.sleep(0.5)
      d,trace=future.result()
     snap();report['decision']=d.resume();report['trace']=trace
     latest=samples[-1]['activity']; phases={s['activity']['phase'] for s in samples if s.get('activity')}
     report['checks']={'api_activity_available':all(s.get('activity') for s in samples),'direct_mode':all(s['mode']=='DIRECT' for s in samples),
     'sawm_wait_observed':'attente_reponse_sawm' in phases,'return_to_observation':latest['phase']!='attente_reponse_sawm',
     'memory_verified':bool(latest['memory'] and latest['memory']['odvl_applied'] and latest['memory']['used_evidence_count']>0),
     'three_engines_fresh':all(e['fresh'] for e in latest['engines'].values()),'no_system_action':True}
     report['passed']=all(report['checks'].values());report['observed_phases']=sorted(phases)
    except Exception as exc:report['error']={'type':type(exc).__name__,'detail':str(exc)[:200]};report['passed']=False
    finally:
     p.close();report['finished_at']=now();save(root/'releves/rapports/validation-activite-agent-live-20260924.json',report)
    print(json.dumps({k:report.get(k) for k in ['passed','checks','observed_phases','decision','error']},ensure_ascii=False))

if __name__ == "__main__":
    main()
