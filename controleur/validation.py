#!/usr/bin/env python3
"""Essais défensifs bornés du laboratoire réel, par les API publiques.

Aucun code fournisseur direct, aucune charge destructive. Les faits sont lus
sur la VM et les actions viennent de SAWM, validées séparément par l'exécuteur.
"""
from __future__ import annotations
import argparse,dataclasses,datetime,hashlib,json,math,os,pathlib,re,sys,time,urllib.request,uuid
from collections.abc import Mapping
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from controleur import vm_labo as vm
from connecteur.pont_memoire import PontMemoire
from connecteur.tour_sawm import TourSawm

REPORTS=ROOT/'releves/rapports';REPORTS.mkdir(parents=True,exist_ok=True)
URL='http://127.0.0.1:'+os.environ.get('LABO_HTTP','8899')
UNITS=['labo-copie-a.service','labo-copie-b.service','labo-repetition.service','labo-calcul.service']

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def post(route,obj):
    try:
        req=urllib.request.Request(URL+route,json.dumps(obj,ensure_ascii=False).encode(),{'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=2) as r:return json.load(r)
    except Exception:return None
def marker(phase,texte,run_id):
    post('/api/marqueur',{'phase':phase,'texte':texte,'run_id':run_id})
def save(path,obj):
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(obj,ensure_ascii=False,indent=2));temp.replace(path)

def configure(run,volume,rate):
    """Crée seulement des unités nommées du manifeste du laboratoire."""
    units={}
    for label,source,slice_,size,speed in [('a','source-a','sawm-legitime.slice',20*1024**3,2*1024**2),
                                         ('b','source-b','sawm-charge.slice',volume,rate)]:
        units[f'labo-copie-{label}.service']=f'''[Unit]
Description=Copie de documents de laboratoire {label}
[Service]
Slice={slice_}
ExecStart=/usr/bin/python3 /opt/sawm-labo/charges_test/transfert.py --source-id {source} --run-id {run} --bytes {size} --duration 300 --rate-bps {speed}
Restart=no
RuntimeMaxSec=305
MemoryMax=128M
CPUQuota=80%
TimeoutStopSec=3
'''
    manifest={'generation':run,'run_id':run,'operation_id':os.environ.get('SAWM_OPERATEUR_ID'),'actif':True,'unites_autorisees':[x for x in UNITS if x!='labo-copie-a.service'],'unites_protegees':['labo-copie-a.service'],'fenetre_verification_s':1,
              'tranches_autorisees':['sawm-charge.slice'],
              'bac_fixtures':'/opt/sawm-labo/fixtures','reference_fixtures':'/opt/sawm-labo/reference',
              'empreintes_fixtures':{},'recepteur':{'adresse':'127.0.0.1','port':9009},'quota_cpu_pct':15}
    code='''import pathlib,json,subprocess,fcntl,os
lock=open('/opt/sawm-labo/.executeur.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
units=UNITS_DATA
for name,text in units.items():
 subprocess.run(['systemctl','stop',name],capture_output=True)
 # Remove only the executor guard for a new explicit test generation.
 (pathlib.Path('/run/sawm-labo/gardes')/(name+'.stop')).unlink(missing_ok=True)
 d=pathlib.Path('/run/systemd/system')/(name+'.d')
 if d.exists():
  for p in d.glob('90-sawm-*.conf'):p.unlink()
 path=pathlib.Path('/etc/systemd/system')/name
 if path.is_symlink():path.unlink()
 path.write_text(text)
p=pathlib.Path('/opt/sawm-labo/manifeste.json');temp=p.with_suffix('.tmp');temp.write_text(json.dumps(MANIFEST_DATA));temp.chmod(0o600);os.replace(temp,p)
subprocess.run(['systemctl','daemon-reload'],check=True)
print(json.dumps({'generation':MANIFEST_DATA['generation']}))'''
    return vm.json_code(code.replace('UNITS_DATA',repr(units)).replace('MANIFEST_DATA',repr(manifest)))

def describe():
    return vm.json_code("import subprocess,json\np=subprocess.run(['/usr/bin/python3','/opt/sawm-labo/executeur/executeur.py','--describe'],capture_output=True,text=True);print(p.stdout)")

def identite_execution(attendu):
    unite=attendu.get('unite') or {}
    return {'cible':attendu.get('cible'),'boot_id':attendu.get('boot_id'),
            **{k:unite.get(k) for k in ('InvocationID','MainPID','ControlGroup')}}


def execute(decision,run,attendu=None,defense_authorisation=None):
    if not decision.executable:return {'applique':False,'refus':decision.refus}
    d=describe()
    req={'decision_id':decision.decision_id,'action':decision.proposition.action,
         'cible':decision.proposition.cible,'generation':run,'run_id':run,
         'manifest_sha256':d['manifest_sha256']}
    if attendu is not None:
        req['expected_identity']=identite_execution(attendu)
    if defense_authorisation is not None:
        req['defense_profondeur_autorisation'] = defense_authorisation
    return vm.json_code("import subprocess,json\np=subprocess.run(['/usr/bin/python3','/opt/sawm-labo/executeur/executeur.py'],input="+repr(json.dumps(req))+",capture_output=True,text=True,timeout=30);print(p.stdout)",timeout=40)

MEMORY_CONTEXT_SCHEMA='sawm-incident-memory/v1'
MAX_MEMORY_CONTEXT_BYTES=262144
MAX_MEMORY_CONTEXT_AGE_S=120.0


def _memory_copy(value):
    raw=json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':'))
    if len(raw.encode())>MAX_MEMORY_CONTEXT_BYTES:
        raise ValueError('contexte mémoire trop volumineux')
    return json.loads(raw)


def _memory_digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,allow_nan=False,
        sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _initial_memory_facts(facts):
    # Les lectures ajoutées au cours de l'enquête ne changent pas son incident.
    # Leur contenu reste donné au modèle comme faits non fiables à chaque tour.
    return [f for f in facts if not (isinstance(f,dict) and set(f)=={'OUTILS_NONFIABLES'})]


def _memory_scope(pont,facts,run,resources,context,politique_locale):
    identity={key:value if isinstance(value,str) else None
              for key in ('espace','entite') for value in (getattr(pont,key,None),)}
    return _memory_digest({'run':run,'resources':sorted(resources),'identity':identity,
        'facts':_initial_memory_facts(facts),'context':context,'politique_locale':politique_locale})


def _memory_query(facts,resources):
    """Choisir un vocabulaire de rappel depuis les champs, jamais un texte d'outil."""
    keys=set()
    def collect(value,depth=0):
        if depth>12:
            return
        if isinstance(value,dict):
            for key,child in value.items():
                keys.add(str(key).lower())
                collect(child,depth+1)
        elif isinstance(value,(list,tuple)):
            for child in value:
                collect(child,depth+1)
    collect(_initial_memory_facts(facts))
    if keys & {'sqlite','database','database_alert','database_baseline','reference_matches','read_available','write_available'}:
        topic='SQLite base de données disponibilité lecture écriture verrou exclusif intégrité SHA256 référence attribution PID cgroup'
    elif keys & {'cpu_percent_one_core','rss_bytes','cpu','cpu_pct','mesures_ressources','resource_alert','ressources_observees'}:
        topic='ressources CPU mémoire quota cgroup processus disponibilité service légitime'
    elif keys & {'octets_recus','observation_connexions','destination','connexions','sockets','reseau'}:
        topic='connexions réseau transfert octets destination processus mandat service légitime'
    else:
        topic='observations système processus disponibilité identité mandat preuves'
    return (' '.join(resources)+' '+topic)[:2000]


def _memory_candidates(proofs):
    if not isinstance(proofs,(list,tuple)) or len(proofs)>5:
        raise ValueError('preuves TSST hors contrat public')
    evidence=[]
    exclus_integrite=0
    integrite_non_renseignee=0
    for preuve in proofs:
        if not isinstance(preuve,Mapping):
            raise ValueError('preuve TSST hors contrat public')
        if 'integrity_verified' in preuve and type(preuve['integrity_verified']) is not bool:
            raise ValueError('vérification intégrité TSST non booléenne')
        if preuve.get('integrity_verified') is False:
            exclus_integrite+=1
        else:
            evidence.append(preuve)
            integrite_non_renseignee+=int('integrity_verified' not in preuve)
    candidates=[]
    by_candidate={}
    for e in evidence:
        if not isinstance(e,Mapping):
            raise ValueError('preuve TSST hors contrat public')
        cid=e.get('candidate_id') or e.get('evidence_id')
        score=e.get('score')
        if (not isinstance(cid,str) or not re.fullmatch(r'[A-Za-z0-9._~:+/=-]{1,160}',cid)
                or cid in by_candidate):
            raise ValueError('identifiant de candidat TSST absent, invalide ou dupliqué')
        if (isinstance(score,bool) or not isinstance(score,(int,float))
                or not 0<=score<=1 or not math.isfinite(score)):
            raise ValueError('score TSST attendu : nombre fini dans [0,1]')
        # PontMemoire attend (identifiant, score, importance). Un score nul
        # reste nul ; aucun score/poids de gravité n'est fabriqué par le labo.
        candidates.append((cid,float(score),0.0))
        by_candidate[cid]=e
    return evidence,candidates,by_candidate,exclus_integrite,integrite_non_renseignee


def _memory_order(evidence,candidates,by_candidate,odvl):
    if candidates:
        # La route publique rend `ranking`, permutation complète déjà ordonnée.
        # Ne pas trier de nouveau par score ni compléter un reçu invalide :
        # ODVL ne peut ajouter, enlever ou dupliquer une preuve.
        ranking=odvl.get('ranking') if isinstance(odvl,Mapping) else None
        if (not isinstance(odvl,Mapping) or odvl.get('schema')!='basira-odvl-ranking/v1'
                or not isinstance(ranking,list) or len(ranking)!=len(candidates)):
            raise ValueError('reçu ODVL hors contrat public')
        ids=[]
        for rank,row in enumerate(ranking,1):
            if (not isinstance(row,Mapping) or not isinstance(row.get('candidate_id'),str)
                    or type(row.get('rank')) is not int or row['rank']!=rank):
                raise ValueError('rang ODVL invalide')
            ids.append(row['candidate_id'])
        if len(set(ids))!=len(ids) or set(ids)!=set(by_candidate):
            raise ValueError('classement ODVL non conservatif')
        evidence=[by_candidate[cid] for cid in ids]
    elif odvl!={'available':False,'reason':'aucune_preuve'}:
        raise ValueError('classement ODVL sans preuve')
    return evidence


def _validate_memory_context(value,scope):
    snapshot=_memory_copy(value)
    fields={'schema','scope_sha256','created_monotonic','prepared_at','query','depot','rappel','odvl','sha256'}
    if (not isinstance(snapshot,dict) or set(snapshot)!=fields
            or snapshot['schema']!=MEMORY_CONTEXT_SCHEMA or snapshot['scope_sha256']!=scope):
        raise ValueError('contexte mémoire hors incident')
    if snapshot['sha256']!=_memory_digest({k:v for k,v in snapshot.items() if k!='sha256'}):
        raise ValueError('empreinte du contexte mémoire invalide')
    created=snapshot['created_monotonic']
    if (isinstance(created,bool) or not isinstance(created,(int,float)) or not math.isfinite(created)
            or not 0<=time.monotonic()-created<=MAX_MEMORY_CONTEXT_AGE_S):
        raise ValueError('contexte mémoire expiré')
    if (not isinstance(snapshot['rappel'],dict) or snapshot['rappel'].get('provenance')!='connecteur'
            or not isinstance(snapshot['depot'],dict) or not isinstance(snapshot['query'],str)
            or not isinstance(snapshot['prepared_at'],str)):
        raise ValueError('contexte mémoire hors contrat public')
    return snapshot


def decision_cloud(pont,facts,run,resources,context='',politique_locale=None,enquete=False,dispositions=None,enquete_budget=None,memory_context=None):
    started=time.monotonic()
    timings={'depot':0.0,'recall':0.0,'odvl':0.0}
    t=now()
    scope=_memory_scope(pont,facts,run,resources,context,politique_locale)
    reused=memory_context is not None
    if reused:
        snapshot=_validate_memory_context(memory_context,scope)
        receipt,recall_data,odvl=(snapshot[k] for k in ('depot','rappel','odvl'))
        evidence,candidates,by_candidate,exclus_integrite,integrite_non_renseignee=_memory_candidates(recall_data.get('preuves'))
    else:
        entry={'id':'obs-'+uuid.uuid4().hex[:10],'titre':'Observation système du laboratoire',
               'contenu':json.dumps({'faits':facts,'contexte_declare':context},ensure_ascii=False),'survenu_a':t}
        mark=time.monotonic()
        receipt=pont.deposer([entry],budget_s=45)
        timings['depot']=round((time.monotonic()-mark)*1000,3)
        query=_memory_query(facts,resources)
        mark=time.monotonic()
        recall=pont.rappeler(query,limite=5)
        timings['recall']=round((time.monotonic()-mark)*1000,3)
        recall_data=dataclasses.asdict(recall)
        evidence,candidates,by_candidate,exclus_integrite,integrite_non_renseignee=_memory_candidates(recall.preuves)
        mark=time.monotonic()
        odvl=pont.hierarchiser(candidates) if candidates else {'available':False,'reason':'aucune_preuve'}
        timings['odvl']=round((time.monotonic()-mark)*1000,3) if candidates else 0.0
        snapshot=_memory_copy({'schema':MEMORY_CONTEXT_SCHEMA,'scope_sha256':scope,
            'created_monotonic':started,'prepared_at':t,'query':query,
            'depot':receipt,'rappel':recall_data,'odvl':odvl})
        snapshot['sha256']=_memory_digest(snapshot)
    evidence=_memory_order(evidence,candidates,by_candidate,odvl)
    # The dashboard receives bounded measured metadata, never recalled text.
    # Publish only after the ODVL permutation has passed its integrity guard.
    marker('memoire_prete',json.dumps({'schema':'sawm-agent-memory-observation/v1',
        'evidence_count':len(recall_data.get('preuves') or []),'used_evidence_count':len(evidence),
        'odvl_applied':bool(candidates),'reused':reused,
        'memory_age_ms':round((time.monotonic()-snapshot['created_monotonic'])*1000,3)},ensure_ascii=False),run)
    # Détacher le cache avant tout appel au modèle : aucune mutation de son
    # entrée ne pourra altérer les preuves conservées pour le tour suivant.
    snapshot=_memory_copy(snapshot)
    evidence=_memory_copy(evidence)
    obs=[{'survenu_a':t,'source':'collecte OS et récepteur local','observation':f} for f in facts]
    explications=[{'reference':'declaration humaine non authentifiee','contexte':context}] if context else []
    msg=TourSawm.composer_message(faits=obs,manifeste=resources,rappels=evidence,
        explications=explications,politique_locale=politique_locale,outils_enquete=enquete,
        dispositions=dispositions,enquete_budget=enquete_budget)
    marker('analyse','Contexte mémoire de cet incident réutilisé, analyse SAWM Cloud demandée' if reused else 'Rappel TSST terminé, analyse SAWM Cloud demandée',run)
    mark=time.monotonic()
    decision=TourSawm(pont).jouer(msg,cibles_autorisees=set(resources),preuves_connecteur=evidence,max_tokens=1200)
    timings['model']=round((time.monotonic()-mark)*1000,3)
    marker('decision',f"SAWM: {decision.resume()['action'] or decision.refus}",run)
    post('/api/decision',{'id':decision.decision_id,'incident_id':run,'action':decision.resume()['action'] or 'refus',
                         'statut':'proposee' if decision.executable else 'refusee','raison_publique':decision.proposition.justification if decision.proposition else decision.refus,
                         'faits':[json.dumps(f,ensure_ascii=False)[:1500] for f in facts], 'run_id':run,'origine':'SAWM Cloud'})
    timings['total']=round((time.monotonic()-started)*1000,3)
    return decision,{'depot':receipt,'rappel':recall_data,
                    'preuves_exclues_integrite':exclus_integrite,'preuves_utilisees':len(evidence),
                    'preuves_integrite_non_renseignee':integrite_non_renseignee,
                    'odvl':odvl,'decision':dataclasses.asdict(decision),
                    'memory_context':snapshot,'memory_reused':reused,
                    'memory_age_ms':round((time.monotonic()-snapshot['created_monotonic'])*1000,3),
                    'timings_ms':timings}

def received(s,run,source):
    return sum(v['recus'] for v in (s.get('recepteur') or {}).get('flux',{}).values() if v['run_id']==run and v['source_id']==source)

def transfer(args):
    run='vm-'+time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:4]
    os.environ['LABO_RUN']=run
    out={'schema':'sawm-vm-validation/v1','run_id':run,'type':'transfert','debut':now(),
         'volume_annonce':args.bytes,'mandat_autorise':getattr(args,'authorized',False),'mode_donnees':'fixture réelle répétée; volume réseau distinct du corpus unique','etapes':[]}
    path=REPORTS/f'experience-{run}.json'
    configure(run,args.bytes,args.rate)
    post('/api/incident',{'id':run,'titre':'Transfert de documents à vérifier','statut':'ouvert','gravite':'a_verifier','run_id':run,'faits':['Observation de deux services de copie dans la VM.']})
    marker('debut','Début du run de mesure des transferts',run)
    p=PontMemoire(campagne=run)
    try:
        vm.commands([['systemctl','start','labo-copie-a.service','labo-copie-b.service']])
        time.sleep(3)
        before=vm.snapshot();out['etapes'].append({'phase':'avant_analyse','snapshot':before})
        facts=[{'unite':'labo-copie-b.service','source_id':'source-b','octets_recus':received(before,run,'source-b'),'destination':'127.0.0.1:9009','observation_connexions':before['sockets']},
               {'unite':'labo-copie-a.service','source_id':'source-a','octets_recus':received(before,run,'source-a'),'role_declare':'copie autorisée'},
               {'service_documentaire':before['temoin']}]
        context='La copie du service labo-copie-a.service est autorisée. Pour labo-copie-b.service aucun mandat de transfert n’a été présenté. Préserver le service documentaire et la copie autorisée. Si une clarification est nécessaire, la demander.'
        if getattr(args,'authorized',False):
            context='Le propriétaire a autorisé ces deux copies vers le récepteur local pour cette fenêtre, depuis ces fixtures. Aucun autre écart connu. Ces autorisations sont des déclarations du propriétaire, distinctes des mesures OS. Préserver la continuité et demander une information si réellement nécessaire.'
        d,trace=decision_cloud(p,facts,run,['labo-copie-a.service','labo-copie-b.service'],context)
        out['analyses']=[trace]
        if not getattr(args,'authorized',False) and d.proposition and d.proposition.action=='demander-clarification':
            out['clarification_humaine']=True
            marker('clarification','Contexte propriétaire: copie-b non autorisée sur ces fixtures',run)
            d,trace=decision_cloud(p,facts,run,['labo-copie-a.service','labo-copie-b.service'],context+' Le propriétaire confirme maintenant : labo-copie-b.service ne dispose pas d’autorisation pour copier ces documents. Cette information est un retour déclaré, pas une observation physique.')
            out['analyses'].append(trace)
        at_decision=vm.snapshot();out['etapes'].append({'phase':'decision','snapshot':at_decision})
        result=execute(d,run);out['recu']=result
        marker('application',json.dumps({'action':d.resume()['action'],'applique':result.get('applique')},ensure_ascii=False),run)
        applied=vm.snapshot();out['etapes'].append({'phase':'application','snapshot':applied})
        time.sleep(5)
        after=vm.snapshot();out['etapes'].append({'phase':'verification','snapshot':after})
        out['mesures']={'source_b_avant':received(before,run,'source-b'),'source_b_decision':received(at_decision,run,'source-b'),
                        'source_b_application':received(applied,run,'source-b'),'source_b_apres':received(after,run,'source-b'),
                        'source_a_progression_apres':received(after,run,'source-a')-received(applied,run,'source-a'),
                        'temoin_http':[s['snapshot']['temoin']['code'] for s in out['etapes']]}
        m=out['mesures']
        out['succes_mesure']=bool(result.get('applique') and m['source_b_apres']==m['source_b_application'] and m['source_b_decision']<args.bytes and m['source_a_progression_apres']>0 and all(x==200 for x in m['temoin_http']))
        if getattr(args,'authorized',False):
            out['succes_mesure']=bool(d.proposition and d.proposition.action in ('ne-rien-faire','ouvrir-dossier') and m['source_b_apres']>m['source_b_application'] and m['source_a_progression_apres']>0 and all(x==200 for x in m['temoin_http']))
        out['retour_memoire']=p.deposer([{'id':'retour-'+run,'titre':'Résultat observé de la décision','contenu':json.dumps({'decision_id':d.decision_id,'mesures':m,'recu':result,'succes_mesure':out['succes_mesure']},ensure_ascii=False),'survenu_a':now()}])
        post('/api/decision',{'id':d.decision_id,'incident_id':run,'action':d.resume()['action'] or 'refus','statut':'verifiee' if out['succes_mesure'] else 'a_revoir','raison_publique':d.proposition.justification if d.proposition else d.refus,'run_id':run,'origine':'SAWM Cloud','preuves':['releves/rapports/'+path.name]})
        post('/api/incident',{'id':run,'titre':'Transfert de documents à vérifier','statut':'resolu' if out['succes_mesure'] else 'a_revoir','run_id':run,'faits':[json.dumps(m)],'preuves':['releves/rapports/'+path.name]})
    except Exception as exc:
        out['erreur']={'type':type(exc).__name__,'detail':str(exc)[:240]};out['succes_mesure']=False
    finally:
        # Cleanup is never credited to SAWM's intervention.
        out['nettoyage_operateur']=vm.commands([['systemctl','stop','labo-copie-a.service','labo-copie-b.service']])
        out['fin']=now();save(path,out);p.close()
    print(json.dumps({'rapport':str(path),'succes_mesure':out.get('succes_mesure'),'mesures':out.get('mesures'),'erreur':out.get('erreur')},ensure_ascii=False),flush=True)
    return out

def main():
    import signal
    def interrompre(*_):raise KeyboardInterrupt('arrêt opérateur')
    signal.signal(signal.SIGTERM,interrompre)
    ap=argparse.ArgumentParser();ap.add_argument('scenario',choices=['transfert']);ap.add_argument('--bytes',type=int,default=1024**3);ap.add_argument('--rate',type=int,default=8*1024**2)
    ap.add_argument('--authorized',action='store_true')
    a=ap.parse_args()
    if not 1<=a.bytes<=20*1024**3 or not 1<=a.rate<=100*1024**2:ap.error('quota hors laboratoire')
    transfer(a)
if __name__=='__main__':main()
