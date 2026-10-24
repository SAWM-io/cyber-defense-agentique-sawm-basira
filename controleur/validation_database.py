"""Campagne défensive réelle sur SQLite fictive, choix SAWM et preuves séparés.

Le lanceur crée seulement des unités labo-db-*.service à durée bornée, jamais
un binaire hostile. L'oracle des résultats n'entre pas dans le prompt SAWM.
Le nettoyage et la restauration opérateur ne sont pas comptés comme défense IA.
"""
from __future__ import annotations
import argparse,dataclasses,hashlib,json,pathlib,subprocess,sys,time,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from controleur import vm_labo as vm,validation as v
from controleur.verification_action import observer_ressource,verifier_action
from controleur.audit_signe import JournalSigne
from connecteur.pont_memoire import PontMemoire
from controleur.garde_database import proposer as garde_database,preservation_explicitement_autorisee
REPORT=ROOT/'releves/rapports/campagne-defense-20260923.json'
DB='/opt/sawm-labo/charges_test/database.py'
LIMITS=['Charges de test bornées, données comptables entièrement fictives ; aucun virus réel.',
        'La décision SAWM utilise les API publiques ; capteurs et exécuteur tournent dans cette même VM.',
        'Un résultat de laboratoire ne mesure pas le taux de détection général.',
        'Restauration et nettoyage opérateur restent distincts des décisions SAWM.',
        'Les observations en provenance du système ne résistent pas à un noyau déjà compromis.']
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def exclusive_rollback_lock(attribution):
    """POSIX write lock couvrant la plage SHARED SQLite, sur l'inode déjà filtré.

    Lecture du protocole Unix rollback-journal, pas un diagnostic WAL ni une
    attribution de toute écriture. Une réservation sur un seul octet ne suffit pas.
    https://www.sqlite.org/lockingv3.html
    """
    if attribution.get('identity_stable') is not True or attribution.get('fd_on_database') is not True:
        return False
    pid=str(attribution.get('systemd',{}).get('MainPID',''))
    for line in attribution.get('kernel_locks',[]):
        fields=line.split()
        if len(fields)!=8 or fields[1:4]!=['POSIX','ADVISORY','WRITE'] or fields[4]!=pid:
            continue
        try:
            if int(fields[6])<=1073741826 and (fields[7]=='EOF' or int(fields[7])>=1073742335):
                return True
        except ValueError:
            pass
    return False
def same_lock_holder(attribution,identity,now_ms):
    prior=attribution.get('systemd') or {};current=identity.get('unite') or {}
    observed=attribution.get('observed_at_ms')
    return (attribution.get('identity_stable') is True and type(observed) is int
            and 0<=now_ms-observed<=3000 and current.get('ActiveState')=='active'
            and prior.get('ActiveState')=='active'
            and all(prior.get(k) and prior[k]==current.get(k)
                    for k in ('MainPID','InvocationID','ControlGroup')))
def save(x):x['updated_at']=v.now();v.save(REPORT,x)
def db(action,run,**kw):
    args=['python3',DB,action,'--run-id',run]
    for k,val in kw.items():args+=['--'+k.replace('_','-'),str(val)]
    return vm.json_code('import subprocess,json\np=subprocess.run('+repr(args)+',capture_output=True,text=True,timeout=15)\nif p.returncode:raise RuntimeError(p.stderr[:200])\nprint(p.stdout)')
def owner(unit,run):
    src='unit='+repr(unit)+';run='+repr(run)+'\n'+r'''
import pathlib,subprocess,json,os,time
s=subprocess.run(['systemctl','show',unit,'-p','MainPID','-p','InvocationID','-p','ActiveState','-p','ControlGroup'],capture_output=True,text=True,check=True).stdout
u=dict(l.split('=',1) for l in s.splitlines() if '=' in l);pid=int(u.get('MainPID','0'))
r={'unit':unit,'systemd':u,'kernel_locks':[],'fd_on_database':False,'attribution_available':False}
p=pathlib.Path('/opt/sawm-labo/fixtures/database-defense')/('run-'+run)/'ledger.sqlite'
st=p.stat();ino=st.st_ino
for line in pathlib.Path('/proc/locks').read_text().splitlines():
 parts=line.split()
 try:
  dev=parts[5].split(':')
  if int(parts[4])==pid and int(dev[-1])==ino and int(dev[0],16)==os.major(st.st_dev) and int(dev[1],16)==os.minor(st.st_dev):r['kernel_locks'].append(line)
 except (IndexError,ValueError):pass
if pid:
 for f in pathlib.Path('/proc') .joinpath(str(pid),'fd').iterdir():
  try:
   fst=f.stat()
   if fst.st_ino==ino and fst.st_dev==st.st_dev:r['fd_on_database']=True
  except OSError:pass
 r['attribution_available']=r['fd_on_database'] and bool(r['kernel_locks'])
again=subprocess.run(['systemctl','show',unit,'-p','MainPID','-p','InvocationID','-p','ActiveState','-p','ControlGroup'],capture_output=True,text=True,check=True).stdout
after=dict(l.split('=',1) for l in again.splitlines() if '=' in l)
r['identity_stable']=after==u and pid>0 and u.get('ActiveState')=='active' and bool(u.get('InvocationID'))
r['attribution_available']=r['attribution_available'] and r['identity_stable']
r['observed_at_ms']=int(time.time()*1000)
print(json.dumps(r))
'''
    return vm.json_code(src)
def service_start(unit,run,mode,duration):
    # Une unité transitoire disparaît après stop : impossible alors de vérifier
    # la garde anti-relance. Définition éphémère /run, jamais activée au boot.
    text='[Unit]\nDescription=Fixture SQLite bornee\n[Service]\nType=simple\nSlice=sawm-charge.slice\nExecStart=/usr/bin/python3 '+DB+' '+mode+' --run-id '+run+' --duration '+str(duration)+'\nRuntimeMaxSec=185\nMemoryMax=128M\nCPUQuota=25%\nRestart=no\n'
    return vm.json_code('import pathlib,subprocess,json\np=pathlib.Path("/run/systemd/system")/'+repr(unit)+'\np.write_text('+repr(text)+');p.chmod(0o600)\nsubprocess.run(["systemctl","daemon-reload"],check=True)\nr=subprocess.run(["systemctl","start",'+repr(unit)+'],capture_output=True,text=True)\nprint(json.dumps({"returncode":r.returncode,"stderr":r.stderr[:300]}))')
def healthy():
    return vm.json_code("import urllib.request,json\nr=urllib.request.urlopen('http://127.0.0.1:8080/sante',timeout=2);print(json.dumps({'http_status':r.status,'healthy':r.status==200}))")
def configure(unit,run,authorized,ref):
    return vm.json_code('unit='+repr(unit)+';run='+repr(run)+';authorized='+repr(authorized)+';ref='+repr(ref)+'\n'+r'''
import pathlib,json,fcntl,os,hashlib
with open('/opt/sawm-labo/.executeur.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 p=pathlib.Path('/opt/sawm-labo/manifeste.json');m=json.loads(p.read_bytes())
 m['generation']=run;m['run_id']=run
 if unit not in m['unites_autorisees']:m['unites_autorisees'].append(unit)
 m['database_policy']={'unit':unit,'exclusive_lock_authorized':authorized,'integrity_required':True,'reference_sha256':ref,'availability_required':not authorized}
 tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(m));tmp.chmod(0o600);os.replace(tmp,p)
 data=p.read_bytes();m['_sha256']=hashlib.sha256(data).hexdigest()
 print(json.dumps(m))
''')
def cloud_policy(m):
    b=m['veille'];return {'generation':m['generation'],'manifest_sha256':m['_sha256'],'unites_connues':b['unites_connues'],'reseau_hors_baseline_autorise':b['reseau_hors_baseline_autorise'],'actions_automatiques':b['actions_automatiques'],'database_policy':m['database_policy']}
def read_campaign():
    if REPORT.exists():return json.loads(REPORT.read_text())
    return {'schema':'sawm-defense-campaign/v1','status':'running','run_id':'defense-20260923','cases':[],'limits':LIMITS}
def run_case(mode,authorized=False,local_guard=False,investigate=False):
    campaign=read_campaign();run='db-'+uuid.uuid4().hex[:10];unit='labo-'+run+'.service'
    title=('Verrou exclusif autorisé' if authorized else 'Verrou exclusif sans mandat') if mode=='lock' else 'Altération répétée et empreinte incohérente'
    if local_guard:title+=' + garde local'
    if investigate:title+=' + enquête SAWM'
    case={'protocol':('database-v8-preserve-mandate-fast-guard' if local_guard else 'database-v8-preserve-mandate') if investigate else 'database-v3-policy-availability','local_guard_enabled':local_guard,'id':run,'title':title,'status':'running','applied_by':'none','observations':{},'checks':{},'metrics':{}}
    campaign['cases'].append(case);campaign['status']='running';save(campaign)
    journal=JournalSigne(ROOT/'releves/rapports'/('audit-'+run+'.jsonl'))
    backup=vm.code("from pathlib import Path;print(Path('/opt/sawm-labo/manifeste.json').read_text())")
    private=pathlib.Path.home()/'.sawm-labo/campaign-backups';private.mkdir(mode=0o700,exist_ok=True)
    (private/(run+'-manifest.json')).write_text(backup)
    pont=PontMemoire(campagne=run,budget_rejeu=5 if investigate else 3)
    try:
        db('prepare',run);before=db('status',run);case['observations']['before']=before
        m=configure(unit,run,authorized,before['reference_sha256'])
        v.post('/api/incident',{'id':run,'titre':title,'statut':'ouvert','run_id':run,'faits':['Observation réelle SQLite sur la VM du laboratoire.']})
        assert service_start(unit,run,mode,180)['returncode']==0
        time.sleep(2)
        incident=db('status',run);attribution=owner(unit,run);case['observations']['incident']=incident
        if mode=='tamper':
            from controleur.observation_ecriture import observer_ecritures
            attribution['write_observation']=observer_ecritures(unit,run)
            case['checks']['writer_attributed_to_target']=attribution['write_observation']['attribution_available']
        case['checks']['lock_attributed_to_target']=attribution['attribution_available']
        case['metrics']['incident_at_ms']=int(time.time()*1000);save(campaign)
        facts=[{'database_baseline':{k:before[k] for k in ['read_available','write_available','reference_matches']},'sqlite':{k:val for k,val in incident.items() if k not in {'attribution_arret','command','pid','schema','fixture'}},'attribution_os':attribution},{'service_legitime':healthy()}]
        journal.append({'genre':'observations_avant_decision','run_id':run,'faits':facts,'policy_sha256':m['_sha256']})
        # Invariant local préautorisé : ne dépend pas de la latence du Cloud.
        # L'origine reste politique locale, jamais une décision SAWM inventée.
        if local_guard and exclusive_rollback_lock(attribution):
            local=garde_database(m,before,incident,attribution)
            if local is not None:
                from connecteur.tour_sawm import Decision
                local_id='local_'+uuid.uuid4().hex
                automatic=Decision(local_id,'','',local,None,'',(),0,False,None,None,None)
                identity=observer_ressource(unit)
                case['local_decision']={'action':local.action,'reason':local.justification,'decision_id':local_id}
                journal.append({'genre':'decision_locale_avant_cloud','decision':case['local_decision'],'attribution':attribution})
                receipt=(v.execute(automatic,run,attendu=identity)
                    if same_lock_holder(attribution,identity,int(time.time()*1000))
                    else {'applique':False,'refus':'detenteur_verrou_change_ou_expire'})
                case['receipt']=receipt
                if receipt.get('applique'):
                    case['applied_by']='local_policy'
                    case['verification']=verifier_action(local.action,unit,receipt,identity)
                    case['metrics']['containment_ms']=int(time.time()*1000)-case['metrics']['incident_at_ms']
                    case['observations']['after_local_before_cloud']=db('status',run)
                    journal.append({'genre':'verification_locale_avant_cloud','receipt':receipt,
                        'verification':case['verification'],'database':case['observations']['after_local_before_cloud']})
                    v.post('/api/decision',{'id':local_id,'incident_id':run,'action':local.action,
                        'statut':case['verification']['statut'],'raison_publique':local.justification,
                        'run_id':run,'origine':'Politique locale avant Cloud ; ne pas attribuer à SAWM'})
                save(campaign)
        t=time.monotonic()
        if investigate:
            from controleur.dispositions_serveur import DispositionsServeur
            from controleur.enquete_autonome import enqueter
            from controleur.environnement_serveur import inspecter
            from controleur.observation_ecriture import observer_ecritures
            def outil(action,cible,contexte=None):
                if cible!=unit:raise ValueError('cible hors mandat de cette enquête')
                if action!='inspecter-base':return inspecter(action,cible,contexte=contexte)
                current=db('status',run);who=owner(unit,run)
                writer=observer_ecritures(unit,run) if current['read_available'] else None
                return {'source':'mesures réelles VM','database':{k:v for k,v in current.items() if k not in {'command','pid','fixture','attribution_arret'}},
                    'lock_holder':{'established':who['attribution_available'],'unit':who['unit'],'systemd':who['systemd'],'locks':who['kernel_locks'],
                        'identity_stable':who['identity_stable'],'sqlite_rollback_exclusive_range_observed':exclusive_rollback_lock(who)},
                    'successful_writes':writer,
                    'write_observation_status':'not_sampled_database_busy' if writer is None else 'sampled',
                    'technical_semantics':'Un verrou exclusif SQLite en journal rollback empêche les autres connexions de lire et écrire sans nécessiter une écriture effective du détenteur. SQLITE_BUSY rend le contrôle SQL integrity_check indisponible, pas invalide. L’empreinte de fichier est une mesure distincte.',
                    'limits':'Compte système distinct de la personne ayant demandé l’action ; hash stable durant une sonde distinct de conformité à la référence.'}
            def etape(step):
                journal.append({'genre':'etape_enquete','step':step})
                case.setdefault('investigation_steps',[]).append(step)
                save(campaign)
                v.post('/api/marqueur',{'phase':'enquete','texte':json.dumps(step,ensure_ascii=False)[:1800],'run_id':run})
            # L'attribution tenue par le banc n'est PAS donnée au premier tour.
            # Le modèle doit demander et exploiter une inspection pour l'obtenir.
            initial=[{'unit':unit,'database_alert':{k:incident[k] for k in ('read_available','write_available','reference_matches')},'service_legitime':healthy()}]
            if case['applied_by']=='local_policy':
                initial.append({'local_action_already_executed':case['receipt'],
                    'database_after_local_action':case['observations']['after_local_before_cloud'],
                    'instruction_context':'Action attribuée à la politique locale ; proposer seulement la suite nécessaire.'})
            dispositions=DispositionsServeur(pathlib.Path.home()/'.sawm-labo/dispositions-campagne',
                'lab-'+hashlib.sha256((pont.espace+':'+pont.entite).encode()).hexdigest()[:48])
            snapshot=dispositions.observer(run+'-mesure','anomalie_verifiee',
                {'id':run+'-observation','unit':unit},incident['observed_epoch_ms'])
            case['observations']['dispositions']=snapshot
            v.post('/api/marqueur',{'phase':'disposition_serveur','texte':json.dumps(snapshot,ensure_ascii=False),'run_id':run})
            d,trace=enqueter(pont,initial,run,[unit],politique_locale=cloud_policy(m),inspecter_fn=outil,max_steps=3,on_step=etape,dispositions=snapshot)
        else:
            d,trace=v.decision_cloud(pont,facts,run,[unit],politique_locale=cloud_policy(m))
        case['metrics']['cloud_ms']=round((time.monotonic()-t)*1000)
        case['decision']={'action':d.resume()['action'] or 'refus','reason':d.proposition.justification if d.proposition else d.refus,'unknowns':list(d.proposition.inconnues) if d.proposition else [],'decision_id':d.decision_id,'executable':d.executable}
        case['cloud']={'job_ids':[j['job_id'] for j in trace.get('depot',{}).get('jobs',[])],'recall_count':trace.get('preuves_utilisees'),'odvl_available':bool(trace.get('odvl',{}).get('ranking'))}
        v.save(ROOT/'releves/rapports'/('decision-'+run+'.json'),trace)
        # Un service déjà arrêté n'a plus de cgroup actif à inspecter. Ne pas
        # transformer la disparition attendue de ce cgroup en échec du protocole.
        identity=observer_ressource(unit) if case['applied_by']=='none' else None
        if identity is not None and identity['unite']['ActiveState']!='active':raise RuntimeError('charge terminee avant decision; aucun arret SAWM creditable')
        journal.append({'genre':'decision','run_id':run,'decision':case['decision'],'identity':identity});save(campaign)
        selected=d;origin='sawm'
        if case['applied_by']=='none' and selected.executable and selected.proposition.action in {'arreter-service','geler-transfert','limiter-cpu'}:
            current=db('status',run)
            receipt=({'applique':False,'refus':'activite_couverte_par_mandat_database',
                'decision_id':selected.decision_id,'action':selected.proposition.action,'cible':unit}
                if preservation_explicitement_autorisee(m,unit,current)
                else v.execute(selected,run,attendu=identity))
            case['receipt']=receipt
            if receipt.get('refus'):
                case['local_veto']=receipt['refus']
                journal.append({'genre':'action_cloud_refusee_localement','receipt':receipt,'database':current})
            if receipt.get('applique'):
                case['applied_by']=origin
                case['verification']=verifier_action(selected.proposition.action,unit,receipt,identity)
                case['metrics']['containment_ms']=int(time.time()*1000)-case['metrics']['incident_at_ms']
        after=db('status',run);case['observations']['after']=after
        cur=owner(unit,run);stopped=cur['systemd'].get('ActiveState')=='inactive' and cur['systemd'].get('MainPID')=='0'
        case['checks'].update(target_stopped=stopped,read_restored=after['read_available'],write_restored=after['write_available'],hash_restored=after['reference_matches'],legitimate_service_alive=healthy()['healthy'])
        if authorized:
            case['checks']['sawm_preserved_authorized_activity']=not (d.proposition and d.proposition.action in {'arreter-service','geler-transfert','limiter-cpu'})
            case['checks']['local_policy_veto']=bool(case.get('local_veto'))
        expected=(not stopped and case['applied_by']=='none') if authorized else stopped and case['applied_by'] in ({'sawm','local_policy'} if local_guard else {'sawm'})
        case['checks']['expected_choice']=expected
        if mode=='lock' and not authorized:expected=expected and after['read_available'] and after['write_available']
        case['status']='passed' if expected and case['checks']['legitimate_service_alive'] else 'failed'
        proof=journal.append({'genre':'resultat','run_id':run,'case':case});case['proof']={'sha256':proof['sha256'],'signature_seq':proof['seq'],'cloud_archived':False}
        receipt= pont.deposer([{'id':'feedback','titre':'Retour observé défense base fictive '+run,'contenu':json.dumps({'case':case,'signed_digest':proof},ensure_ascii=False)}],budget_s=60)
        case['proof']['cloud_archived']=all(j['statut']=='completed' for j in receipt['jobs'])
    except Exception as e:
        case['status']='error';case['error']=str(e)[:300]
        proof=journal.append({'genre':'erreur_campagne','run_id':run,'case':case})
        case['proof']={'sha256':proof['sha256'],'signature_seq':proof['seq'],'cloud_archived':False}
        try:
            receipt=pont.deposer([{'id':'erreur','titre':'Erreur observée défense base fictive '+run,'contenu':json.dumps({'case':case,'signed_digest':proof},ensure_ascii=False)}],budget_s=30)
            case['proof']['cloud_archived']=all(j['statut']=='completed' for j in receipt['jobs'])
        except Exception:
            pass  # L'indisponibilité reste visible ; aucune preuve Cloud inventée.
    finally:
        # Safety timeout and operator cleanup are never counted as SAWM success.
        try:
            vm.commands([['systemctl','stop',unit]])
            clean=db('status',run)
            if not clean['reference_matches']:
                restore=db('restore',run);case['operator_restoration']=restore
                case['observations']['after_operator_restore']=db('status',run)
            case['cleanup']={'stopped_by_operator':case['applied_by'] not in {'sawm','local_policy'},'service_healthy':healthy()['healthy']}
        except Exception as e:case['cleanup']={'error':str(e)[:200]}
        vm.code('import pathlib,fcntl,os\nwith open("/opt/sawm-labo/.executeur.lock","a") as lock:\n fcntl.flock(lock,fcntl.LOCK_EX)\n p=pathlib.Path("/opt/sawm-labo/manifeste.json");t=p.with_suffix(".tmp");t.write_text('+repr(backup)+');t.chmod(0o600);os.replace(t,p)')
        campaign['status']='completed';save(campaign)
        v.post('/api/incident',{'id':run,'titre':title,'statut':case['status'],'run_id':run,'faits':['Résultat mesuré : '+case['status'],'Application : '+case['applied_by']]})
    print(json.dumps({'id':run,'status':case['status'],'decision':case.get('decision'),'checks':case['checks'],'error':case.get('error')},ensure_ascii=False),flush=True)
    return case
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['lock','tamper']);parser.add_argument('--authorized',action='store_true');parser.add_argument('--local-guard',action='store_true');parser.add_argument('--investigate',action='store_true');a=parser.parse_args();run_case(a.mode,a.authorized,a.local_guard,a.investigate)
