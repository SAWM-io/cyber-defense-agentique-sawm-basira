"""Contrôles bornés HTTP/LSM, distincts des décisions du modèle SAWM."""
from __future__ import annotations
import contextlib,io,json,pathlib,sys,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from controleur import vm_labo as vm, validation as v, validation_noyau
from controleur.validation_database import read_campaign,save
from controleur.audit_signe import JournalSigne
from connecteur.pont_memoire import PontMemoire

def conserver(case):
    case['applied_by']='local_policy'
    case['decision']={'action':'politique-locale','reason':'Contrôle déterministe HTTP/LSM ; aucune décision SAWM créditée.'}
    j=JournalSigne(ROOT/'releves/rapports'/('audit-'+case['id']+'.jsonl'))
    anchor=j.append({'genre':'validation_locale','case':case})
    case['proof']={'sha256':anchor['sha256'],'signature_seq':anchor['seq'],'cloud_archived':False}
    campaign=read_campaign();campaign['cases'].append(case);save(campaign)
    try:
        pont=PontMemoire(campagne=case['id'])
        receipt=pont.deposer([{'id':'resultat','titre':case['title'],'contenu':json.dumps({'case':case,'signed_digest':anchor},ensure_ascii=False)}],budget_s=60)
        case['proof']['cloud_archived']=all(j['statut']=='completed' for j in receipt['jobs'])
        case['cloud']={'job_ids':[j['job_id'] for j in receipt['jobs']]}
    except Exception as e:
        case['cloud']={'error':str(e)[:200]}
    save(campaign)
    v.post('/api/marqueur',{'phase':'validation','texte':case['title']+' : '+case['status']+' (politique locale)','run_id':case['id']})
    print(json.dumps(case,ensure_ascii=False),flush=True)

def authentication():
    result=vm.json_code(r'''
import sys,json,urllib.request,urllib.error
sys.path.insert(0,'/opt/sawm-labo/agent')
from jetons import emettre,tourner,version_courante
def probe(token=None):
    req=urllib.request.Request('http://127.0.0.1:8080/document',headers={'X-Labo-Jeton':token} if token else {})
    try:
        with urllib.request.urlopen(req,timeout=3) as r:return r.status
    except urllib.error.HTTPError as e:return e.code
version=version_courante();legitime=emettre()
r={'sans_jeton':probe(),'jeton_non_signe':probe('v'+str(version)+'.imposteur'),
   'signature_invalide':probe('v'+str(version)+'.'+'0'*32+'.'+'0'*64),
   'jeton_legitime_avant':probe(legitime)}
tourner()
r.update(jeton_revoque=probe(legitime),nouveau_jeton_legitime=probe(emettre()))
print(json.dumps(r))
''')
    checks={k:result[k]==expected for k,expected in {'sans_jeton':401,'jeton_non_signe':401,'signature_invalide':401,'jeton_legitime_avant':200,'jeton_revoque':401,'nouveau_jeton_legitime':200}.items()}
    conserver({'id':'auth-'+uuid.uuid4().hex[:10],'title':'Accès HTTP falsifié et révocation réelle','status':'passed' if all(checks.values()) else 'failed','observations':{'incident':result},'checks':checks})

def kernel():
    output=io.StringIO()
    with contextlib.redirect_stdout(output):validation_noyau.main()
    result=json.loads(output.getvalue())
    conserver({'id':result['run_id'],'title':'Refus LSM ciblé, lecture root réelle','status':'passed' if result['succes_mesure'] else 'failed','observations':{'incident':result},'checks':{'kernel_denied_read':result['succes_mesure']}})

if __name__=='__main__':
    authentication()
    kernel()
