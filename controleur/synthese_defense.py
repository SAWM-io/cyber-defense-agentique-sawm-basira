"""Fige les mesures de campagne, vérifie les signatures et l'altération détectée."""
import collections,hashlib,json,pathlib,shutil,sys,tempfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from controleur import audit_signe as audit
from controleur import mesures_rapport as mesures
from controleur import validation as v
R=ROOT/'releves/rapports'

def main():
    report=json.loads((R/'campagne-defense-20260923.json').read_text())
    ids={c['id'] for c in report['cases']}
    cloud=[];seen=set()
    for line in (pathlib.Path.home()/'.sawm-labo/cloud-appels.jsonl').read_text().splitlines():
        e=json.loads(line)
        if e.get('run_id') in ids and e.get('event_id') not in seen:
            seen.add(e.get('event_id'));cloud.append(e)
    with urllib.request.urlopen('http://127.0.0.1:8899/api/etat?n=120',timeout=5) as f:state=json.load(f)
    events=[dict(e,genre='invite') for e in state['invite']]+[dict(e,genre='hote') for e in state['hote']]
    public=R/'defense-audit-ed25519.pub';shutil.copyfile(str(audit.DEFAULT_KEY)+'.pub',public)
    proofs=[]
    for case in report['cases']:
        path=R/('audit-'+case['id']+'.jsonl')
        result=audit.verifier(path,public_key_path=public)
        proofs.append({'id':case['id'],'journal':path.name,'validation':result})
    path=R/('audit-'+report['cases'][-1]['id']+'.jsonl')
    checks={}
    with tempfile.TemporaryDirectory(prefix='sawm-proof-check-') as tmp:
        dest=pathlib.Path(tmp)/'audit.jsonl'
        shutil.copyfile(str(path)+'.checkpoint.json',str(dest)+'.checkpoint.json')
        original=path.read_bytes()
        for label,data in [('modification',original.replace(b'"genre"',b'"genRe"',1)),('troncature',b'\n'.join(original.splitlines()[:-1])+b'\n')]:
            dest.write_bytes(data)
            try:audit.verifier(dest,public_key_path=public);checks[label]=False
            except audit.AuditInvalide:checks[label]=True
    summary={'schema':'sawm-defense-summary/v1','generated_at':v.now(),
       'cases':len(report['cases']),'statuses':dict(collections.Counter(c['status'] for c in report['cases'])),
       'application_origins':dict(collections.Counter(c.get('applied_by') for c in report['cases'])),
       'cloud_campaign_only':mesures.mesurer_cloud(cloud),'signed_journals':proofs,
       'tampering_rejected':checks,'resources_recent_snapshot':mesures.mesurer_ressources(events),
       'resources_scope':'Derniers échantillons du dashboard (120 demandés), pas toute la campagne.',
       'telemetry':state['telemetrie_invite'],
       'report_sha256':hashlib.sha256((R/'campagne-defense-20260923.json').read_bytes()).hexdigest()}
    v.save(R/'synthese-defense-20260923.json',summary)
    print(json.dumps({'cases':summary['cases'],'cloud_calls':len(cloud),'signatures_valid':len(proofs),'tampering_rejected':checks}))
if __name__=='__main__':main()
