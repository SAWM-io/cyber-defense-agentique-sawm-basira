"""Validation bornée, exclusivement Mac -> VM du laboratoire et deux netns privées.

Un service d'authentification fictif sur 8082, cinq essais par source. Ne cible
ni SSH ni un compte réel. Les secrets jetables restent en mémoire et dans une
configuration hachée 0600 de l'invité. Aucun mot de passe n'entre dans le rapport.
"""
from __future__ import annotations
import argparse, datetime, hashlib, ipaddress, json, os, pathlib, secrets, sys, time, urllib.request, urllib.error
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controleur import vm_labo as vm
from controleur.validation import save, post, now

REPORT = ROOT/'releves/rapports/validation-acces-exterieur-20260923.json'
DETAIL = ROOT/'releves/rapports/preuves-acces-exterieur-20260923.json'
HOST = os.environ.get('SAWM_LABO_AUTH_TEST_HOST', '')
CONTROLLER_IP = os.environ.get('SAWM_LABO_AUTH_TEST_SOURCE', '')
NS = [('sawm-auth-a', 'swau-ha', 'swau-na', '10.203.0.1', '10.203.0.2'),
      ('sawm-auth-b', 'swau-hb', 'swau-nb', '10.203.0.5', '10.203.0.6')]
NFT = '''table inet sawm_auth_guard {
 set blocked4 { type ipv4_addr; flags timeout; size 4096; }
 set blocked6 { type ipv6_addr; flags timeout; size 4096; }
 chain input {
  type filter hook input priority -5; policy accept;
  tcp dport 8082 ip saddr @blocked4 counter drop
  tcp dport 8082 ip6 saddr @blocked6 counter drop
 }
}
'''
UNIT = '''[Unit]
Description=Authentification fictive du laboratoire SAWM, port 8082 uniquement
After=network-online.target
[Service]
ExecStartPre=/usr/bin/python3 /opt/sawm-labo/agent/auth_guard_firewall.py
ExecStart=/usr/bin/python3 /opt/sawm-labo/agent/auth_guard.py
Restart=on-failure
RestartSec=2
User=root
Slice=sawm-defense.slice
MemoryMax=128M
CPUQuota=25%
TasksMax=32
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/opt/sawm-labo/auth-guard
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
[Install]
WantedBy=multi-user.target
'''

def request(password=None, *, namespace=None, xff=None):
    payload = None if password is None else {'username':'demo-cto', 'password':password}
    route = '/health' if payload is None else '/login'
    headers = {'Content-Type':'application/json'}
    if xff: headers['X-Forwarded-For'] = xff
    if namespace:
        if namespace not in {x[0] for x in NS}: raise ValueError('namespace hors laboratoire')
        script = '''import urllib.request,urllib.error,json,time
t=time.monotonic()
q=urllib.request.Request(URL,data=DATA,headers=HEADERS)
try:
 with urllib.request.urlopen(q,timeout=1.2) as r: result={'status':r.status,'body':json.load(r)}
except urllib.error.HTTPError as e:
 result={'status':e.code,'body':json.load(e)}
except Exception as e:result={'status':None,'error':type(e).__name__}
result['duration_ms']=round((time.monotonic()-t)*1000,3)
print(json.dumps(result))
'''
        script='URL='+repr('http://'+HOST+':8082'+route)+'\nDATA='+repr(json.dumps(payload).encode() if payload else None)+'\nHEADERS='+repr(headers)+'\n'+script
        return vm.json_code("import subprocess,json\np=subprocess.run(['ip','netns','exec',"+repr(namespace)+",'python3','-'],input="+repr(script)+",text=True,capture_output=True,timeout=5)\nif p.returncode: raise RuntimeError('requete espace reseau echouee')\nprint(p.stdout)",timeout=10)
    started=time.monotonic()
    q=urllib.request.Request('http://'+HOST+':8082'+route,data=json.dumps(payload).encode() if payload else None,headers=headers)
    try:
        with urllib.request.urlopen(q,timeout=1.2) as r: result={'status':r.status,'body':json.load(r)}
    except urllib.error.HTTPError as e: result={'status':e.code,'body':json.load(e)}
    except Exception as e: result={'status':None,'error':type(e).__name__}
    result['duration_ms']=round((time.monotonic()-started)*1000,3)
    return result

def kernel():
    return vm.json_code("import subprocess,json\np=subprocess.run(['nft','-j','list','table','inet','sawm_auth_guard'],text=True,capture_output=True,check=True)\nprint(p.stdout)")

def ban_present(state, ip):
    # nft may put live elements either in the set or an element record.
    def walk(v):
        if v == ip: return True
        if isinstance(v,dict): return any(walk(x) for x in v.values())
        if isinstance(v,list): return any(walk(x) for x in v)
        return False
    return walk(state)

def packets(state):
    total=0
    for row in state.get('nftables',[]):
        for expr in row.get('rule',{}).get('expr',[]):
            total += expr.get('counter',{}).get('packets',0)
    return total

def witness():
    return vm.json_code("import urllib.request,json,subprocess\nwith urllib.request.urlopen('http://127.0.0.1:8080/sante',timeout=2) as r: status=r.status\np=subprocess.run(['systemctl','is-active','labo-telemetrie.service','labo-lsm.service','labo-capteur-exec.service'],text=True,capture_output=True)\nprint(json.dumps({'http':status,'ssh_access':True,'protection_services':p.stdout.splitlines()}))")

def provision(password, ownership):
    vm.push(ROOT/'invite/agent_labo/auth_guard.py','/opt/sawm-labo/agent/auth_guard.py')
    vm.push(ROOT/'invite/agent_labo/auth_guard_firewall.py','/opt/sawm-labo/agent/auth_guard_firewall.py')
    # Only the owned table can be refreshed. Existing unrelated firewall remains.
    source = '''import pathlib,subprocess,json,hashlib,secrets,os
def run(a,**kw):return subprocess.run(a,check=True,capture_output=True,text=True,**kw)
marker=pathlib.Path('/opt/sawm-labo/auth-guard/netns-owner.json')
if marker.exists():raise RuntimeError('proprietaire namespace precedent a examiner')
names=run(['ip','netns','list']).stdout.splitlines()
if any(any(line.split()[0]==n[0] for line in names) for n in NAMES):raise RuntimeError('namespace de test deja present')
for n in NAMES:
 if subprocess.run(['ip','link','show',n[1]],capture_output=True).returncode==0:raise RuntimeError('interface de test deja presente')
unit=pathlib.Path('/etc/systemd/system/labo-auth-guard.service')
if unit.exists() and 'Authentification fictive du laboratoire SAWM' not in unit.read_text():raise RuntimeError('unite etrangere')
subprocess.run(['systemctl','stop','labo-auth-guard.service'],capture_output=True)
has=subprocess.run(['nft','list','table','inet','sawm_auth_guard'],capture_output=True).returncode==0
if has and not unit.exists():raise RuntimeError('table preexistante non attribuee')
if has:run(['nft','delete','table','inet','sawm_auth_guard'])
run(['nft','-f','-'],input=RULES)
base=pathlib.Path('/opt/sawm-labo/auth-guard');base.mkdir(mode=0o700,exist_ok=True)
owned={'token':OWNER_TOKEN,'names':[],'links':[]}
def record():
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(owned,f)
record()
salt=secrets.token_bytes(16)
config={'schema':'sawm-auth-guard-config/v1','username':'demo-cto','salt_hex':salt.hex(),
 'password_hash_hex':hashlib.pbkdf2_hmac('sha256',PASSWORD.encode(),salt,200000).hex(),
 'pbkdf2_iterations':200000,'threshold':5,'window_s':30,'ban_s':60}
path=base/'config.json'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump(config,f)
path.chmod(0o600)
unit.write_text(UNIT_DATA);unit.chmod(0o644)
run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','labo-auth-guard.service'])
for name,host,peer,hostip,peerip in NAMES:
 run(['ip','netns','add',name]);owned['names'].append(name);record()
 run(['ip','link','add',host,'type','veth','peer','name',peer]);owned['links'].append(host);record()
 run(['ip','link','set',peer,'netns',name]);run(['ip','addr','add',hostip+'/30','dev',host]);run(['ip','link','set',host,'up'])
 run(['ip','netns','exec',name,'ip','addr','add',peerip+'/30','dev',peer]);run(['ip','netns','exec',name,'ip','link','set',peer,'up'])
 run(['ip','netns','exec',name,'ip','link','set','lo','up']);run(['ip','netns','exec',name,'ip','route','add',AUTH_HOST+'/32','via',hostip])
print(json.dumps({'service':run(['systemctl','is-active','labo-auth-guard.service']).stdout.strip(),'namespace_count':len(NAMES),'password_logged':False}))
'''
    source='AUTH_HOST='+repr(HOST)+'\nNAMES='+repr(NS)+'\nRULES='+repr(NFT)+'\nPASSWORD='+repr(password)+'\nUNIT_DATA='+repr(UNIT.replace('[Service]','[Service]\nEnvironment=LABO_AUTH_BIND='+HOST))+'\nOWNER_TOKEN='+repr(ownership)+'\n'+source
    return vm.json_code(source,timeout=45)

def cleanup(ownership):
    return vm.json_code('''import subprocess,json,pathlib
p=pathlib.Path('/opt/sawm-labo/auth-guard/netns-owner.json')
owned=json.loads(p.read_text()) if p.exists() else {}
if owned.get('token')==TOKEN:
 for name in owned['names']:
  if name not in ('sawm-auth-a','sawm-auth-b'):raise RuntimeError('namespace inconnu')
  subprocess.run(['ip','netns','delete',name],capture_output=True)
 for link in owned['links']:
  if link not in ('swau-ha','swau-hb'):raise RuntimeError('interface inconnue')
  subprocess.run(['ip','link','delete',link],capture_output=True)
 p.unlink()
print(json.dumps({'namespaces':subprocess.run(['ip','netns','list'],capture_output=True,text=True).stdout.splitlines()}))
'''.replace('TOKEN',repr(ownership)))

def analyse_cloud():
    from connecteur.pont_memoire import PontMemoire
    from controleur.validation import decision_cloud
    report=json.loads(REPORT.read_text())
    if report['status'] not in ('passed','failed') or not report['events']:raise RuntimeError('essais_non_termines')
    detail_path=ROOT/'releves/rapports/analyse-acces-exterieur-20260923.json'
    if detail_path.exists():detail_path.with_name(detail_path.stem+'-avant-'+str(int(time.time()*1000))+'.json').write_bytes(detail_path.read_bytes())
    run='acces-exterieur-20260923';pont=PontMemoire(campagne=run,post_evenement=lambda e:post('/api/cloud',e))
    facts=[{'auth_test':{'scope':report['scope'],'cases':report['cases'],'events':report['events'],
                       'correlations':report['correlations'],'geography':report['geography']}}]
    manifest=vm.json_code("import pathlib,hashlib,json\np=pathlib.Path('/opt/sawm-labo/manifeste.json');m=json.loads(p.read_text());print(json.dumps({'generation':m['generation'],'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'units':m.get('unites_autorisees',[])}))")
    policy={'generation':manifest['generation'],'manifest_sha256':manifest['sha256'],'unites_connues':manifest['units'],
            'reseau_hors_baseline_autorise':False,'actions_automatiques':[]}
    context='Essai autorisé sur compte fictif. La règle locale a bloqué les trois sources sur 8082 et les exclusions ont expiré ; ce ne sont PAS des actions SAWM. SSH et témoin sont préservés. Analyser et ouvrir un dossier si utile, sans nouvelle action restrictive. La corrélation ne prouve pas une identité commune ; pas de pays pour ces IP privées. Ne pas attribuer les succès locaux au modèle.'
    try:
        d,trace=decision_cloud(pont,facts,run,['labo-auth-guard.service'],context=context,politique_locale=policy)
        prop=d.proposition
        ok=d.executable and prop.action in ('ouvrir-dossier','ne-rien-faire','demander-clarification')
        report['cloud']={'status':'passed' if ok else 'failed','decision_id':d.decision_id,
            'action':prop.action if prop else None,'reason':prop.justification if prop else d.refus,
            'unknowns':list(prop.inconnues) if prop else [],'recall_count':trace['preuves_utilisees'],
            'odvl_available':odvl_applied(trace['odvl']),'calls':len(pont.journal_appels),
            'latency_ms':trace['timings_ms']['total']}
        save(detail_path,{'trace':trace,'calls':list(pont.journal_appels)})
    except Exception as exc:
        report['cloud']={'status':'failed','error':type(exc).__name__,'calls':len(pont.journal_appels)}
        last=next((c for c in reversed(pont.journal_appels) if c.get('resultat')=='http_error'),None)
        if last:
            report['cloud']['reason']=str(last.get('appel'))+' : HTTP '+str(last.get('statut'))+' ('+str(last.get('code') or 'erreur')+'). Aucun choix SAWM obtenu.'
        save(detail_path,{'error':report['cloud'],'calls':list(pont.journal_appels)})
    finally:pont.close()
    report['updated_at']=now();save(REPORT,report)
    print(json.dumps(report['cloud'],ensure_ascii=False),flush=True)

def odvl_applied(receipt):
    # Le reçu public odvl:rank ne porte pas le champ `available` de la route
    # odvl:observe. Un champ absent ne doit pas masquer un classement exécuté.
    return (isinstance(receipt,dict)
            and receipt.get('schema')=='basira-odvl-ranking/v1'
            and receipt.get('ranking_applied') is True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');parser.add_argument('--cloud',action='store_true');args=parser.parse_args()
    if args.cloud:return analyse_cloud()
    if not args.run:parser.error('--run requis pour le test borne sur la VM configuree')
    for name,value in [('SAWM_LABO_AUTH_TEST_HOST',HOST),('SAWM_LABO_AUTH_TEST_SOURCE',CONTROLLER_IP)]:
        try: address=ipaddress.ip_address(value)
        except ValueError:parser.error(name+' must be an explicit private IPv4 lab address')
        if address.version!=4 or not address.is_private or address.is_unspecified or address.is_loopback:parser.error(name+' must be a private non-loopback IPv4 lab address')
    tick=int(time.time()*1000);start=time.monotonic();password=secrets.token_urlsafe(32);ownership=secrets.token_hex(16)
    # Conserver chaque tentative, y compris les erreurs de provisionnement.
    for previous in (REPORT,DETAIL):
        if previous.exists():
            archived=previous.with_name(previous.stem+'-avant-'+str(tick)+previous.suffix)
            archived.write_bytes(previous.read_bytes())
    report={'schema':'sawm-external-auth-validation/v1','status':'running','updated_at':now(),
      'scope':'Mac externe à la VM sur réseau privé, service fictif 8082 ; rotation de sources via deux namespaces privés. Ni SSH, ni Internet public, ni compte client.',
      'cases':[],'events':[],'correlations':[],'geography':[],
      'limits':['L’exclusion est exécutée par une règle locale, pas par SAWM.',
        'Une corrélation multi-IP est une hypothèse, pas une identité.',
        'Adresses privées : aucune géolocalisation ; couverture Internet public non testée.',
        'Protection limitée au service fictif 8082 ; aucun test de SSH ni garantie antivirus.',
        'Les exclusions expirent après 60 s. Les compteurs applicatifs ne persistent pas après redémarrage.'],
      'cloud':{'status':'not_run'}}
    proof={'schema':'sawm-external-auth-proof/v1','started_at':now(),'scope':report['scope'],'samples':[]}
    def case(id,title,ip,checks,measurements):
        report['cases'].append({'id':id,'title':title,'status':'passed' if all(checks.values()) else 'failed','source_ip':ip,'checks':checks,'measurements':measurements})
        report['updated_at']=now();save(REPORT,report)
        print(json.dumps({'case':id,'status':report['cases'][-1]['status']},ensure_ascii=False),flush=True)
    save(REPORT,report)
    try:
        proof['provision']=provision(password,ownership)
        for _ in range(50):
            h=request()
            if h['status']==200:break
            time.sleep(.3)
        proof['initial_health']=h
        if h['status']!=200:raise RuntimeError('service_not_ready')
        w0=witness();initial=request(password)
        case('legitime','Accès autorisé avant les essais',CONTROLLER_IP,{'login_200':initial['status']==200,'witness_200':w0['http']==200},initial)
        before=kernel();attempts=[request('erreur-fictive-'+str(i)) for i in range(5)];after=kernel();denied=request();kernel_drop=kernel()
        good_other=request(password,namespace=NS[0][0]);w1=witness()
        case('mac-exterieur','Mots de passe incorrects depuis le Mac',CONTROLLER_IP,{
            'four_401':all(x['status']==401 for x in attempts[:4]),'fifth_429':attempts[4]['status']==429,
            'kernel_source_present':ban_present(after,CONTROLLER_IP),'connection_blocked':denied['status'] is None,
            'drop_counter_increased':packets(kernel_drop)>packets(after),
            'other_source_authorized':good_other['status']==200,'witness_200':w1['http']==200,
            'ssh_preserved':w1['ssh_access']}, {'attempt_statuses':[x['status'] for x in attempts],
            'attempt_total_ms':round(sum(x['duration_ms'] for x in attempts),3),'blocked_request':denied,
            'dropped_packets':packets(kernel_drop)-packets(after),'legitimate_other_source':good_other['status']})
        proof['samples'].append({'before':before,'ban':after,'after_probe':kernel_drop,'witness':w1})
        for name,_,_,_,ip in NS:
            rows=[request('incorrect-isole-'+str(i),namespace=name,xff='203.0.113.99') for i in range(5)]
            state=kernel();probe=request(namespace=name)
            case('rotation-'+name,'Nouvelle source : seuil propre puis exclusion',ip,{
                'not_preblocked':rows[0]['status']==401,'fifth_429':rows[4]['status']==429,
                'peer_ip_banned':ban_present(state,ip),'xff_not_banned':not ban_present(state,'203.0.113.99'),
                'connection_blocked':probe['status'] is None}, {'attempt_statuses':[r['status'] for r in rows],'probe':probe,'forwarded_header_ignored':True})
            proof['samples'].append({'source_ip':ip,'nft':state})
        # Observe real expiry, no manual deletion. Each sleep remains short.
        deadline=time.monotonic()+72
        while time.monotonic()<deadline:
            if not any(ban_present(kernel(),ip) for ip in [CONTROLLER_IP,NS[0][4],NS[1][4]]):break
            time.sleep(3)
        final=request(password);w2=witness();state=kernel()
        case('expiration','Fin automatique des exclusions et accès rétabli',CONTROLLER_IP,{
            'login_200':final['status']==200,'expired_all':not any(ban_present(state,ip) for ip in [CONTROLLER_IP,NS[0][4],NS[1][4]]),
            'witness_200':w2['http']==200,'sensors_active':w2['protection_services']==['active']*3}, {'login':final,'elapsed_s':round(time.monotonic()-start,3),'witness':w2})
        proof['events_raw']=vm.json_code("import pathlib,json\np=pathlib.Path('/opt/sawm-labo/auth-guard/events.jsonl')\nrows=[json.loads(x) for x in p.read_text().splitlines()[-500:]]\nprint(json.dumps(rows))")
        proof['events_raw']=[e for e in proof['events_raw'] if e.get('observed_ms',0)>=tick]
        failed_ips=sorted({e['source_ip'] for e in proof['events_raw'] if e['outcome'] in ('rejected','temporarily_blocked')})
        for e in proof['events_raw']:
            receipt=e.get('block_receipt') or {};blocked=e['outcome']=='temporarily_blocked'
            report['events'].append({'timestamp_ms':e['observed_ms'],'source_ip':e['source_ip'],
                'event':e['outcome'],'username':e['username_label'],
                'reason':receipt.get('reason') or ('Identifiant valide' if e['outcome']=='authenticated' else 'Authentification refusée'),
                'ban_until_ms':e['observed_ms']+60000 if blocked else None,
                'applied_by':'local_policy' if blocked else 'none'})
        if any(e['campaign_hint']['possible'] for e in proof['events_raw']):
            report['correlations']=[{'source_ips':failed_ips,'reason':'Échecs sur le compte fictif demo-cto et le même service dans une fenêtre de 120 s.',
              'confidence_label':'hypothese_non_confirmee','same_actor_confirmed':False}]
        report['geography']=[{'source_ip':ip,'status':'private_address' if ipaddress.ip_address(ip).is_private else 'unknown','country':None,'source':None} for ip in failed_ips]
        case('correlation','Campagne possible signalée sans attribuer une identité',None,{
            'three_sources':len(failed_ips)==3,'hypothesis_present':bool(report['correlations']),
            'no_identity_claim':all(not c['same_actor_confirmed'] for c in report['correlations']),
            'no_forged_source':all(e['source_ip']!='203.0.113.99' for e in report['events'])},
            {'observations':len(report['events']),'source_ips':failed_ips,'geography':'private_addresses_only'})
        proof['ended_at']=now()
        report['status']='passed' if all(c['status']=='passed' for c in report['cases']) else 'failed'
    except Exception as exc:
        report['status']='failed';proof['error']=type(exc).__name__
        if str(exc)=='service_not_ready':proof['error']='service_not_ready'
        print(json.dumps({'status':'failed','error':type(exc).__name__}),flush=True)
    finally:
        try:proof['cleanup']=cleanup(ownership)
        except Exception as exc:
            proof['cleanup']={'error':type(exc).__name__};report['status']='failed'
        report['updated_at']=now();save(DETAIL,proof);save(REPORT,report)
    print(json.dumps({'status':report['status'],'cases':len(report['cases']),'report':str(REPORT)}),flush=True)

if __name__=='__main__':main()
