#!/usr/bin/env python3
"""Epreuve de reprise systemd : battements benins, Cloud public, garde locale.

Execution explicite seulement. Ce script ne prouve aucune immunite contre root :
le proprietaire peut retirer la garde. SIGKILL et la tentative de start sont des
injections de test operees par le controleur, jamais attribuees a SAWM.
"""
from __future__ import annotations

import argparse
import os
import json
import pathlib
import re
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controleur import vm_labo as vm
from controleur.validation import decision_cloud, describe, execute, now, post, save
from connecteur.pont_memoire import PontMemoire

UNITE = 'labo-repetition.service'
SOURCE = 'repetition'
GARDE = '/run/sawm-labo/gardes/' + UNITE + '.stop'
DROPIN = '/run/systemd/system/' + UNITE + '.d/90-sawm-lab-stop.conf'
PROTEGEES = ['labo-copie-a.service', 'labo-temoin.service', 'labo-recepteur.service',
             'labo-telemetrie.service', 'labo-lsm.service', 'labo-capteur-exec.service']


def provision_source(run):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', run):
        raise ValueError('identifiant de campagne invalide')
    manifest = {'generation': run, 'run_id': run,'operation_id':os.environ.get('SAWM_OPERATEUR_ID'), 'actif': True,
        'unites_autorisees': [UNITE], 'unites_protegees': PROTEGEES,
        'tranches_autorisees': ['sawm-charge.slice'], 'fenetre_verification_s': 1,
        'actions_autorisees': ['arreter-service', 'ne-rien-faire', 'ouvrir-dossier',
                               'demander-clarification'],
        'identites_unites': {UNITE: {'Slice': 'sawm-charge.slice',
            'FragmentPath': '/etc/systemd/system/' + UNITE}}}
    return '''import fcntl,hashlib,json,os,pathlib,subprocess,tempfile,time
unit=UNIT_DATA
m=MANIFEST_DATA
root=pathlib.Path('/opt/sawm-labo')
fd=os.open(root/'.executeur.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
fcntl.flock(fd,fcntl.LOCK_EX)
def command(*args,allowed=(0,)):
 p=subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,text=True,timeout=20)
 if p.returncode not in allowed:raise RuntimeError('systemctl '+args[0]+' refuse')
 return p
def write(path,data,mode):
 handle,tmp=tempfile.mkstemp(prefix='.sawm-reprise-',dir=path.parent)
 try:
  with os.fdopen(handle,'wb') as out:
   os.fchmod(out.fileno(),mode);out.write(data);out.flush();os.fsync(out.fileno())
  os.replace(tmp,path)
 finally:pathlib.Path(tmp).unlink(missing_ok=True)
if not (root/'charges_test/tache.py').is_file():raise RuntimeError('tache de laboratoire absente')
command('stop','--',unit,allowed=(0,5))
# Retrait des seules gardes de CETTE unite pour une nouvelle generation.
(pathlib.Path('/run/sawm-labo/gardes')/(unit+'.stop')).unlink(missing_ok=True)
(pathlib.Path('/run/systemd/system')/(unit+'.d')/'90-sawm-lab-stop.conf').unlink(missing_ok=True)
deadline=time.time()+300
text=('[Unit]\\nDescription=Battements benins du laboratoire\\nStartLimitIntervalSec=0\\n'
 '[Service]\\nType=simple\\nSlice=sawm-charge.slice\\n'
 'ExecStart=/usr/bin/python3 /opt/sawm-labo/charges_test/tache.py --source-id repetition '
 '--run-id '+m['run_id']+' --duration 300 --deadline-epoch '+str(deadline)+' --interval 0.25\\n'
 'Restart=always\\nRestartSec=0.25\\nRestartPreventExitStatus=78\\nSuccessExitStatus=78\\n'
 'KillMode=control-group\\nRuntimeMaxSec=300\\nTimeoutStopSec=3\\nMemoryMax=64M\\nCPUQuota=20%\\n')
path=pathlib.Path('/etc/systemd/system')/unit
if path.is_symlink() and os.readlink(path)!='/dev/null':raise RuntimeError('unite symbolique inattendue')
write(path,text.encode(),0o644)
raw=json.dumps(m,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
write(root/'manifeste.json',raw,0o600)
command('daemon-reload')
command('reset-failed','--',unit,allowed=(0,1))
print(json.dumps({'generation':m['generation'],'manifest_sha256':hashlib.sha256(raw).hexdigest(),
 'unite':unit,'deadline_epoch':deadline,'unite_sha256':hashlib.sha256(text.encode()).hexdigest()}))
os.close(fd)
'''.replace('UNIT_DATA', repr(UNITE)).replace('MANIFEST_DATA', repr(manifest))


def provisionner(run):
    return vm.json_code(provision_source(run), timeout=60)


def observer(run):
    """Etat systemd et battements frais, releves depuis le controleur."""
    source = '''import json,pathlib,subprocess,time,urllib.request
def unit(name):
 p=subprocess.run(['/usr/bin/systemctl','show','--property=Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Restart,Slice,ControlGroup,DropInPaths,ConditionResult','--',name],capture_output=True,text=True,timeout=5)
 if p.returncode:raise RuntimeError('lecture systemd impossible')
 return dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
out={'guest_epoch':time.time(),'unite':unit(UNIT_DATA),'protegee_a':unit('labo-copie-a.service')}
try:
 with urllib.request.urlopen('http://127.0.0.1:8080/document',timeout=2) as response:
  out['temoin']={'code':response.status}
except Exception as exc:out['temoin']={'code':None,'erreur':type(exc).__name__}
out['charge']=None
p=pathlib.Path('/opt/sawm-labo/charges-etat/repetition.json')
if p.exists():
 data=json.loads(p.read_text())
 if data.get('run_id')==RUN_DATA:out['charge']=data
p=pathlib.Path(GARDE_DATA)
out['garde']=json.loads(p.read_text()) if p.exists() else None
print(json.dumps(out))'''
    return vm.json_code(source.replace('UNIT_DATA', repr(UNITE))
                       .replace('RUN_DATA', repr(run)).replace('GARDE_DATA', repr(GARDE)))


def commande(*args):
    rows = vm.commands([['systemctl', *args, '--', UNITE]])
    return rows[0]


def attendre(run, predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        state = observer(run)
        if predicate(state):
            return state
        if time.monotonic() >= deadline:
            raise TimeoutError('etat attendu de l unite non observe')
        time.sleep(0.25)


def entier(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return -1


def actif(state):
    unit, charge = state['unite'], state.get('charge') or {}
    return (unit.get('ActiveState') == 'active' and entier(unit.get('MainPID')) > 0
            and charge.get('termine') is False and entier(charge.get('battements')) >= 2
            and entier(charge.get('pid')) == entier(unit.get('MainPID')))


def relance(before, after):
    a, b = before['unite'], after['unite']
    return (actif(after) and b.get('MainPID') != a.get('MainPID')
            and bool(b.get('InvocationID')) and b.get('InvocationID') != a.get('InvocationID')
            and entier(a.get('NRestarts')) >= 0
            and entier(b.get('NRestarts')) > entier(a.get('NRestarts')))


def mesurer(before, restarted, window, after_start, receipt, decision, deadline):
    states = [before, restarted, *window, after_start]
    stopped = all(s['unite'].get('ActiveState') in {'inactive', 'failed'}
                  and s['unite'].get('MainPID') == '0' for s in [*window, after_start])
    guard = after_start.get('garde') or {}
    guarded = (guard.get('decision_id') == decision.decision_id
               and after_start['unite'].get('ConditionResult') in {'no', 'false'}
               and after_start['unite'].get('Restart') == 'no'
               and DROPIN in after_start['unite'].get('DropInPaths', '').split())
    protected = before['protegee_a']
    preserved = all(all(s['protegee_a'].get(k) == protected.get(k)
                        for k in ('ActiveState', 'MainPID', 'InvocationID')) for s in states)
    measures = {'relance_apres_kill_operateur': relance(before, restarted),
        'fenetre_cinq_secondes_observee': len(window) >= 2 and window[-1]['guest_epoch'] - window[0]['guest_epoch'] >= 5,
        'arret_pendant_fenetre_et_apres_start': stopped,
        'garde_verifiee_sur_start_operateur': guarded,
        'temoin_toujours_200': all(s.get('temoin', {}).get('code') == 200 for s in states),
        'unite_a_preservee': preserved,
        'verification_avant_echeance_naturelle': all(s['guest_epoch'] < deadline for s in states),
        'action_sawm_arreter_service': bool(decision.proposition
            and decision.proposition.action == 'arreter-service' and decision.proposition.cible == UNITE),
        'recu_executeur_verifie': receipt.get('applique') is True and receipt.get('effet_verifie') is True,
        'nrestarts_avant_kill': entier(before['unite'].get('NRestarts')),
        'nrestarts_apres_kill': entier(restarted['unite'].get('NRestarts'))}
    success = all(value for key, value in measures.items() if not key.startswith('nrestarts_'))
    return measures, success


def reprise():
    run = 'reprise-' + time.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:4]
    path = ROOT / 'releves/rapports' / ('experience-' + run + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'sawm-vm-reprise/v1', 'run_id': run, 'debut': now(),
        'type': 'redemarrage_systemd', 'unite': UNITE, 'etapes': [], 'succes_mesure': False,
        'limite': 'Garde systemd du laboratoire, retirable par le proprietaire root; aucune immunite contre root.',
        'attribution': 'SIGKILL et tentative start sont des injections operateur; la garde est posee par l executeur sur proposition SAWM.'}
    pont = None
    configured = False

    def checkpoint(phase, data):
        report['etapes'].append({'phase': phase, 'donnees': data})
        save(path, report)

    try:
        provisioning = provisionner(run)
        configured = True
        report['provisionnement'] = provisioning
        described = describe()
        if (described.get('generation') != run
                or described.get('manifest_sha256') != provisioning['manifest_sha256']):
            raise RuntimeError('generation ou SHA du manifeste non conforme')
        report['manifeste_verifie'] = described
        post('/api/incident', {'id': run, 'titre': 'Activite qui redemarre apres un arret de processus',
            'statut': 'ouvert', 'run_id': run, 'faits': ['Tache benigne de battements, unite dediee.']})
        start = commande('start')
        checkpoint('start_operateur', start)
        if start['code'] != 0:
            raise RuntimeError('demarrage initial refuse')
        before = attendre(run, actif)
        checkpoint('avant_kill_main', before)
        killed = commande('kill', '--kill-who=main', '--signal=SIGKILL')
        checkpoint('sigkill_main_operateur', killed)
        if killed['code'] != 0:
            raise RuntimeError('injection SIGKILL main refusee')
        restarted = attendre(run, lambda state: relance(before, state))
        checkpoint('relance_constatee', restarted)
        pont = PontMemoire(campagne=run)
        facts = [{'unite': UNITE, 'etat_avant': before['unite'], 'etat_apres': restarted['unite'],
                  'mesure_avant_epoch': before['guest_epoch'], 'mesure_apres_epoch': restarted['guest_epoch'],
                  'battements_apres': restarted['charge'],
                  'arret_main_par_operateur': {'signal': 'SIGKILL', 'code_commande': killed['code']}},
                 {'service_documentaire': restarted['temoin'], 'unite_a_protegee': restarted['protegee_a']}]
        context = ('Le proprietaire interdit desormais les battements de labo-repetition.service '
            'et autorise son arret durable dans cette generation de laboratoire. Une simple mort du '
            'processus principal ne met pas fin a cette activite, selon les observations jointes. '
            'Preserver labo-copie-a.service, le temoin et le recepteur. Il s agit d une tache benigne '
            'de test; ne pas la qualifier de logiciel malveillant. La decision de mandat est declaree '
            'par le proprietaire, pas deduite d une mesure OS.')
        decision, trace = decision_cloud(pont, facts, run, [UNITE], context)
        report['analyse'] = trace
        checkpoint('proposition_cloud', decision.resume())
        receipt = execute(decision, run)
        report['recu'] = receipt
        checkpoint('application_executeur', receipt)
        window = [observer(run)]
        for _ in range(5):
            time.sleep(1)
            window.append(observer(run))
        checkpoint('fenetre_cinq_secondes', window)
        restart_attempt = commande('start')
        checkpoint('tentative_start_operateur', restart_attempt)
        time.sleep(0.5)
        after_start = observer(run)
        checkpoint('apres_tentative_start', after_start)
        measures, success = mesurer(before, restarted, window, after_start, receipt,
                                     decision, provisioning['deadline_epoch'])
        report['mesures'], report['succes_physique'], report['succes_mesure'] = measures, success, success
        report['retour_memoire'] = pont.deposer([{'id': 'retour-' + run,
            'titre': 'Retour mesure apres arret et tentative de relance', 'survenu_a': now(),
            'contenu': json.dumps({'decision_id': decision.decision_id, 'mesures': measures,
                'recu': receipt, 'succes_mesure': success, 'limite': report['limite']}, ensure_ascii=False)}])
        post('/api/decision', {'id': decision.decision_id, 'incident_id': run, 'run_id': run,
            'action': decision.resume()['action'] or 'refus', 'statut': 'verifiee' if success else 'a_revoir',
            'raison_publique': 'Mesures independantes de relance, arret, garde et disponibilite.',
            'origine': 'SAWM Cloud', 'preuves': ['releves/rapports/' + path.name]})
        post('/api/incident', {'id': run, 'run_id': run, 'titre': 'Activite qui redemarre',
            'statut': 'resolu' if success else 'a_revoir', 'faits': [json.dumps(measures)],
            'preuves': ['releves/rapports/' + path.name]})
    except Exception as exc:
        report['erreur'] = {'type': type(exc).__name__}
        report['succes_mesure'] = False
    finally:
        if configured:
            try:
                report['nettoyage_operateur'] = commande('stop')
            except Exception as exc:
                report['nettoyage_operateur'] = {'erreur': type(exc).__name__}
        if pont is not None:
            pont.close()
        report['fin'] = now()
        save(path, report)
    print(json.dumps({'rapport': str(path), 'succes_mesure': report['succes_mesure'],
                      'mesures': report.get('mesures'), 'erreur': report.get('erreur')}, ensure_ascii=False))
    return report


def main():
    import signal
    def interrompre(*_):raise KeyboardInterrupt('arrêt opérateur')
    signal.signal(signal.SIGTERM,interrompre)
    argparse.ArgumentParser(description=__doc__).parse_args()
    return 0 if reprise()['succes_mesure'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
