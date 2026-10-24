"""Accès au SEUL invité de laboratoire, avec clé dédiée hors dépôt."""
from __future__ import annotations
import base64,json,os,pathlib,re,stat,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
RACINE_INVITE=pathlib.Path('/opt/sawm-labo')
# SSH target must be configured explicitly; no private laboratory host is built in.
# known_hosts propre au HOME de l'instance, pour ne pas mélanger les empreintes hôtes du labo et de la nouvelle VM.
_CIBLE_SSH = os.environ.get("SAWM_LABO_SSH_CIBLE", "").strip()
SSH=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=8",
     "-o","ServerAliveInterval=5","-o","ServerAliveCountMax=2",
     "-o","ControlMaster=no",
     "-o","StrictHostKeyChecking=yes",
     "-o",f"UserKnownHostsFile={pathlib.Path.home()}/.sawm-labo/known_hosts",
     "-o",f"ControlPath={pathlib.Path.home()}/.sawm-labo/ssh-control",
     "-i",str(pathlib.Path.home()/".sawm-labo/cle_labo"),_CIBLE_SSH]

def local_vm():
    """Aucune détection implicite : le transport SSH historique reste le défaut."""
    return os.environ.get('SAWM_LABO_LOCAL_VM') == '1'

def verifier_vm_locale():
    """Refuse un hôte ordinaire : Linux root et installation labo déjà présente."""
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise RuntimeError('mode VM locale réservé à root dans le Linux du laboratoire')
    if RACINE_INVITE.resolve() != RACINE_INVITE:
        raise RuntimeError('racine du laboratoire symbolique')
    for path, directory in ((RACINE_INVITE, True), (RACINE_INVITE/'manifeste.json', False)):
        try:
            st=path.lstat()
        except OSError:
            raise RuntimeError('installation du laboratoire local absente') from None
        regular=stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
        if not regular or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('installation du laboratoire local non fiable')

def code(source,timeout=35):
    if local_vm():
        verifier_vm_locale()
        commande=[sys.executable, '-']
    else:
        if not _CIBLE_SSH or not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9][A-Za-z0-9_.:-]*", _CIBLE_SSH):
            raise RuntimeError("SAWM_LABO_SSH_CIBLE must explicitly name user@host; enroll its host key first")
        commande=SSH+["sudo -n python3 -"]
    p=subprocess.run(commande,input=source,text=True,
                     capture_output=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"invité: code {p.returncode}: {p.stderr[-400:]}")
    return p.stdout

def json_code(source,timeout=35):
    return json.loads(code(source,timeout))

def push(local,remote):
    if not remote.startswith(("/opt/sawm-labo/","/etc/systemd/system/labo-")):
        raise ValueError("destination hors laboratoire")
    raw=base64.b64encode(pathlib.Path(local).read_bytes()).decode()
    code(f"import pathlib,base64\np=pathlib.Path({remote!r})\np.parent.mkdir(parents=True,exist_ok=True)\np.write_bytes(base64.b64decode({raw!r}))\np.chmod(0o644)\n")

def commands(commands):
    """Commandes de provisionnement écrites par le développeur, jamais un LLM."""
    return json_code("import subprocess,json\na="+repr(commands)+"\no=[]\nfor c in a:\n p=subprocess.run(c,capture_output=True,text=True,timeout=20);o.append({'cmd':c,'code':p.returncode,'out':p.stdout,'err':p.stderr})\nprint(json.dumps(o))")

def snapshot():
    return json_code('''import json,pathlib,subprocess,urllib.request,time
out={'mur_epoch_ms':int(time.time()*1000)}
try:out['recepteur']=json.loads(pathlib.Path('/run/recepteur_labo.json').read_text())
except Exception:out['recepteur']=None
try:
 t=time.monotonic()
 import sys
 sys.path.insert(0,'/opt/sawm-labo/agent')
 from jetons import emettre
 requete=urllib.request.Request('http://127.0.0.1:8080/document',headers={'X-Labo-Jeton':emettre()})
 with urllib.request.urlopen(requete,timeout=2) as r:out['temoin']={'code':r.status,'body':json.load(r),'ms':(time.monotonic()-t)*1000}
except Exception as e:out['temoin']={'code':None,'erreur':type(e).__name__}
out['charges']={}
for p in pathlib.Path('/opt/sawm-labo/charges-etat').glob('*.json'):
 try:out['charges'][p.stem]=json.loads(p.read_text())
 except Exception:pass
out['sockets']=subprocess.run(['ss','-Htnp'],capture_output=True,text=True).stdout[:6000]
out['exec_recents']=pathlib.Path('/var/log/capteur_exec.jsonl').read_text().splitlines()[-25:]
print(json.dumps(out))''')
