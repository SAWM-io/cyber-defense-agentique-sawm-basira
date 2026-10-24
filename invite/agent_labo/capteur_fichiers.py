"""Événements inotify réels, limités aux fixtures du laboratoire.

Les noms sont observés, jamais le contenu. inotify n'attribue pas un PID.
Une saturation ou un répertoire non surveillé reste explicitement signalé.
"""
import collections,ctypes,json,os,pathlib,select,struct,threading,time
BASE=pathlib.Path('/opt/sawm-labo/fixtures')
NOMS={1:'lecture',2:'modification',4:'attributs',8:'fermeture_ecriture',16:'fermeture',32:'ouverture',64:'deplacement_source',128:'deplacement_destination',256:'creation',512:'suppression',1024:'suppression_repertoire',2048:'deplacement_repertoire'}
MASK=sum(NOMS)
class Capteur:
 def __init__(self):
  self.verrou=threading.Lock();self.events=collections.deque(maxlen=80);self.compteurs=collections.Counter();self.pertes=0;self.watches={};self.erreur=None
  self.lib=ctypes.CDLL(None,use_errno=True);self.fd=self.lib.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
  if self.fd<0:raise OSError(ctypes.get_errno(),'inotify_init1')
  self.ajouter(BASE)
  for p in BASE.rglob('*'):
   if p.is_dir() and not p.is_symlink():self.ajouter(p)
 def ajouter(self,p):
  if len(self.watches)>=256:self.erreur='limite_256_repertoires';return
  if p.is_symlink() or not p.resolve().is_relative_to(BASE):return
  wd=self.lib.inotify_add_watch(self.fd,os.fsencode(p),MASK)
  if wd<0:self.erreur='ajout_surveillance_impossible';return
  self.watches[wd]=p
 def lire(self):
  if not select.select([self.fd],[],[],.5)[0]:return
  data=os.read(self.fd,65536);offset=0
  with self.verrou:
   while offset+16<=len(data):
    wd,mask,cookie,n=struct.unpack_from('iIII',data,offset);offset+=16
    nom=data[offset:offset+n].split(b'\0')[0].decode(errors='replace');offset+=n
    if mask&16384:self.pertes+=1;continue
    base=self.watches.get(wd)
    if base is None:continue
    p=base/nom
    if mask&256 and mask&0x40000000:self.ajouter(p)
    actions=[v for k,v in NOMS.items() if mask&k]
    self.compteurs.update(actions)
    self.events.append({'mur_epoch_ms':int(time.time()*1000),'chemin':str(p.relative_to(BASE)),'operations':actions,'cookie':cookie,'pid':None})
    if mask&32768:self.watches.pop(wd,None)
 def boucle(self):
  while True:
   try:self.lire()
   except Exception as e:
    self.erreur=type(e).__name__;time.sleep(1)
 def etat(self):
  with self.verrou:return {'source':'inotify','perimetre':str(BASE),'repertoires':len(self.watches),'compteurs':dict(self.compteurs),'pertes_file':self.pertes,'evenements':list(self.events),'erreur':self.erreur,'attribution_pid':False}
_CAPTEUR=None
_ERREUR=None
def demarrer():
 global _CAPTEUR,_ERREUR
 try:
  _CAPTEUR=Capteur();threading.Thread(target=_CAPTEUR.boucle,daemon=True).start()
 except Exception as e:_ERREUR=type(e).__name__
def etat():return _CAPTEUR.etat() if _CAPTEUR else {'source':'inotify','erreur':_ERREUR or 'non_demarre'}
