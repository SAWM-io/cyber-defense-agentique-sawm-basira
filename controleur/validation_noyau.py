"""Preuve locale de refus LSM, réversible, indépendante de SAWM Cloud."""
from controleur import vm_labo as vm
from controleur.validation import REPORTS,save,now,post
import json,time

def main():
 run='noyau-'+time.strftime('%Y%m%dT%H%M%S');out={'run_id':run,'type':'noyau','debut':now(),'origine_actions':'politique locale du test; aucune decision SAWM'}
 script=r'''import pathlib,os,subprocess,struct,json,errno
p=pathlib.Path('/opt/sawm-labo/fixtures/controle-lecture.fixture');p.write_bytes(b'Exclusivement une fixture de laboratoire.');p.chmod(0o644)
st=p.stat();key=[f'{b:02x}' for b in struct.pack('<Q',st.st_ino)];table='/sys/fs/bpf/sawm/inodes_refusees'
r={'inode':st.st_ino,'dev':st.st_dev,'avant':p.read_bytes() is not None}
def bp(args):
 x=subprocess.run(['bpftool','map',*args],capture_output=True,text=True)
 if x.returncode:raise RuntimeError(x.stderr[:160])
uidkey=[f'{b:02x}' for b in struct.pack('<I',1000)];uidtable='/sys/fs/bpf/sawm/uids_temoins'
old=subprocess.run(['bpftool','-j','map','lookup','pinned',uidtable,'key','hex',*uidkey],capture_output=True,text=True)
previous=json.loads(old.stdout).get('value') if old.returncode==0 else None
try:
 bp(['update','pinned',uidtable,'key','hex',*uidkey,'value','hex','01',*['00']*7])
 bp(['update','pinned',table,'key','hex',*key,'value','hex',*['00']*8])
 try:p.read_bytes();r['errno_root']=None
 except OSError as e:r['errno_root']=e.errno
 test=subprocess.run(['/usr/bin/python3','-c',"import os;os.setuid(1000);open('/opt/sawm-labo/fixtures/controle-lecture.fixture').read()"],capture_output=True,text=True)
 r['lecture_uid1000_autorisee']=test.returncode==0
 r['autre_fixture_autorisee']=pathlib.Path('/opt/sawm-labo/fixtures/document-1.txt').read_bytes() is not None
finally:
 bp(['delete','pinned',table,'key','hex',*key])
 if previous is None:bp(['delete','pinned',uidtable,'key','hex',*uidkey])
 else:bp(['update','pinned',uidtable,'key','hex',*uidkey,'value','hex',*[f'{int(v,0) if isinstance(v,str) else v:02x}' for v in previous]])
 r['apres_retrait']=p.read_bytes() is not None
 p.unlink()
r['succes']=r['errno_root']==errno.EPERM and r['lecture_uid1000_autorisee'] and r['autre_fixture_autorisee'] and r['apres_retrait']
print(json.dumps(r))'''
 try:
  out['mesures']=vm.json_code(script);out['succes_mesure']=out['mesures']['succes'];out['temoin']=vm.snapshot()['temoin']
 except Exception as e:out['erreur']=str(e);out['succes_mesure']=False
 out['fin']=now();path=REPORTS/('experience-'+run+'.json');save(path,out)
 post('/api/marqueur',{'phase':'validation','texte':'Refus LSM local vérifié; origine locale, non SAWM','run_id':run,'preuves':['releves/rapports/'+path.name]})
 print(json.dumps(out,ensure_ascii=False))
if __name__=='__main__':main()
