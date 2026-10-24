"""Ancre le bilan final (nettoyage inclus) dans Basira après fermeture des essais."""
import hashlib,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from controleur.audit_signe import JournalSigne
from controleur.validation import save,now
from connecteur.pont_memoire import PontMemoire
R=ROOT/'releves/rapports'

def main():
    files=['campagne-defense-20260923.json','synthese-defense-20260923.json','tests-defense-20260923.json']
    hashes={f:hashlib.sha256((R/f).read_bytes()).hexdigest() for f in files}
    j=JournalSigne(R/'audit-defense-final-20260923.jsonl')
    record={'genre':'cloture_campagne','created_at':now(),'file_sha256':hashes,
            'scope':'Empreintes des bilans complets, incluant nettoyages opérateur ; journaux par essai conservés séparément.'}
    anchor=j.append(record)
    pont=PontMemoire(campagne='defense-final-20260923')
    receipt=pont.deposer([{'id':'bilan-final-'+anchor['sha256'][:24],'titre':'Bilan final défense VM 23 septembre 2026',
      'contenu':json.dumps({'bilan':record,'ancre_signee':anchor},ensure_ascii=False)}],budget_s=60)
    save(R/'ancrage-defense-final-20260923.json',{'created_at':now(),'file_sha256':hashes,
       'signature':anchor,'verified':j.verify(),'cloud_completed':all(x['statut']=='completed' for x in receipt['jobs']),
       'cloud_jobs':receipt['jobs']})
    print(json.dumps({'cloud_completed':all(x['statut']=='completed' for x in receipt['jobs']),'signed_digest':anchor['sha256']}))
if __name__=='__main__':main()
