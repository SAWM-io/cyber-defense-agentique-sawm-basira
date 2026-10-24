cd /opt/sawm-labo
INO42=$(stat -c %i fixtures/dossier-client-42.txt)
INO43=$(stat -c %i fixtures/dossier-client-43.txt)
echo "fixture visee  : fixtures/dossier-client-42.txt  inode=$INO42"
echo "fixture temoin : fixtures/dossier-client-43.txt  inode=$INO43"
echo
echo "=========== ETAT A : politique attachee, tables VIDES ==========="
printf "  lecture par root                 : "; cat fixtures/dossier-client-42.txt >/dev/null 2>&1 && echo AUTORISEE || echo REFUSEE
echo "  (une politique vide ne refuse rien : c'est le garde-fou)"
echo
echo "=========== ETAT B : l'executeur inscrit l'inode ==========="
python3 - "$INO42" <<'PY'
import struct, subprocess, sys
ino = int(sys.argv[1])
def h(v, n=8): return [f"{b:02x}" for b in struct.pack("<Q", v)[:n]]
def maj(t, cle, val, nc=8):
    r = subprocess.run(["bpftool","map","update","pinned",f"/sys/fs/bpf/sawm/{t}",
                        "key","hex",*h(cle,nc),"value","hex",*h(val)],
                       capture_output=True, text=True)
    print(f"  {t:<24} <- cle={cle}  {'ok' if r.returncode==0 else 'ECHEC '+r.stderr.strip()[:80]}")
maj("inodes_refusees", ino, 0xDEC15102026)
maj("uids_temoins", 1000, 1, nc=4)
PY
echo
echo "=========== ETAT C : le noyau refuse-t-il REELLEMENT ? ==========="
printf "  lecture par root (uid 0)         : "
cat fixtures/dossier-client-42.txt >/dev/null 2>&1 && echo "AUTORISEE  <- echec du test" || echo "REFUSEE PAR LE NOYAU"
echo -n "  erreur rendue a l'appelant       : "; cat fixtures/dossier-client-42.txt 2>&1 | head -1
echo -n "  errno vu par open(2)             : "; python3 -c "
try:
    open('fixtures/dossier-client-42.txt').read()
    print('aucune erreur')
except OSError as e:
    import errno; print(f'{errno.errorcode[e.errno]} ({e.errno}) - {e.strerror}')"
printf "  lecture par vagrant (temoin)     : "
sudo -u vagrant cat fixtures/dossier-client-42.txt >/dev/null 2>&1 && echo "AUTORISEE  <- refus CIBLE, prouve" || echo "REFUSEE  <- le temoin ne devrait pas l'etre"
printf "  autre fixture, hors politique    : "
cat fixtures/dossier-client-43.txt >/dev/null 2>&1 && echo "AUTORISEE  <- pas de blocage general" || echo "REFUSEE  <- blocage trop large"
printf "  meme fichier par un autre chemin : "
cat /opt/sawm-labo/./fixtures/../fixtures/dossier-client-42.txt >/dev/null 2>&1 && echo "AUTORISEE  <- contournable par chemin" || echo "REFUSEE  <- la regle porte sur l'INODE, pas le chemin"
echo
echo "=========== COMPTEURS DU NOYAU ==========="
echo "  0=refus ouverture  1=exemptions temoin  2=refus execution  3=ouvertures vues"
bpftool map dump pinned /sys/fs/bpf/sawm/compteurs 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for e in d: print('   cle',e.get('key'),'->',e.get('value'))
except Exception:
    sys.stdin.seek(0) if hasattr(sys.stdin,'seek') else None" 2>/dev/null || bpftool map dump pinned /sys/fs/bpf/sawm/compteurs
echo
echo "=========== ETAT D : retrait de la politique ==========="
rm -f /sys/fs/bpf/sawm/refus_ouverture /sys/fs/bpf/sawm/refus_execution
sleep 1
printf "  lecture par root apres retrait   : "
cat fixtures/dossier-client-42.txt >/dev/null 2>&1 && echo "AUTORISEE  <- reversible, prouve" || echo "ENCORE REFUSEE"
