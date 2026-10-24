#!/usr/bin/env python3
"""Récepteur local de données fictives : octets effectivement lus, par flux.
Ne retransmet rien. En-tête ANNONCE taille source_id run_id borné à 4096 octets.
Les métriques sont celles de la même VM, pas une attestation contre root.
"""
from __future__ import annotations
import copy,json,os,pathlib,re,signal,socket,socketserver,threading,time
ETAT=pathlib.Path(os.environ.get("LABO_RECEPTEUR_ETAT","/run/recepteur_labo.json"))
ECOUTE=(os.environ.get("LABO_RECEPTEUR_BIND","127.0.0.1"),int(os.environ.get("LABO_RECEPTEUR_PORT","9009")))
verrou=threading.RLock()
compteur={"octets_recus":0,"octets_annonces":0,"connexions":0,"connexions_ouvertes":0,"flux_interrompus":0,"premier_octet_epoch_ms":None,"dernier_octet_epoch_ms":None,"debut_epoch_ms":int(time.time()*1000),"flux":{}}
def publier():
    with verrou:
        tmp=ETAT.with_suffix(".tmp")
        tmp.write_text(json.dumps(compteur))
        tmp.replace(ETAT)
def entete(sock):
    data=b""
    while b"\n" not in data:
        b=sock.recv(1)
        if not b: raise ValueError("entete_incomplete")
        data+=b
        if len(data)>4096:raise ValueError("entete_trop_longue")
    p=data.decode("ascii").strip().split()
    if len(p) not in (2,4) or p[0]!="ANNONCE":raise ValueError("entete_invalide")
    n=int(p[1])
    if not 0<=n<=20*1024**3:raise ValueError("volume_hors_limite")
    source,run=p[2:] if len(p)==4 else ("sans-source","sans-run")
    if any(not re.fullmatch(r"[a-zA-Z0-9._-]{1,100}",v) for v in (source,run)):raise ValueError("identite_invalide")
    return n,source,run
class Flux(socketserver.BaseRequestHandler):
    def handle(self):
        ident=None; total=0; status="erreur"
        self.request.settimeout(10)
        try:
            annonce,source,run=entete(self.request)
            with verrou:
                compteur["connexions"]+=1;compteur["connexions_ouvertes"]+=1
                compteur["octets_annonces"]+=annonce
                ident=f"{run}:{source}:{compteur['connexions']}"
                compteur["flux"][ident]={"source_id":source,"run_id":run,"annonces":annonce,"recus":0,"etat":"en_cours","debut_ms":int(time.time()*1000),"dernier_ms":None,"fin_ms":None}
                # Bounded metadata; completed records are preserved by host sampling.
                if len(compteur["flux"])>256:
                    old=next((k for k,v in compteur["flux"].items() if v["etat"]!="en_cours"),None)
                    if old:del compteur["flux"][old]
            while total<annonce:
                block=self.request.recv(min(65536,annonce-total))
                if not block:break
                total+=len(block);now=int(time.time()*1000)
                with verrou:
                    compteur["octets_recus"]+=len(block)
                    compteur["premier_octet_epoch_ms"]=compteur["premier_octet_epoch_ms"] or now
                    compteur["dernier_octet_epoch_ms"]=now
                    compteur["flux"][ident].update(recus=total,dernier_ms=now)
            status="complet" if total==annonce else "interrompu"
        except (OSError,ValueError,UnicodeError):status="interrompu" if ident else "entete_refusee"
        finally:
            if ident:
                with verrou:
                    compteur["connexions_ouvertes"]-=1
                    if status!="complet":compteur["flux_interrompus"]+=1
                    compteur["flux"][ident].update(etat=status,fin_ms=int(time.time()*1000))
            publier()
class Serveur(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

def main():
    publier();srv=Serveur(ECOUTE,Flux)
    def pulse():
        while True:publier();time.sleep(.2)
    threading.Thread(target=pulse,daemon=True).start()
    def stop(*_):threading.Thread(target=srv.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:srv.serve_forever(poll_interval=.2)
    finally:srv.server_close();publier()
if __name__=="__main__":main()
