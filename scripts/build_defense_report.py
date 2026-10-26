#!/usr/bin/env python3
"""Build the public client report with ReportLab; no Cloud, VM or private evidence reads.

Install reportlab, then run:
    python scripts/build_defense_report.py
All reviewed claims are frozen below. Runtime files, keys, host addresses and
customer identifiers are intentionally never consulted by this generator.
"""
from __future__ import annotations
import argparse
from pathlib import Path
from html import escape

from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph
from reportlab.lib.utils import ImageReader

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'output/pdf/SAWM-Basira-Cyberdefense-Agentique-2026-10-26.pdf'
DATE = '26 OCTOBRE 2026'
REPO = 'https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira'
DOC = REPO + '/blob/main/docs/'
W, H = 595.276, 841.89
M, CW = 47, 501.276
INK, GRAY, LIGHT, RULE = colors.HexColor('#111111'), colors.HexColor('#555555'), colors.HexColor('#f1f1f1'), colors.HexColor('#d0d0d0')
BODY = ParagraphStyle('body',fontName='Helvetica',fontSize=10.1,leading=14.2,textColor=INK,spaceAfter=7)
SMALL = ParagraphStyle('small',parent=BODY,fontSize=8.3,leading=11.3,textColor=GRAY)
TINY = ParagraphStyle('tiny',parent=SMALL,fontSize=7.5,leading=10)
CELL = ParagraphStyle('cell',parent=BODY,fontSize=9.1,leading=12)
HEAD = ParagraphStyle('head',parent=CELL,fontName='Helvetica-Bold',textColor=colors.white)
WHITE = ParagraphStyle('white',parent=BODY,textColor=colors.white)
WHITE_SMALL = ParagraphStyle('white-small',parent=SMALL,textColor=colors.HexColor('#dedede'))
SOURCES = [
 ('R1','Kit public et documentation', REPO),
 ('R2','Essais VM du 26 octobre 2026',DOC+'VALIDATION-VM-2026-10-26.md'),
 ('R3','Défense en profondeur et garde locale',DOC+'DEFENSE-PROFONDEUR.md'),
 ('R4','Démarrage et API publiques',DOC+'QUICKSTART.md'),
 ('R5','ISO/IEC 27001:2022', 'https://www.iso.org/standard/27001'),
 ('R6','ISO/IEC 27002:2022', 'https://www.iso.org/standard/75652.html'),
 ('R7','ISO/IEC 27035-1:2023', 'https://www.iso.org/standard/78973.html'),
 ('R8','ISO : certification et organismes externes', 'https://www.iso.org/certification.html'),
 ('R9','CIS Controls v8.1', 'https://www.cisecurity.org/controls/v8-1'),
 ('R10','Liste officielle des 18 contrôles CIS', 'https://www.cisecurity.org/controls/cis-controls-list'),
 ('R11','MITRE D3FEND : définition et limites', 'https://d3fend.mitre.org/faq/'),
 ('R12','D3FEND : File Analysis, D3-FA', 'https://d3fend.mitre.org/technique/d3f:FileAnalysis/'),
 ('R13','D3FEND : Process Analysis, D3-PA', 'https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/'),
 ('R14','Matrice D3FEND, version consultée 1.6.0', 'https://d3fend.mitre.org/'),
]


def clean(t):
    return str(t).replace('\u2011','-').replace('\u2013','-').replace('\u2014','-').replace('\u2192',' > ')


class Report:
    def __init__(self, path):
        self.c=canvas.Canvas(str(path),pagesize=(W,H),pageCompression=1,invariant=1)
        self.c.setTitle('Cyberdéfense agentique SAWM & Basira - Fonctionnement, preuves et intégration')
        self.c.setAuthor('SAWM & Basira')
        self.c.setSubject('Défense en profondeur, résultats VM et repères ISO, CIS et MITRE D3FEND')
        self.page=0;self.y=0;self.md=[];self.min_y=H

    def p(self, text, *, x=None, width=None, y=None, style=BODY, gap=7):
        x=M if x is None else x;width=CW if width is None else width
        yy=self.y if y is None else y
        para=Paragraph(clean(text),style);_,height=para.wrap(width,1000)
        if yy-height<48:raise RuntimeError(f'Page {self.page} overflow: {text[:80]} at {yy-height:.1f}')
        para.drawOn(self.c,x,yy-height);self.min_y=min(self.min_y,yy-height)
        if y is None:self.y=yy-height-gap
        self.md.append(clean(text))
        return height

    def title(self,label,title,intro=None):
        self.new_page(label)
        self.p(title,style=ParagraphStyle('title',parent=BODY,fontName='Helvetica-Bold',fontSize=27,leading=30),gap=15)
        if intro:self.p(intro,style=ParagraphStyle('intro',parent=BODY,fontSize=11.2,leading=15.6),gap=15)

    def new_page(self,label):
        if self.page:self.footer();self.c.showPage()
        self.page+=1;self.c.bookmarkPage(f'p{self.page}');self.c.addOutlineEntry(label,f'p{self.page}',0)
        self.md.append('\n\n# '+str(self.page)+'. '+label+'\n')
        self.c.setFillColor(INK);self.c.setFont('Helvetica-Bold',9);self.c.drawString(M,H-37,'SAWM & BASIRA')
        self.c.setFillColor(GRAY);self.c.setFont('Helvetica',8);self.c.drawRightString(W-M,H-37,'CYBERDÉFENSE AGENTIQUE')
        self.c.setStrokeColor(RULE);self.c.line(M,H-48,W-M,H-48)
        self.c.setFillColor(GRAY);self.c.setFont('Helvetica-Bold',8);self.c.drawString(M,H-71,label.upper())
        self.y=H-88

    def footer(self):
        self.c.setStrokeColor(RULE);self.c.line(M,38,W-M,38)
        self.c.setFillColor(GRAY);self.c.setFont('Helvetica',7.2)
        self.c.drawString(M,25,'SAWM & BASIRA  /  DOSSIER CLIENT  /  '+DATE)
        self.c.drawRightString(W-M,25,f'{self.page:02d} / 10')

    def section(self,title):
        self.y-=6
        self.p(title,style=ParagraphStyle('section',parent=BODY,fontName='Helvetica-Bold',fontSize=12.3,leading=16),gap=8)

    def box(self, title, text, *, dark=False):
        title_style=ParagraphStyle('box-title',parent=WHITE if dark else BODY,fontName='Helvetica-Bold',fontSize=11.5,leading=15)
        body_style=WHITE if dark else BODY
        _,h1=Paragraph(clean(title),title_style).wrap(CW-28,1000)
        _,h2=Paragraph(clean(text),body_style).wrap(CW-28,1000)
        height=h1+h2+36
        self.c.setFillColor(INK if dark else LIGHT);self.c.rect(M,self.y-height,CW,height,fill=1,stroke=0)
        self.p(title,x=M+14,width=CW-28,y=self.y-13,style=title_style)
        self.p(text,x=M+14,width=CW-28,y=self.y-21-h1,style=body_style)
        self.y-=height+13

    def table(self,headers,rows,widths,*,font=9.1):
        widths=[CW*w/sum(widths) for w in widths]
        style=ParagraphStyle('table-cell',parent=CELL,fontSize=font,leading=font+3)
        for index,row in enumerate([headers]+rows):
            styles=[HEAD]*len(row) if index==0 else [style]*len(row)
            paras=[Paragraph(clean(str(t)),st) for t,st in zip(row,styles)]
            height=max(p.wrap(w-18,1000)[1] for p,w in zip(paras,widths))+18
            if self.y-height<51:raise RuntimeError(f'Page {self.page} table overflow at row {index}')
            self.c.setFillColor(INK if index==0 else (LIGHT if index%2 else colors.white))
            self.c.rect(M,self.y-height,CW,height,fill=1,stroke=0)
            x=M
            for p,w in zip(paras,widths):
                _,h=p.wrap(w-18,1000);p.drawOn(self.c,x+9,self.y-9-h);x+=w
            self.y-=height;self.md.append(' | '.join(clean(x) for x in row))
        self.y-=13

    def refs(self, ids):
        refs=[]
        for ident in ids:
            key,label,url=next(x for x in SOURCES if x[0]==ident)
            refs.append(f'<link href="{escape(url,quote=True)}" color="#555555"><u>{key} - {escape(label)}</u></link>')
        self.p('Sources : '+' ; '.join(refs),style=TINY,gap=9)

    def numbered(self,n,title,text):
        self.c.setFillColor(INK);self.c.circle(M+11,self.y-10,10,fill=1,stroke=0)
        self.c.setFillColor(colors.white);self.c.setFont('Helvetica-Bold',9);self.c.drawCentredString(M+11,self.y-13,str(n))
        h=self.p('<b>'+title+'</b><br/>'+text,x=M+32,width=CW-32,y=self.y,style=BODY)
        self.y-=max(h,22)+13

    def finish(self):
        self.footer();self.c.save()
        if self.page!=10:raise RuntimeError(f'Expected 10 pages, got {self.page}')


def arrow(c,x1,y1,x2,y2):
    c.setStrokeColor(INK);c.setFillColor(INK);c.setLineWidth(1);c.line(x1,y1,x2,y2)
    import math
    a=math.atan2(y2-y1,x2-x1);p=c.beginPath();p.moveTo(x2,y2)
    p.lineTo(x2-5*math.cos(a-.45),y2-5*math.sin(a-.45));p.lineTo(x2-5*math.cos(a+.45),y2-5*math.sin(a+.45));p.close();c.drawPath(p,fill=1,stroke=0)


def architecture(r):
    top=r.y;h=224;c=r.c
    c.setFillColor(LIGHT);c.rect(M,top-h,CW,h,fill=1,stroke=0)
    r.p('LABORATOIRE - CAPTEURS VM / CONTRÔLEUR HÔTE',x=M+14,width=CW-28,y=top-12,style=ParagraphStyle('label',parent=SMALL,fontName='Helvetica-Bold'))
    bw=(CW-48)/3;xs=[M+12+i*(bw+12) for i in range(3)]
    for x,title,body in zip(xs,['CAPTEURS LINUX','CONTRÔLEUR HÔTE','EXÉCUTEUR LINUX'],['Fichiers, processus,<br/>connexions, disponibilité','Corrélation, mandat,<br/>journal, ticket signé','Identité et maintenance,<br/>action bornée, contrôle']):
        c.setFillColor(colors.white);c.rect(x,top-102,bw,60,fill=1,stroke=0)
        r.p('<b>'+title+'</b><br/>'+body,x=x+9,width=bw-18,y=top-51,style=SMALL)
    arrow(c,xs[0]+bw,top-72,xs[1],top-72);arrow(c,xs[1]+bw,top-72,xs[2],top-72)
    c.setFillColor(INK);c.rect(M+12,top-205,CW-24,63,fill=1,stroke=0)
    r.p('<b>API PUBLIQUES BASIRA / SAWM CLOUD</b><br/>Basira conserve - TSST rappelle - ODVL classe - SAWM propose',x=M+26,width=CW-52,y=top-154,style=WHITE)
    arrow(c,xs[1]+bw/2-16,top-104,xs[1]+bw/2-16,top-140)
    arrow(c,xs[1]+bw/2+16,top-140,xs[1]+bw/2+16,top-104)
    r.p('Dépôt / rappel / proposition',x=M+270,width=200,y=top-118,style=TINY)
    r.y=top-h-14


def build(path:Path, markdown:Path|None=None):
    path.parent.mkdir(parents=True,exist_ok=True);r=Report(path)
    # 1 - executive opening
    r.new_page('Vue dirigeant')
    c=r.c;c.setFillColor(INK);c.rect(0,H-480,W,480,fill=1,stroke=0)
    logo=ROOT/'docs/assets/sawm-basira-flower.png'
    if logo.exists():c.drawImage(ImageReader(str(logo)),W-M-82,H-126,82,82,mask='auto',preserveAspectRatio=True)
    r.p('SAWM & BASIRA',x=M,width=350,y=H-49,style=ParagraphStyle('brand',parent=WHITE,fontName='Helvetica-Bold',fontSize=12,leading=16))
    r.p('DOSSIER CLIENT / OCTOBRE 2026',x=M,width=350,y=H-77,style=WHITE_SMALL)
    r.p('Cyberdéfense<br/>agentique',x=M,width=CW,y=H-158,style=ParagraphStyle('cover',parent=WHITE,fontName='Helvetica-Bold',fontSize=42,leading=45))
    r.p('Observer. Comprendre.<br/>Intervenir. Prouver.',x=M,width=CW,y=H-270,style=ParagraphStyle('tag',parent=WHITE,fontSize=23,leading=29))
    r.p('Une défense qui relie les événements du serveur,<br/>les décisions autorisées et leurs effets vérifiés.',x=M,width=CW,y=H-356,style=ParagraphStyle('cover-body',parent=WHITE,fontSize=12,leading=17))
    r.p('VM Linux réelle - données fictives - API publiques<br/>Résultats et périmètre arrêtés au 26 octobre 2026',x=M,width=CW,y=H-424,style=WHITE_SMALL)
    r.y=H-502
    r.section('Ce que le client peut déjà examiner')
    for title,text in [
        ('Disponibilité retrouvée','Un verrou SQLite non autorisé a conduit SAWM à choisir l’arrêt ciblé ; le service a retrouvé ses lectures et écritures.'),
        ('Maintenance préservée','Un mandat signé protège les opérations autorisées. La garde locale bloque une tentative d’arrêt incompatible.'),
        ('Actions explicables','Le dossier conserve faits, proposition, autorisation, reçu et effet. L’arrêt de l’auteur ne devient pas une restauration de données.')]:
        r.p('<b>'+title+'</b> - '+text,gap=10)
    r.p('À lire : fonctionnement p. 2 - capacités p. 3 - défense en profondeur p. 4 - preuves p. 5 - audit p. 6 - ISO/CIS p. 7 - D3FEND p. 8 - intégration p. 9 - pilote et sources p. 10.',style=SMALL)
    # 2 - architecture
    r.title('01 / Fonctionnement','Une boucle qui va<br/>jusqu’au résultat.', 'L’agent suit une situation, rappelle le contexte utile et choisit parmi les inspections et interventions déléguées. Le serveur vérifie les droits au moment d’agir.')
    architecture(r)
    r.table(['Composant','Rôle concret'],[
        ['<b>Basira</b>','Conserve les observations et retours avec leur provenance, pour retrouver ce qui a été déclaré et ce qui a changé.'],
        ['<b>TSST</b>','Rappelle les preuves pertinentes dans le périmètre autorisé. Le rappel ne remplace pas une mesure actuelle du serveur.'],
        ['<b>ODVL</b>','Reclasse les candidats du rappel. Il n’ajoute ni droit ni preuve et ne certifie pas qu’une information est vraie.'],
        ['<b>SAWM</b>','Examine le contexte, choisit une inspection ou une proposition et fournit une justification publique avec ses inconnues.'],
    ],[1,4],font=9.3)
    r.box('Le noyau observe et applique les protections prévues.','Dans cette campagne, les capteurs et l’exécuteur tournent dans la VM ; le contrôleur et le dashboard sur l’hôte. Les sondes eBPF et BPF LSM sont côté Linux. SAWM, Basira, TSST et ODVL restent des services consommés par API, hors du noyau.')
    r.refs(['R1','R3'])
    # 3 - capability catalogue
    r.title('02 / Capacités','Ce que l’équipe peut<br/>mettre à l’épreuve.', 'Une vue utile au responsable de sécurité : ce qui est observé, la réponse possible et la portée de la preuve disponible.')
    r.table(['Situation','Réponse du système','État de preuve'],[
        ['Base bloquée','Attribuer le verrou, contrôler la maintenance, arrêter l’unité déléguée, retester la disponibilité.','<b>VM + SAWM</b><br/>Validé le 26/10.'],
        ['Fichier ou base altéré','Corréler empreinte et opération attribuée ; contenir l’auteur autorisé à être arrêté.','<b>VM locale</b><br/>Confinement validé ; restauration distincte.'],
        ['Maintenance planifiée','Vérifier signature, opération, cible, période et incarnation du processus ; opposer le veto.','<b>VM locale</b><br/>Protection validée.'],
        ['Connexion forcée','Compter les refus, exclure temporairement une source sur le service d’essai, vérifier le retour.','<b>VM locale</b><br/>Port fictif 8082 ; pas un pare-feu global.'],
        ['Connexion SSH rejetée','Observer les refus et alerter en gardant l’accès légitime.','<b>VM + OpenSSH</b><br/>Pas de bannissement SSH automatique.'],
        ['Accès à une fixture protégée','Appliquer une politique BPF LSM et vérifier un accès témoin autorisé.','<b>VM + noyau</b><br/>Lecture refusée, y compris au processus root testé.'],
        ['CPU / réseau inhabituels','Inspecter processus, compte, connexions ou base ; proposer gel, arrêt ou limite CPU.','<b>Code + essais antérieurs</b><br/>Qualification par cible requise.'],
        ['Paquet ou grand dossier','Examiner un .deb soumis avec ClamAV ; inventorier et comparer des fichiers par blocs.','<b>Modules + tests</b><br/>Pas revalidés en VM dans cette campagne.'],
    ],[1.1,2.7,1.7],font=9)
    r.p('<b>Lecture des statuts.</b> « VM » désigne un essai réel dans le laboratoire, sur données fictives. « Code + tests » signifie que la capacité existe, sans prétendre qu’elle a été éprouvée ici contre toutes les attaques. Un pic CPU ou une empreinte modifiée ne suffit pas à identifier un malware.',style=SMALL)
    r.refs(['R2','R3'])
    # 4 - defense in depth
    r.title('03 / Défense en profondeur','Plusieurs contrôles.<br/>Une autorité explicite.', 'L’autonomie commence avec un mandat approuvé. Aucune phrase de l’agent ne peut élargir ses droits ni remplacer une preuve technique manquante.')
    layers=[
        ('1','Mandat institutionnel','Unités et actions autorisées, services protégés, génération du manifeste et clés enrôlées.'),
        ('2','Observation datée','Faits système, attribution, posture et fraîcheur. Une mesure ancienne reste ancienne.'),
        ('3','Enquête bornée','Le modèle choisit parmi quatre inspections permises ; au plus trois inspections sous 120 secondes.'),
        ('4','Veto du contrôleur','Délégation, journal signé, capteurs, budget et contrôles bloquants choisis par l’administrateur.'),
        ('5','Ticket Ed25519','Autorisation liée à la décision, à l’action, à la cible, à son identité et à l’empreinte du manifeste.'),
        ('6','Réinspection locale','Maintenance, identité, mandat et ticket recontrôlés après écriture durable, avant mutation.'),
        ('7','Effet et preuve','Reçu, vérification de l’effet et du témoin ; dépôt du retour en mémoire et traçabilité.'),
    ]
    for n,title,text in layers:r.numbered(n,title,text)
    r.section('Posture de la VM : 22 contrôles, dont 12 sondes OS')
    x=M
    for count,fill in [(17,INK),(3,colors.HexColor('#999999')),(2,colors.HexColor('#dddddd'))]:
        width=CW*count/22
        r.c.setFillColor(fill);r.c.rect(x,r.y-17,width,17,fill=1,stroke=0);x+=width
    r.y-=25
    r.p('<b>17 satisfaits</b> / 3 écarts / 2 inconnus. Instantané de déploiement ; aucun taux de conformité ISO. Les écarts concernent SSH et NTP ; les inconnus, l’ancrage externe et l’attestation LSM continue.',style=SMALL)
    r.p('Tickets : 5 s. Posture : validité maximale 60 s. La garde locale exige des preuves fraîches de 1 500 ms et revérifie avant l’action. Ces durées sont des critères d’autorisation, pas des délais garantis de détection.',style=SMALL)
    r.refs(['R3'])
    # 5 - measured results
    r.title('04 / Preuves au 26 octobre','Une décision SAWM<br/>exécutée et vérifiée.', 'La campagne utilise de vrais processus Linux, de vraies bases SQLite et le Cloud réel. Les données de test sont fictives et le nettoyage opérateur est comptabilisé séparément.')
    r.box('Cas validé : remettre une base à disposition.', 'Le noyau attribue un verrou exclusif ; lectures et écritures sont bloquées. SAWM choisit <b>arreter-service</b>. Le ticket et les contrôles locaux autorisent l’intervention. La base redevient accessible, le témoin reste sain et le résultat est enregistré dans Basira.',dark=True)
    r.table(['Scénario','Décideur / mécanisme','Résultat observé'],[
        ['Verrou SQLite non autorisé','SAWM Cloud + exécuteur local','<b>Réussi.</b> Choix d’arrêt, effet vérifié et retour mémoire.'],
        ['Verrou SQLite sans Cloud','Garde locale signée','<b>Réussi.</b> Arrêt ciblé, lectures et écritures rétablies.'],
        ['Altération de base fictive','Garde locale signée','<b>Réussi.</b> Auteur confiné ; l’écart d’intégrité reste visible.'],
        ['Maintenance avec mandat signé','Garde + exécuteur locaux','<b>Réussi.</b> Processus préservé ; tentative d’arrêt refusée.'],
        ['Maintenance examinée par SAWM','SAWM Cloud','<b>Autonomie incomplète.</b> Aucun arrêt, mais clarification demandée au lieu du choix final attendu.'],
        ['Autorisation absente, falsifiée ou expirée','Exécuteur local','<b>Refus vérifiés.</b> La cible n’est pas arrêtée par une demande non autorisée.'],
    ],[1.45,1.35,2.4],font=9.1)
    r.p('<b>Répétition et contrôle.</b> Les trois cas de garde locale ont été exécutés deux fois, dont une fois après le correctif de maintenance. Le mandat initial est restauré à l’identique après chaque scénario. L’altération n’a pas été revalidée par SAWM après la reprise du Cloud.',style=SMALL)
    r.p('<b>Validation logicielle distincte :</b> 775 tests du runner isolé réussis, sources inchangées pendant l’exécution, puis 10 tests d’instances parallèles réussis. Aucun pourcentage de détection générale n’est extrapolé.',style=SMALL)
    r.refs(['R2'])
    # 6 - audit and operations
    r.title('05 / Traçabilité et résilience','Expliquer l’action.<br/>Conserver l’écart.', 'Le dashboard donne une lecture commune aux exploitants, aux responsables de sécurité et aux auditeurs. Les preuves de campagne sont distinguées de la santé actuelle du serveur.')
    r.table(['Question de l’auditeur','Ce que le dossier doit montrer'],[
        ['Que s’est-il passé ?','Source, date, observation, fichier ou unité concernée, attribution disponible et limites.'],
        ['Pourquoi intervenir ?','Proposition structurée, justification publique, preuves retenues et inconnues. Les pensées internes du LLM ne sont pas une preuve.'],
        ['Qui l’a autorisé ?','Mandat applicable, rôle du signataire, cible, action, durée du ticket et éventuelle maintenance.'],
        ['L’action a-t-elle eu lieu ?','Reçu local, identité recontrôlée, effet observé et disponibilité du service légitime.'],
        ['Le système a-t-il appris de ce retour ?','Dépôt du résultat dans Basira pour le rappel suivant. Cela ne prouve pas un entraînement automatique des poids du modèle.'],
    ],[1.35,3.65],font=9.4)
    r.section('Trois vues qui ne doivent pas se confondre')
    r.p('<b>État courant :</b> fraîcheur des capteurs, disponibilité, activité de la veille et contrôles de posture. Une donnée périmée ou absente devient explicitement inconnue.')
    r.p('<b>Campagne récente :</b> garde locale et pipeline SAWM séparés ; essais réussis, bloqués et échoués conservés ; cartes repliables, reçus et nettoyage distincts.')
    r.p('<b>Historique :</b> décisions, résultats, changements, signatures et références des rapports. Les archives ne valent pas état actuel du serveur.')
    r.box('Continuité locale et reprise maîtrisée','Les gardes locales supervisées peuvent agir sans Cloud dans leur mandat. La panne Cloud bloque les nouvelles décisions distantes. La campagne a rencontré une saturation mémoire et un worker arrêté ; la reprise a permis le tour SAWM validé. Le limiteur Cloud a été corrigé et redéployé ; sa fenêtre de comptage est désormais mise à jour atomiquement, sans remise à zéro des consommations.')
    r.p('Une chaîne signée protège l’intégrité vérifiable du journal. Une ancre extérieure indépendante est nécessaire contre son effacement ou un retour arrière conjoint. Les scores fonctionnels de vigilance ne sont ni une preuve de malware ni des sentiments vécus.',style=SMALL)
    r.refs(['R2','R3'])
    # 7 - ISO and CIS
    r.title('06 / Référentiels de sécurité','Des preuves utiles<br/>au programme ISO.', 'Le kit apporte des mécanismes techniques et un dossier d’exécution. Les correspondances ci-dessous sont une analyse du projet ; elles ne constituent pas une certification ou un audit complet des normes.')
    r.table(['Référence','Rôle du référentiel','Contribution du kit'],[
        ['<b>ISO/IEC 27001:2022</b>','Exigences d’un système de management de la sécurité et traitement des risques.','Périmètre, mandats, responsabilité des décisions et preuves d’exécution à intégrer au SMSI du client.'],
        ['<b>ISO/IEC 27002:2022</b>','Recommandations pour choisir et mettre en œuvre des mesures de sécurité.','Accès bornés, surveillance, journalisation et vérification des interventions. La pertinence dépend du risque.'],
        ['<b>ISO/IEC 27035-1:2023</b>','Principes et processus de préparation, détection, évaluation, réponse et retour d’expérience.','Événement, enquête, décision, action et résultat conservés dans une chronologie explicable.'],
    ],[1.45,1.9,2.15],font=9.2)
    r.section('CIS Controls v8.1 : repères techniques sélectionnés')
    r.table(['Objectif du kit','Familles CIS pertinentes','À compléter chez le client'],[
        ['Inventaire et posture','1, 2 et 4','Périmètre exhaustif, propriétaires, inventaire logiciel et configurations de référence.'],
        ['Mandats et maintenance','5 et 6','Annuaire, MFA, cycle de vie des accès et revues des droits.'],
        ['Journal et observation','8 et 13','Couverture réseau, conservation extérieure, alertes et exploitation SOC.'],
        ['Paquets, reprise, incidents','10, 11 et 17','Politique antivirus, sauvegardes restaurables, exercices et procédure de réponse.'],
    ],[1.5,1.15,2.85],font=9)
    r.p('<b>Statut précis.</b> ISO 27001 vise un SMSI sur un périmètre défini. ISO 27002 n’est pas certifiable. Une certification, lorsqu’elle est recherchée, relève d’un organisme externe. Le kit n’est annoncé ni « certifié ISO », ni conforme à l’ensemble des Safeguards CIS.',style=SMALL)
    r.refs(['R5','R6','R7','R8','R9','R10'])
    # 8 - D3FEND
    r.title('07 / Lecture MITRE D3FEND','Nommer les protections.<br/>Délimiter leur effet.', 'D3FEND est un graphe de connaissances des techniques défensives. Il fournit un vocabulaire commun ; il ne garantit ni la priorité ni l’efficacité d’un produit. Version consultée : 1.6.0, le 26 octobre 2026.')
    r.table(['Technique de référence','Mécanisme du kit','Ce que le rapprochement ne prouve pas'],[
        ['<b>Process Analysis</b><br/>D3-PA','Attribution aux processus, incarnation, cgroup et inspection de leurs ressources.','Ni analyse de toutes les familles de malware, ni surveillance de chaque processus.'],
        ['<b><link href="https://d3fend.mitre.org/technique/d3f:FileAccessPatternAnalysis/">File Access Pattern Analysis</link></b><br/>D3-FAPA','Corrélation entre opérations sur les fichiers déclarés, identité OS et autorisations.','Ni lecture sémantique de tous les accès, ni intention malveillante déduite d’un seul indice.'],
        ['<b>File Analysis</b><br/>D3-FA','Sas des paquets .deb soumis, inspection de contenu et recours à ClamAV.','Ni interception générale des téléchargements, ni absence prouvée de porte dérobée.'],
        ['<b><link href="https://d3fend.mitre.org/technique/d3f:ApplicationPerformanceMonitoring/">Application Performance Monitoring</link></b><br/>D3-APM','Délais des sondes et du témoin, durée des inspections et des appels ; CPU et RAM comme contexte.','Un pic de charge n’identifie pas à lui seul une attaque.'],
    ],[1.45,2.1,2],font=9.4)
    r.box('Le classement est descriptif.','Ces correspondances sont proposées par l’équipe SAWM & Basira à partir des fonctions du code. Elles ne constituent ni une validation par MITRE, ni un score de couverture, ni une preuve qu’une technique offensive associée sera automatiquement arrêtée.')
    r.section('Un cadre de test commun avec le client')
    r.numbered(1,'Définir le cas','Quel service et quelle donnée protéger ? Quel comportement doit être autorisé, signalé ou contenu ?')
    r.numbered(2,'Lier mécanisme et preuve','Quelle sonde observe le fait ? Quel reçu démontre l’action ? Quel contrôle confirme la disponibilité et l’intégrité ?')
    r.numbered(3,'Éprouver les exceptions','Maintenance, attribution absente, ticket expiré, perte des capteurs ou du Cloud.')
    r.y+=9
    r.refs(['R11','R12','R13','R14'])
    # 9 - integration
    r.title('08 / Intégration','Du Cloud public<br/>à votre VM de test.', 'Le code public est un kit d’intégration réutilisable. Les moteurs restent privés et sont accessibles avec un compte autorisé, les droits adaptés et les crédits du service.')
    r.numbered(1,'Créer le périmètre Cloud','Depuis <link href="https://basira.sawm.io/espace"><u>basira.sawm.io/espace</u></link> : créer un espace, une entité serveur et un principal de service ; accorder read/write sur cette entité précise.')
    r.numbered(2,'Émettre une clé de service limitée','Profil Runtime agent + SAWM : events:write, jobs:read, memory:recall, tsst:recall, odvl:rank, sawm:run. Le scope API et le grant d’entité sont deux vérifications distinctes.')
    r.numbered(3,'Installer le kit et les capteurs','Python 3.11+, systemd, cgroup v2 et outils adaptés au noyau. Examiner le plan de préparation, puis installer dans une VM dédiée. eBPF/LSM se construit et se vérifie pour le noyau cible.')
    r.numbered(4,'Protéger les transports et les clés','Coffre local privé, secrets hors Git, clés hôtes SSH vérifiées, dashboard sur loopback avec tunnel authentifié. Le socket de télémétrie exige une isolation ou un transport authentifié.')
    r.numbered(5,'Observer, puis déléguer','Démarrer sans action, raccorder le Cloud, vérifier les preuves. Enrôler la clé publique, définir les cibles/actions et activer uniquement la délégation nécessaire.')
    r.box('Trois modes progressifs', '<font name="Courier" size="8.3">python controleur/veille.py --duration 60<br/>python controleur/veille.py --duration 300 --cloud --cloud-per-hour 4<br/>python controleur/veille.py --permanent --cloud --apply --cloud-per-hour 4</font><br/><br/>Ces commandes supposent le transport et les droits déjà configurés. --apply ne remplace pas le manifeste, l’enrôlement de clé ni le mandat de maintenance.')
    r.p('<b>Exploitation.</b> Superviser les processus et surveiller la fraîcheur. Le budget actuel est de quatre tours SAWM par heure, pas quatre requêtes HTTP ni quatre enquêtes complètes. Aucun appel Cloud n’est déclenché par la seule ouverture du dashboard.',style=SMALL)
    r.p('<b>Licence.</b> Kit Apache-2.0 ; fichier BPF LSM sous GPL-2.0-only. Services Cloud, marques et droits d’accès restent distincts de cette licence.',style=SMALL)
    r.refs(['R1','R3','R4'])
    # 10 - next steps and sources
    r.title('09 / Pilote client et références','Transformer la démonstration<br/>en preuve métier.', 'Le prochain engagement consiste à mesurer cette boucle sur une installation représentative du client, avec un mandat de test, des critères d’acceptation et un responsable identifié.')
    r.table(['Avant mise en service','Preuve d’acceptation attendue'],[
        ['Périmètre et droits','Inventaire, services protégés, maintenances, responsables et révocation des accès.'],
        ['Détection et décision','Scénarios positifs et négatifs, délais, faux positifs, qualité d’attribution et absence d’action hors mandat.'],
        ['Panne et reprise','Perte du Cloud et des capteurs, redémarrage, épuisement du budget, restauration testée, ancre indépendante.'],
        ['Charge et exploitation','Capacité par serveur, coûts mesurés, rétention, alertes opérateur, transport authentifié et intégration SOC.'],
    ],[1.45,3.55],font=9)
    r.p('<b>Améliorations prioritaires :</b> rendre la maintenance autonome sans clarification redondante ; reprendre explicitement une enquête après retour humain ; qualifier les grands dossiers, paquets et volumes réseau ; étendre le périmètre des capteurs et l’intégration des identités. Les écarts SSH/NTP et les mesures inconnues du laboratoire restent visibles jusqu’à vérification.',style=SMALL)
    r.section('Sources consultées et méthode')
    r.p('Les résultats techniques proviennent de la documentation de campagne et des rapports locaux vérifiés. Les fichiers bruts restent privés ; ce PDF n’inclut ni clé, ni identité de compte, ni adresse du laboratoire. Les références externes ci-dessous sont les sources officielles consultées le 26/10/2026. Les correspondances sont une analyse du projet.',style=SMALL,gap=10)
    # Compact two-column bibliography with clickable references, preserving legibility.
    start=r.y;col=(CW-22)/2
    for idx,(key,label,url) in enumerate(SOURCES):
        side=idx//7;row=idx%7;x=M+side*(col+22);y=start-row*29
        r.p(f'<b>{key}</b> <link href="{escape(url,quote=True)}" color="#111111"><u>{escape(label)}</u></link>',x=x,width=col,y=y,style=TINY)
    r.y=start-7*29-5
    r.p('Périmètre : démonstrateur Linux sur données fictives. La couverture de tous les malwares, une résistance à un noyau compromis et la conformité complète d’une organisation ne sont pas établies par ces essais. Le pilote doit éprouver les risques et obligations du client.',style=TINY)
    r.finish()
    if markdown:
        markdown.parent.mkdir(parents=True,exist_ok=True)
        markdown.write_text('# Rapport client - Cyberdéfense agentique SAWM & Basira\n\nÉdition du 26 octobre 2026. Source reproductible : `scripts/build_defense_report.py`.\n\n'+'\n\n'.join(r.md)+'\n\n## Références\n\n'+'\n'.join(f'- [{k} - {label}]({url})' for k,label,url in SOURCES)+'\n',encoding='utf-8')
    return r.page


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=DEST)
    parser.add_argument('--markdown',type=Path,help='Optional reading transcript; PDF is the formatted reference.')
    args=parser.parse_args()
    count=build(args.output,args.markdown)
    print(f'{count} pages: {args.output}')


if __name__=='__main__':main()
