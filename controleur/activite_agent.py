"""Measured agent activity, separate from functional personality heuristics.

Derives a public read-only view from controller heartbeat and existing API
events. No Cloud call, permission change or fabricated TSST/ODVL risk score.
"""
from __future__ import annotations
import json
import math

FRESH_MS=300_000


def number(value):
    return value if type(value) in (int,float) and math.isfinite(value) and value>=0 else None


def engine_for(call):
    return {'recall:tsst':'tsst','odvl:rank':'odvl','sawm:responses':'sawm'}.get(call.get('appel'))


def age_fields(timestamp,now):
    age=now-timestamp if number(timestamp) is not None else None
    return {'observed_ms':timestamp if number(timestamp) is not None else None,
            'age_ms':max(0,round(age)) if age is not None else None,
            'fresh':age is not None and 0<=age<=FRESH_MS}


def call_view(event,now):
    if not event:return {'status':'not_observed','observed_ms':None,'age_ms':None,'fresh':False,
                         'http_status':None,'latency_ms':None,'attempt':None,'terminal':None,
                         'source':'metadonnees_client_API'}
    timestamp=number(event.get('mur_epoch_ms'));duration=number(event.get('ms'))
    if timestamp is not None and duration is not None:timestamp+=duration
    http=event.get('statut') if type(event.get('statut')) is int else None
    result=event.get('resultat')
    terminal=event.get('terminal') if event.get('terminal') in {'turn.done','turn.failed','turn.cancelled'} else None
    status=('error' if result in {'http_error','transport_error','stream_error'} or http and http>=400 else
            'incomplete' if result=='incomplete' else
            'completed' if event.get('appel')=='sawm:responses' and terminal=='turn.done' and result=='ok' else
            'http_ok' if http and 200<=http<300 else 'unknown')
    return {'status':status,**age_fields(timestamp,now),'http_status':http,
            'latency_ms':duration,'attempt':number(event.get('tentative')),'terminal':terminal,
            'source':'metadonnees_client_API'}


def marker_value(markers,phase):
    row=next((x for x in reversed(markers) if x.get('phase')==phase),None)
    if not row or not isinstance(row.get('texte'),str) or len(row['texte'])>4000:return None,None
    try:value=json.loads(row['texte'])
    except (ValueError,TypeError):return row,None
    return row,value if type(value) is dict else None


def summarize(snapshot,heartbeat,latest_calls,*,now_ms):
    markers=snapshot.get('marqueurs',[])
    engines={name:call_view(latest_calls.get(name),now_ms) for name in ('tsst','odvl','sawm')}
    alive=heartbeat.get('battement_frais') is True and heartbeat.get('active') is True
    mode=snapshot.get('mode')
    recent=[x for x in markers if x.get('phase') in {'analyse','decision'} and number(x.get('mur_epoch_ms')) is not None]
    last_stage=max(recent,key=lambda x:x['mur_epoch_ms'],default=None)
    model_pending=bool(last_stage and last_stage['phase']=='analyse' and 0<=now_ms-last_stage['mur_epoch_ms']<180_000)
    if (model_pending and engines['sawm']['observed_ms'] is not None
            and engines['sawm']['observed_ms']>=last_stage['mur_epoch_ms']):
        model_pending=False  # A completed/error HTTP/SSE receipt ends waiting.
    if mode!='DIRECT':phase='rejeu'
    elif model_pending:phase='attente_reponse_sawm'
    elif not alive:phase='veille_indisponible'
    elif heartbeat.get('analyse_en_cours') is True:phase='analyse_en_cours'
    elif (number(heartbeat.get('repli_cloud_secondes')) or 0)>0:phase='repli_cloud'
    elif ((number(heartbeat.get('analyses_reservees_derniere_heure')) or 0)
          >=(number(heartbeat.get('budget_analyses_par_heure')) or float('inf'))):phase='budget_cloud_epuise'
    elif (number(heartbeat.get('analyses_en_attente')) or 0)>0:phase='attente_analyse'
    else:phase='observation_locale'
    memory=None;row,value=marker_value(markers,'memoire_prete')
    if (value and value.get('schema')=='sawm-agent-memory-observation/v1'
            and all(type(value.get(k)) is int and value[k]>=0 for k in ('evidence_count','used_evidence_count'))
            and all(type(value.get(k)) is bool for k in ('odvl_applied','reused'))):
        memory={**age_fields(row.get('mur_epoch_ms'),now_ms),
                **{k:value[k] for k in ('evidence_count','used_evidence_count','odvl_applied','reused')},
                'memory_age_ms':number(value.get('memory_age_ms')),
                'source':'connecteur_apres_validation_permutation_ODVL'}
    dispositions=None;row,value=marker_value(markers,'disposition_serveur')
    if value and value.get('schema')=='sawm-server-dispositions/v1' and type(value.get('revision')) is int:
        dispositions={**age_fields(row.get('mur_epoch_ms'),now_ms),'revision':value['revision'],
                      'source':'heuristique_locale_non_calibree'}
    if mode!='DIRECT':
        for entry in [*engines.values(),memory,dispositions]:
            if entry:entry['fresh']=False
    dates=[x['observed_ms'] for x in engines.values() if x['observed_ms'] is not None]
    if last_stage:dates.append(last_stage['mur_epoch_ms'])
    return {'schema':'sawm-agent-activity/v1','observed_ms':now_ms,'phase':phase,
            'veille_fresh':heartbeat.get('battement_frais') is True,
            'local_observation_active':mode=='DIRECT' and (snapshot.get('telemetrie_invite') or {}).get('connectee') is True,
            'last_activity_ms':max(dates,default=None),'engines':engines,'memory':memory,'dispositions':dispositions,
            'freshness_threshold_ms':FRESH_MS,'source':'battement_et_metadonnees_controleur',
            'limits':['Un succès HTTP ne prouve pas une décision ni une amélioration du modèle.',
                      'Les résultats datés restent historiques quand fresh=false.',
                      'Les traits locaux ne sont ni un score TSST/ODVL ni une mesure de sentiments.']}
