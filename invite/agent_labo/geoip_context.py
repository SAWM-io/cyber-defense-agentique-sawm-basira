"""Contexte pays DB-IP local : aucun réseau, aucune attribution humaine/action.

Le fichier SQLite dérivé est vérifié par son manifeste avant lecture. Les
observations d'authentification restent la preuve ; le pays est une indication
approximative distincte. Charger une instance par processus, puis la réutiliser.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

PROVIDER = 'DB-IP Country Lite'
SOURCE_URL = 'https://db-ip.com/db/download/ip-to-country-lite'
LICENSE_URL = 'https://creativecommons.org/licenses/by/4.0/'
ATTRIBUTION = {'text': 'IP Geolocation by DB-IP', 'url': 'https://db-ip.com'}
MAX_DATABASE_BYTES = 128 * 1024 * 1024
MAX_REPORT_BYTES = 65536
LIMITS = [
    'Pays approximatif associé à une plage IP, jamais position d’une personne.',
    'VPN, proxy, NAT, relais et anycast peuvent dissocier cette indication de l’origine réelle.',
    'Aucun score de confiance individuel ni réputation malveillante fournis par cette base.',
    'Ni blocage automatique ni identité commune ne sont déduits de la géographie.',
]
# Restrictions explicites identiques sur Python 3.10 et 3.14, en complément
# d'is_global : documentation, traduction et quelques espaces spéciaux.
NON_LOCALISABLE = tuple(ipaddress.ip_network(cidr) for cidr in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    '::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48',
    '100::/64', '2001:db8::/32', '2002::/16', '3fff::/20', 'fc00::/7',
    'fe80::/10', 'ff00::/8'))


def _sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _identity(path, limit):
    # Un propriétaire local/root et des parents non modifiables par autrui
    # rendent cette base de contexte indépendante d'un nom de fichier observé.
    for parent in (path, *path.parents):
        st = parent.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid not in (0, os.geteuid()):
            raise ValueError('geoip_path_untrusted')
        if st.st_mode & 0o022 and not (stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX):
            raise ValueError('geoip_path_writable')
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= limit or st.st_nlink != 1:
        raise ValueError('geoip_file_invalid')
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class GeoIPContext:
    """Lecteur sans téléchargement. Une base absente/altérée reste explicite."""
    def __init__(self, database, manifest, *, now_ms=None):
        self.database = Path(database).absolute()
        self.manifest = Path(manifest).absolute()
        self.now_ms = now_ms
        self.reader = None
        self.reason = 'base_absente'
        self.source = {'provider': PROVIDER, 'source_url': SOURCE_URL,
                       'license': 'CC-BY-4.0', 'license_url': LICENSE_URL,
                       'attribution': dict(ATTRIBUTION)}
        self._ids = None
        try:
            before = (_identity(self.database, MAX_DATABASE_BYTES), _identity(self.manifest, 16384))
            source = json.loads(self.manifest.read_text(encoding='utf-8'))
            if (source.get('schema') != 'sawm-dbip-country-manifest/v1'
                or source.get('provider') != PROVIDER or source.get('license') != 'CC-BY-4.0'
                or source.get('source_url') != SOURCE_URL
                or source.get('license_url') != LICENSE_URL
                or not re.fullmatch(r'[0-9]{4}-[0-9]{2}', str(source.get('release', '')))
                or source.get('download_url') != 'https://download.db-ip.com/free/dbip-country-lite-'+str(source.get('release'))+'.csv.gz'
                or any(not re.fullmatch(r'[a-f0-9]{64}', str(source.get(key, '')))
                       for key in ('source_sha256', 'database_sha256'))
                or type(source.get('records')) is not int or not 1 <= source['records'] <= 2000000):
                raise ValueError('geoip_manifest_invalid')
            release = datetime.date.fromisoformat(source['release']+'-01')
            now = datetime.datetime.fromtimestamp((now_ms if now_ms is not None else time.time()*1000)/1000,
                                                   datetime.timezone.utc).date()
            if release > now:
                raise ValueError('geoip_release_future')
            if _sha(self.database) != source['database_sha256']:
                raise ValueError('geoip_database_hash_mismatch')
            self.reader = sqlite3.connect(self.database.as_uri()+'?mode=ro&immutable=1', timeout=.1)
            self.reader.execute('PRAGMA query_only=ON')
            self.reader.execute('PRAGMA trusted_schema=OFF')
            dbmeta = dict(self.reader.execute('SELECT key, value FROM metadata'))
            if any(str(source[key]) != dbmeta.get(key) for key in ('source_sha256', 'release', 'records')):
                raise ValueError('geoip_metadata_mismatch')
            after = (_identity(self.database, MAX_DATABASE_BYTES), _identity(self.manifest, 16384))
            if before != after:
                raise ValueError('geoip_file_changed_during_load')
            self._ids = after
            self.source.update({key: source[key] for key in
                ('release', 'source_sha256', 'database_sha256', 'records', 'download_url') if key in source})
            self.source.update(database_age_days=(now-release).days,
                               stale=(now-release).days > 75, modified='CSV importé dans un index SQLite ; codes pays conservés.')
            self.reason = 'base_locale_verifiee'
        except (OSError, ValueError, TypeError, OverflowError, sqlite3.Error):
            if self.reader is not None:
                self.reader.close()
            self.reader = None
            self.reason = 'base_absente_ou_non_verifiable'

    def close(self):
        if self.reader is not None:
            self.reader.close()
            self.reader = None

    def describe(self):
        """État du lecteur : stat seulement, pas de re-hachage par polling."""
        available, reason = self.reader is not None, self.reason
        if available:
            try:
                if self._ids != (_identity(self.database, MAX_DATABASE_BYTES), _identity(self.manifest, 16384)):
                    available, reason = False, 'base_modifiee_rechargement_requis'
            except (OSError, ValueError):
                available, reason = False, 'base_locale_non_verifiable'
        return {'available':available, 'status':reason, 'source':dict(self.source),
                'network_request':False, 'block_from_geography':False, 'human_location_known':False,
                'limits':list(LIMITS)}

    def lookup(self, ip):
        row = {'schema': 'sawm-ip-geography/v1', 'ip': None, 'status': 'inconnu',
               'country_code': None, 'precision': 'pays_approximatif',
               'source': dict(self.source), 'confidence': None,
               'human_location_known': False, 'block_from_geography': False,
               'network_request': False, 'limits': list(LIMITS)}
        try:
            if type(ip) is not str or not 1 <= len(ip) <= 45 or '%' in ip:
                raise ValueError()
            address = ipaddress.ip_address(ip)
            row['ip'] = str(address)
        except ValueError:
            row['reason'] = 'ip_invalide'
            return row
        if (not address.is_global or address.is_multicast or address.is_reserved
            or any(address.version == network.version and address in network for network in NON_LOCALISABLE)):
            row.update(status='non_localisable', reason='ip_privee_reservee_ou_traduite', precision=None)
            return row
        if self.reader is None:
            row['reason'] = self.reason
            return row
        try:
            if self._ids != (_identity(self.database, MAX_DATABASE_BYTES), _identity(self.manifest, 16384)):
                row['reason'] = 'base_modifiee_rechargement_requis'
                return row
            packed = address.packed
            found = self.reader.execute('SELECT last_ip, country FROM ranges WHERE version=? AND first_ip<=? '
                                        'ORDER BY first_ip DESC LIMIT 1', (address.version, packed)).fetchone()
            if not found or found[0] < packed or not re.fullmatch(r'[A-Z]{2}', found[1]) or found[1] in ('ZZ','XX','EU','AP'):
                row['reason'] = 'plage_sans_pays_exploitable'
                return row
            row.update(status='approximatif', country_code=found[1], reason='plage_ip_de_la_base_locale')
        except (OSError, ValueError, TypeError, sqlite3.Error):
            row['reason'] = 'lecture_locale_indisponible'
        return row

    def enrich_campaigns(self, diagnostic):
        """Copie bornée ; l'enrichissement ne change ni score ni recommandation."""
        if type(diagnostic) is not dict:
            raise ValueError('geoip_campaign_schema_invalid')
        encoded = json.dumps(diagnostic, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode()) > 32768:
            raise ValueError('geoip_campaign_input_too_large')
        output = json.loads(encoded)
        campaigns = output.get('campagnes')
        if type(campaigns) is not list or len(campaigns) > 16:
            raise ValueError('geoip_campaign_schema_invalid')
        for campaign in campaigns:
            if type(campaign) is not dict:
                raise ValueError('geoip_campaign_schema_invalid')
            sources = campaign.get('sources')
            if type(sources) is not list or len(sources) > 32:
                raise ValueError('geoip_campaign_sources_invalid')
            for source in sources:
                if type(source) is not dict:
                    raise ValueError('geoip_campaign_sources_invalid')
                geography = self.lookup(source.get('ip'))
                source['geographie'] = geography['status']
                source['geolocalisation'] = geography
            campaign['geographie_etablit_identite_commune'] = False
            campaign['geographie_declenche_blocage'] = False
        output['geoip'] = {'source': dict(self.source), 'limits': list(LIMITS), 'network_request': False}
        if len(json.dumps(output, ensure_ascii=False, allow_nan=False).encode()) > MAX_REPORT_BYTES:
            raise ValueError('geoip_campaign_output_too_large')
        return output
