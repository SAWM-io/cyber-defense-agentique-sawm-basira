"""Import local DB-IP Country Lite et validation sans connexion aux IP testées.

Le téléchargement est séparé et effectué par l'opérateur depuis l'URL officielle.
Le fichier dérivé ne modifie aucun code pays ; il ajoute seulement un index local.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from invite.agent_labo.geoip_context import GeoIPContext, PROVIDER, SOURCE_URL, LICENSE_URL, _sha
from invite.agent_labo.auth_campaigns import campagnes_auth

DEFAULT_DIR = ROOT / 'releves/geoip'
PUBLIC_EXAMPLES = [
    {'ip':'8.8.8.8', 'source':'https://db-ip.com/db/format/ip-to-country-lite/csv.html'},
    {'ip':'8.8.4.4', 'source':'https://developers.google.com/speed/public-dns/docs/using'},
    {'ip':'2001:4860:4860::8888', 'source':'https://developers.google.com/speed/public-dns/docs/using'},
    {'ip':'1.1.1.1', 'source':'https://developers.cloudflare.com/1.1.1.1/ip-addresses/'},
    {'ip':'2606:4700:4700::1111', 'source':'https://developers.cloudflare.com/1.1.1.1/ip-addresses/'},
]


def import_csv(archive, database, manifest, *, release, download_url, expected_source_sha1=None):
    if not re.fullmatch(r'[0-9]{4}-[0-9]{2}', release):
        raise ValueError('release_invalid')
    datetime.date.fromisoformat(release+'-01')
    if download_url != f'https://download.db-ip.com/free/dbip-country-lite-{release}.csv.gz':
        raise ValueError('official_download_required')
    archive, database, manifest = Path(archive), Path(database), Path(manifest)
    if not 0 < archive.stat().st_size <= 16*1024*1024:
        raise ValueError('archive_size_invalid')
    database.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.dbip-', suffix='.sqlite', dir=database.parent)
    os.close(fd)
    tmp = Path(tmp_name)
    connection = None
    try:
        connection = sqlite3.connect(tmp)
        connection.execute('PRAGMA journal_mode=OFF')
        connection.execute('CREATE TABLE ranges (version INTEGER NOT NULL, first_ip BLOB NOT NULL, '
                           'last_ip BLOB NOT NULL, country TEXT NOT NULL, PRIMARY KEY(version, first_ip)) WITHOUT ROWID')
        connection.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID')
        digest, sha1, size, count, previous, batch = hashlib.sha256(), hashlib.sha1(), 0, 0, {}, []
        with gzip.open(archive, 'rb') as stream:
            for line in iter(lambda: stream.readline(201), b''):
                size += len(line)
                if size > 70*1024*1024 or len(line) > 200:
                    raise ValueError('source_size_limit')
                digest.update(line); sha1.update(line)
                fields = next(csv.reader([line.decode('utf-8')]))
                if len(fields) != 3:
                    raise ValueError('source_row_invalid')
                first, last = ipaddress.ip_address(fields[0]), ipaddress.ip_address(fields[1])
                country = fields[2]
                if (first.version != last.version or first > last or
                    not re.fullmatch(r'[A-Z]{2}', country) or
                    first.version in previous and int(first) <= previous[first.version]):
                    raise ValueError('source_range_invalid')
                previous[first.version] = int(last)
                count += 1
                if count > 2000000:
                    raise ValueError('source_record_limit')
                batch.append((first.version, first.packed, last.packed, country))
                if len(batch) >= 4096:
                    connection.executemany('INSERT INTO ranges VALUES (?,?,?,?)', batch)
                    batch.clear()
        if batch:
            connection.executemany('INSERT INTO ranges VALUES (?,?,?,?)', batch)
        if expected_source_sha1 and sha1.hexdigest() != expected_source_sha1:
            raise ValueError('published_source_checksum_mismatch')
        if count == 0:
            raise ValueError('source_empty')
        metadata = {'release':release, 'source_sha256':digest.hexdigest(), 'records':str(count)}
        connection.executemany('INSERT INTO metadata VALUES (?,?)', metadata.items())
        connection.commit()
        if connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('database_check_failed')
        connection.close(); connection = None
        source = {'schema':'sawm-dbip-country-manifest/v1', 'provider':PROVIDER,
            'release':release, 'source_url':SOURCE_URL, 'download_url':download_url,
            'downloaded_archive_sha256':_sha(archive), 'source_sha256':digest.hexdigest(),
            'source_sha1':sha1.hexdigest(), 'published_sha1_verified':bool(expected_source_sha1),
            'database_sha256':_sha(tmp), 'records':count, 'source_bytes':size,
            'license':'CC-BY-4.0', 'license_url':LICENSE_URL,
            'attribution':{'text':'IP Geolocation by DB-IP', 'url':'https://db-ip.com'},
            'modified':'CSV importé dans un index SQLite ; codes pays conservés.',
            'prepared_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
        os.replace(tmp, database)
        fd, mname = tempfile.mkstemp(prefix='.dbip-manifest-', dir=manifest.parent)
        with os.fdopen(fd, 'w') as stream:
            json.dump(source, stream, ensure_ascii=False, indent=2); stream.write('\n')
        os.replace(mname, manifest)
        return source
    finally:
        if connection is not None:
            connection.close()
        tmp.unlink(missing_ok=True)


def validate(database, manifest):
    started = time.monotonic()
    reader = GeoIPContext(database, manifest)
    loading_ms = round((time.monotonic()-started)*1000, 3)
    public, excluded = [], []
    for example in PUBLIC_EXAMPLES:
        started = time.monotonic()
        result = reader.lookup(example['ip'])
        public.append({'documented_ip':example, 'result':result,
                       'lookup_ms':round((time.monotonic()-started)*1000, 3),
                       'passed':result['status'] == 'approximatif' and result['country_code'] is not None})
    for ip in ('127.0.0.1','10.2.3.4','100.64.0.1','192.168.64.2','198.51.100.42',
               '203.0.113.7','224.0.0.1','2001:db8::1','fc00::1','::ffff:10.1.2.3'):
        result = reader.lookup(ip)
        excluded.append({'ip':ip, 'status':result['status'], 'country_code':result['country_code'],
                         'passed':result['status'] == 'non_localisable' and result['country_code'] is None})
    now_ms = int(time.time()*1000)
    # Fiction explicite : aucun de ces résolveurs n'a attaqué le laboratoire.
    synthetic = [{'schema':'sawm-auth-observation/v1', 'observed_ms':now_ms,
                  'source_ip':ip, 'username_label':'demo-cto','endpoint':'/login',
                  'outcome':'rejected','failures_in_window':3} for ip in ('8.8.8.8','1.1.1.1')]
    before = campagnes_auth(synthetic, maintenant_ms=now_ms)
    after = reader.enrich_campaigns(before)
    campaign_passed = (len(after['campagnes']) == 1
        and after['campagnes'][0]['recommandation'] == before['campagnes'][0]['recommandation'] == 'signaler'
        and after['campagnes'][0]['priorite'] == before['campagnes'][0]['priorite']
        and after['campagnes'][0]['ip_a_bloquer'] == []
        and after['campagnes'][0]['identite_commune_etablie'] is False
        and all(row['geolocalisation']['status'] == 'approximatif' for row in after['campagnes'][0]['sources']))
    result = {'schema':'sawm-geoip-local-validation/v1', 'observed_ms':now_ms,
        'status':'passed' if all(row['passed'] for row in public+excluded) and campaign_passed else 'failed',
        'source':reader.source, 'load_ms':loading_ms, 'public_examples':public,
        'excluded_examples':excluded,
        'campaign_fixture':{'synthetic':True,'no_attack_occurred':True,'passed':campaign_passed,
                            'diagnostic':after},
        'network_requests_to_tested_ips':0,
        'claims':['Lecture effective de la base publique licenciée, sur cinq exemples documentés.',
                  'Cela ne valide pas leur emplacement physique ni la localisation d’un attaquant.',
                  'Les observations multi-IP de cette validation sont fictives ; aucun résolveur n’a attaqué.']}
    reader.close()
    if len(json.dumps(result,ensure_ascii=False,allow_nan=False).encode()) > 65536:
        raise ValueError('validation_output_limit')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=DEFAULT_DIR/'dbip-country.sqlite')
    parser.add_argument('--manifest', type=Path, default=DEFAULT_DIR/'manifest.json')
    parser.add_argument('--prepare', type=Path, help='Archive CSV.gz locale, déjà téléchargée depuis DB-IP.')
    parser.add_argument('--release', default='2026-09')
    parser.add_argument('--published-sha1', default='2d99eae57714d39e7670a12985ae3083f8df807b')
    parser.add_argument('--output', type=Path, default=ROOT/'releves/rapports/validation-geoip-local-20260924.json')
    args = parser.parse_args()
    if args.prepare:
        import_csv(args.prepare, args.database, args.manifest, release=args.release,
            download_url=f'https://download.db-ip.com/free/dbip-country-lite-{args.release}.csv.gz',
            expected_source_sha1=args.published_sha1)
    report = validate(args.database, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'status':report['status'],'path':str(args.output),'release':report['source'].get('release'),
        'public_examples':len(report['public_examples']),'excluded_examples':len(report['excluded_examples']),
        'database_sha256':report['source'].get('database_sha256'),'network_requests_to_tested_ips':0}))


if __name__ == '__main__':
    main()
