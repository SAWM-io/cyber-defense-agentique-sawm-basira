"""Explicit offline import of official ClamAV CVD files; never downloads.

Run as root only during a scanner maintenance window. Inputs may be mutable
staging files: bounded stable copies are verified without privilege/network,
then atomically promoted as one directory. Old definitions remain preserved.
"""
from __future__ import annotations
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

BASE=Path('/opt/sawm-labo')
DESTINATION=BASE/'av-signatures'
RELEASES=BASE/'signature-releases'
SIGTOOL=BASE/'tools/clamav/usr/local/bin/sigtool'
LIBRARY=BASE/'tools/clamav/usr/local/lib'
CERTIFICATES=BASE/'tools/clamav/usr/local/etc/certs'
NAMES=('main','daily','bytecode')
DAILY_MAX_AGE=7*86400


class ImportRefused(ValueError):pass


def header(raw):
    try:
        fields=raw[:512].decode('ascii').strip().split(':')
        if len(fields)!=9 or fields[0]!='ClamAV-VDB':raise ValueError()
        result={'version':int(fields[2]),'signatures':int(fields[3]),'published_epoch':int(fields[8])}
        if any(type(v) is not int or v<=0 for v in result.values()):raise ValueError()
        return result
    except (ValueError,UnicodeDecodeError):raise ImportRefused('invalid_cvd_header') from None


def check_publication(name, metadata, *, now):
    age=now-metadata['published_epoch']
    if age<0 or name=='daily' and age>DAILY_MAX_AGE:
        raise ImportRefused('signature_publication_future_or_stale')


def trusted_directory(path):
    path=Path(path)
    if path.resolve()!=path or any(x.is_symlink() for x in (path,*path.parents)):
        raise ImportRefused('trusted_directory_is_symbolic')
    info=path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
        raise ImportRefused('trusted_directory_not_root_protected')


def open_directory(path):
    """Hold each directory component, never follow a replaced parent symlink."""
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ImportRefused('staging_path_invalid')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        return fd
    except Exception:os.close(fd);raise


def stable_copy(directory_fd,name,destination,*,limit):
    if not re.fullmatch(r'(?:main|daily|bytecode)(?:-\d+)?\.cvd(?:\.sign)?',name):
        raise ImportRefused('signature_filename_invalid')
    source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
    with os.fdopen(source,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=limit:
            raise ImportRefused('signature_input_not_bounded_regular')
        digest=hashlib.sha256();size=0
        with open(destination,'xb') as output:
            while block:=stream.read(1024*1024):
                size+=len(block)
                if size>limit:raise ImportRefused('signature_input_grew')
                output.write(block);digest.update(block)
            output.flush();os.fsync(output.fileno())
        after=os.fstat(stream.fileno());current=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
        identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        if identity(before)!=identity(after) or identity(before)!=identity(current):
            raise ImportRefused('signature_input_changed')
    Path(destination).chmod(0o444)
    return {'sha256':digest.hexdigest(),'bytes':size}


def verification_command(path,mode):
    if mode not in ('--verify','--info'):raise ImportRefused('verification_mode_invalid')
    args=['systemd-run','--quiet','--wait','--pipe','--collect',
          '--unit=labo-signature-check-'+uuid.uuid4().hex[:12]+'.service',
          '--setenv=LD_LIBRARY_PATH='+str(LIBRARY),
          '--setenv=CVD_CERTS_DIR='+str(CERTIFICATES),'--setenv=LC_ALL=C']
    settings={'DynamicUser':'yes','PrivateNetwork':'yes','PrivateTmp':'yes',
              'NoNewPrivileges':'yes','CapabilityBoundingSet':'','ProtectSystem':'strict',
              'ProtectHome':'yes','PrivateDevices':'yes','RestrictAddressFamilies':'AF_UNIX',
              'MemoryMax':'512M','CPUQuota':'75%','TasksMax':'16','RuntimeMaxSec':'60'}
    for key,value in settings.items():args+=['-p',key+'='+value]
    return args+[str(SIGTOOL),mode,str(path)]


def verify_copy(path,metadata,*,runner=subprocess.run):
    verified=runner(verification_command(path,'--verify'),capture_output=True,text=True,timeout=70)
    if (verified.returncode!=0 or 'Successfully verified' not in verified.stdout
            or 'ClamAV_datafiles_release' not in verified.stdout):
        raise ImportRefused('official_external_signature_not_verified')
    info=runner(verification_command(path,'--info'),capture_output=True,text=True,timeout=70)
    version=re.search(r'^Version:\s*(\d+)\s*$',info.stdout,re.M)
    count=re.search(r'^Signatures:\s*(\d+)\s*$',info.stdout,re.M)
    if (info.returncode!=0 or 'Verification OK' not in info.stdout or not version or not count
            or int(version[1])!=metadata['version'] or int(count[1])!=metadata['signatures']):
        raise ImportRefused('cvd_info_or_embedded_verification_invalid')
    return {'external_signature_verified':True,'embedded_verification_ok':True,
            'signer':'ClamAV_datafiles_release','verification_network':'disabled'}


def no_rollback(previous,current):
    if current['version']<previous['version']:
        raise ImportRefused('signature_version_rollback')
    if current['version']==previous['version'] and current['sha256']!=previous['sha256']:
        raise ImportRefused('same_version_changed_content')


def atomic_promote(prepared,destination):
    """Linux renameat2 exchange keeps the old directory as an evidence copy."""
    if not destination.exists():
        os.rename(prepared,destination);return None
    trusted_directory(destination)
    library=ctypes.CDLL(None,use_errno=True)
    exchange=getattr(library,'renameat2',None)
    if exchange is None:raise ImportRefused('atomic_directory_exchange_unavailable')
    exchange.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    exchange.restype=ctypes.c_int
    if exchange(-100,os.fsencode(prepared),-100,os.fsencode(destination),2)!=0:
        raise OSError(ctypes.get_errno(),'atomic_directory_exchange_failed')
    return str(prepared)


def import_offline(staging,*,now=None):
    if os.geteuid()!=0:raise ImportRefused('root_import_controller_required')
    now=time.time() if now is None else now
    trusted_directory(BASE)
    RELEASES.mkdir(mode=0o755,exist_ok=True);trusted_directory(RELEASES)
    lock=os.open(RELEASES/'.import.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        prepared=RELEASES/('release-'+str(int(now))+'-'+uuid.uuid4().hex[:12])
        prepared.mkdir(mode=0o700)
        directory_fd=open_directory(staging)
        rows=[]
        try:
            for name in NAMES:
                copied=stable_copy(directory_fd,name+'.cvd',prepared/(name+'.cvd'),limit=256*1024**2)
                with (prepared/(name+'.cvd')).open('rb') as file:metadata=header(file.read(512))
                signature=name+'-'+str(metadata['version'])+'.cvd.sign'
                signed=stable_copy(directory_fd,signature,prepared/signature,limit=1024**2)
                rows.append({'name':name+'.cvd',**metadata,**copied,'signature_file':signature,
                             'signature_sha256':signed['sha256']})
        finally:os.close(directory_fd)
        # Root-owned and read-only; definitions are public. This permits the
        # unprivileged verifier to read the stable copy, never mutable staging.
        prepared.chmod(0o755)
        for row in rows:
            row.update(verify_copy(prepared/row['name'],row))
            check_publication(row['name'].split('.')[0],row,now=now)
        if DESTINATION.exists():
            trusted_directory(DESTINATION)
            present=[name for name in NAMES if (DESTINATION/(name+'.cvd')).exists()]
            if present and len(present)!=len(NAMES):raise ImportRefused('previous_generation_incomplete')
            oldfd=open_directory(DESTINATION)
            try:
                for row in rows if present else []:
                    # Reuse bounded stable reads for the existing generation;
                    # temporary copies are kept outside the next active set.
                    previous_path=RELEASES/('.previous-'+uuid.uuid4().hex)
                    try:
                        prior=stable_copy(oldfd,row['name'],previous_path,limit=256*1024**2)
                        with previous_path.open('rb') as file:prior.update(header(file.read(512)))
                        no_rollback(prior,row)
                    finally:previous_path.unlink(missing_ok=True)
            finally:os.close(oldfd)
        manifest={'schema':'sawm-offline-signature-import/v1','approved_at_ms':int(now*1000),
                  'source':'explicit_offline_staging','databases':rows,'network_used':False,
                  'publication_freshness_source':'verified_CVD_header_epoch','daily_max_age_seconds':DAILY_MAX_AGE,
                  'maintenance_required':'no scanner may run during promotion'}
        manifest_path=prepared/'import-manifest.json'
        with manifest_path.open('x') as file:
            file.write(json.dumps(manifest,indent=2)+'\n');file.flush();os.fsync(file.fileno())
        manifest_path.chmod(0o444)
        prior=atomic_promote(prepared,DESTINATION)
        for parent in (DESTINATION.parent,RELEASES):
            directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        return {**manifest,'promoted':True,'destination':str(DESTINATION),
                'previous_generation_preserved':prior,'automatic_update_scheduled':False}
    finally:os.close(lock)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging',type=Path,required=True)
    parser.add_argument('--maintenance-window',action='store_true',required=True)
    args=parser.parse_args()
    print(json.dumps(import_offline(args.staging),ensure_ascii=False))
