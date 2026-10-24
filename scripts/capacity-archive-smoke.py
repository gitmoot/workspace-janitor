#!/usr/bin/env python3
"""Exact synthetic export: live reader/queue holds, archive, expiry, real restore."""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

p=argparse.ArgumentParser()
p.add_argument('binary',type=Path)
p.add_argument('receipt',type=Path)
a=p.parse_args()
binary=str(a.binary.resolve())
result={'binary':binary,'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),'production_mutation':False}
with tempfile.TemporaryDirectory(prefix='janitor-report-archive70-') as temporary:
    home=Path(temporary)
    source_root=home/'completed-exports'
    archive=home/'retained-archives'
    proc=home/'proc'
    services=home/'services'
    unrelated=home/'unrelated-project'
    policy=home/'.config/workspace-janitor/policy.yaml'
    ledger=home/'.gitmoot/gitmoot.db'
    for directory in [source_root,archive,proc,services,unrelated,policy.parent,ledger.parent]: directory.mkdir(parents=True,exist_ok=True)
    source=source_root/'completed.json'
    protected=source_root/'.env'
    payload=(b'{"evidence":"synthetic-completed-report"}\n'*1024)
    source.write_bytes(payload)
    source.chmod(0o640)
    modified_ns=time.time_ns()-32*24*3600*10**9
    os.utime(source,ns=(modified_ns,modified_ns))
    protected.write_bytes(b'SYNTHETIC_PROTECTED_CREDENTIAL_MARKER\n')
    protected_hash=hashlib.sha256(protected.read_bytes()).hexdigest()
    source_stat=source.stat()
    completion=(datetime.now(timezone.utc)-timedelta(days=31)).isoformat()
    env={k:v for k,v in os.environ.items() if not k.startswith(('JANITOR_','XDG_'))}
    env['HOME']=str(home)
    binding={}
    def configure():
        bound=''
        if binding:
            bound='      manifest: '+json.dumps(binding['manifest'])+'\n      manifest_sha256: '+binding['manifest_sha256']+'\n'
        policy.write_text(f'''roots:
  - path: {source_root}
    max_depth: 1
protect:
  paths: [{archive}]
collectors:
  git: true
  processes: true
  services: true
  proc_root: {proc}
  systemd_dirs: [{services}]
  cron_paths: []
  pm2_dumps: []
retention:
  default: none
  delete_enabled: true
prevention:
  min_free_bytes: 0
  min_free_percent: 0
limits:
  command_timeout: 30s
evidence_exports:
  - name: completed-report
    class: completed_report
    path: {source}
    owner: isolated-fixture
    approval: synthetic-completion-approval
    completed_at: {completion}
    credential_free: true
    source_container: {source_root}
    source_lifetime: completed-fixture-job
    local_retention: 30d
    local_expiry_enabled: true
    max_bytes: 8388608
    archive:
      directory: {archive}
      owner: isolated-archive-owner
      approval: synthetic-destination-approval
      lifetime: retained-beyond-source-container
      retention: permanent
      delete_enabled: false
{bound}''')
    def run(*args,ok=True):
        completed=subprocess.run([binary,'--format','json',*args],env=env,cwd=unrelated,text=True,capture_output=True,timeout=60)
        assert (completed.returncode==0)==ok, (args,completed.returncode,completed.stdout,completed.stderr)
        if not ok: return {'exit':completed.returncode,'stderr':completed.stderr,'stdout':completed.stdout}
        return json.loads(completed.stdout)['data']
    def available():
        stat=os.statvfs(home)
        return stat.f_bavail*stat.f_frsize
    def allocated_tree(path):
        return sum(item.stat().st_blocks*512 for item in [path,*path.rglob('*')])
    db=sqlite3.connect(ledger)
    db.executescript('CREATE TABLE jobs(id TEXT,state TEXT,payload TEXT,updated_at TEXT); CREATE TABLE tasks(state TEXT,worktree_path TEXT); CREATE TABLE cleanup_obligations(owner_job_id TEXT,expected_path TEXT,resource_kind TEXT,state TEXT,created_at TEXT,updated_at TEXT);')
    db.commit()
    configure()
    run('scan')
    result['preview']=run('archive','--rule','completed-report')
    reader=subprocess.Popen([sys.executable,'-c','import sys,time; f=open(sys.argv[1],"rb"); print("ready",flush=True); time.sleep(120)',str(source)],cwd=unrelated,stdout=subprocess.PIPE,text=True,env=env)
    try:
        assert reader.stdout.readline().strip()=='ready'
        (proc/str(reader.pid)).symlink_to(Path('/proc')/str(reader.pid))
        result['live_descriptor_hold']=run('archive','--rule','completed-report','--dry-run=false','--confirm',ok=False)
        assert reader.poll() is None
        assert source.read_bytes()==payload
    finally:
        reader.terminate()
        reader.wait(timeout=10)
        (proc/str(reader.pid)).unlink(missing_ok=True)
    db.execute("INSERT INTO jobs VALUES('future-reader','queued','{}','2026-10-24 00:00:00')")
    db.commit()
    result['queued_user_hold']=run('archive','--rule','completed-report','--dry-run=false','--confirm',ok=False)
    assert source.read_bytes()==payload
    db.execute("UPDATE jobs SET state='succeeded'")
    db.commit()
    archive_before=allocated_tree(archive)
    result['available_before_archive_bytes']=available()
    result['archived']=run('archive','--rule','completed-report','--dry-run=false','--confirm')
    binding=result['archived']['binding']
    configure()
    assert source.read_bytes()==payload
    run('scan')
    planned=run('plan','--no-jev')['plan']
    selected=next(action for action in planned['actions'] if action['path']==str(source))
    assert selected['kind']=='quarantine',selected
    protected_action=next(action for action in planned['actions'] if action['path']==str(protected))
    assert protected_action['kind']=='keep',protected_action
    run('plan','--plan',planned['id'],'--approve',selected['id'],'--no-jev')
    result['quarantined']=run('apply','--quarantine','--action',selected['id'],'--dry-run=false','--confirm')
    receipt=next(item for item in result['quarantined']['items'] if item['source']==str(source))
    archive_payload=Path(binding['manifest']).parent/'content.gz'
    original=archive_payload.read_bytes()
    damaged=bytearray(original)
    damaged[4]^=1
    archive_payload.write_bytes(damaged)
    result['corrupt_archive_hold']=run('apply','--expire','--cleanup',receipt['cleanup_id'],'--dry-run=false','--confirm',ok=False)
    assert Path(receipt['destination']).read_bytes()==payload
    archive_payload.write_bytes(original)
    result['expired']=run('apply','--expire','--cleanup',receipt['cleanup_id'],'--dry-run=false','--confirm')
    assert not source.exists() and not Path(receipt['destination']).exists()
    result['available_after_expiry_bytes']=available()
    result['source_allocated_bytes']=source_stat.st_blocks*512
    result['incremental_archive_allocated_bytes']=allocated_tree(archive)-archive_before
    result['scoped_net_reclaimed_bytes']=result['source_allocated_bytes']-result['incremental_archive_allocated_bytes']
    result['accounting_limit']='Scoped net excludes Janitor ledger/receipt growth; filesystem delta includes all concurrent writers. Same-filesystem copying alone is not reclaim.'
    assert result['scoped_net_reclaimed_bytes']>0
    assert hashlib.sha256(protected.read_bytes()).hexdigest()==protected_hash
    retained_marker=home/'retained-protected-marker'
    protected.rename(retained_marker)
    source_root.rmdir()
    restored=home/'restored.json'
    result['restored']=run('archive','--rule','completed-report','--restore-to',str(restored),'--dry-run=false','--confirm')
    assert restored.read_bytes()==payload
    restored_stat=restored.stat()
    assert (restored_stat.st_mode&0o777,restored_stat.st_uid,restored_stat.st_gid,restored_stat.st_mtime_ns)==(0o640,source_stat.st_uid,source_stat.st_gid,modified_ns)
    assert archive_payload.read_bytes()==original
    assert hashlib.sha256(retained_marker.read_bytes()).hexdigest()==protected_hash
    result['restore_verified']={'sha256':hashlib.sha256(payload).hexdigest(),'mode':'0640','uid':restored_stat.st_uid,'gid':restored_stat.st_gid,'mtime_ns':restored_stat.st_mtime_ns,'original_container_absent':not source_root.exists(),'source_container_removed':True,'archive_survived_source_container_removal':True}
    history=run('status')['inventory_report']['activities']
    result['operation_history']=history
    assert any(event['kind']=='expiry' and event['state']=='failed' and event['errors'] for event in history)
    assert any(event['kind']=='expiry' and event['state']=='completed' and event['completed']==1 and event['actual_reclaimed_bytes'] is None for event in history)
    for kind in ['verified_archive','quarantine','archive_restore']:
        event=next(event for event in history if event['kind']==kind and event['state']=='completed')
        assert event['actual_reclaimed_bytes']==0, event
    for index in range(257):
        destination=home/'bounded-report-restore'
        run('archive','--rule','completed-report','--restore-to',str(destination),'--dry-run=false','--confirm')
        assert hashlib.sha256(destination.read_bytes()).digest()==hashlib.sha256(payload).digest()
        destination.unlink()
    bounded=run('status')['inventory_report']
    assert len(bounded['activities'])==bounded['activity_history_limit']==256
    assert all(event['kind']=='archive_restore' and event['state']=='completed' for event in bounded['activities'])
    state_db=home/'.local/state/workspace-janitor/janitor.db'
    with sqlite3.connect(state_db) as report_db:
        rows=report_db.execute('SELECT count(*) FROM capacity_activity').fetchone()[0]
        assert rows==256
    result['bounded_history']={'rows':rows,'restores_exercised':257,'all_completed':True,'authoritative_archive_still_verified':run('archive','--rule','completed-report','--verify')['status']}
    db.close()
a.receipt.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'receipt':str(a.receipt),'scoped_net_reclaimed_bytes':result['scoped_net_reclaimed_bytes'],'restore_verified':result['restore_verified'],'production_mutation':False},indent=2))
