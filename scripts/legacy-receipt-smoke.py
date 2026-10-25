#!/usr/bin/env python3
"""Temporary hosted instrument: real old quarantine -> new expiry on isolated stores."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

OLD = '5ee52f74f6ce6eac6f6f0fc2f094d7dd16036e46'
BROKEN = '172e82e8c6a44a76df806f3c98dcf130f6eaea08'
SOURCE = r'''//go:build linux

package action

import (
    "context"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/gitmoot/workspace-janitor/internal/collect"
    "github.com/gitmoot/workspace-janitor/internal/core"
    "github.com/gitmoot/workspace-janitor/internal/safety"
    "github.com/gitmoot/workspace-janitor/internal/store"
)

func TestCrossVersionReceiptSmoke(t *testing.T) {
    for _, scenario := range []string{"unchanged", "edited", "replaced", "activity", "active"} {
        t.Run(scenario, func(t *testing.T) {
            base := filepath.Join(os.Getenv("LEGACY_SMOKE_HOME"), scenario)
            root, state := filepath.Join(base,"root"), filepath.Join(base,"state")
            proc, units := filepath.Join(base,"proc"), filepath.Join(base,"units")
            for _, path := range []string{root,state,proc,units} {
                if err := os.MkdirAll(path,0700); err != nil { t.Fatal(err) }
            }
            ctx := context.Background()
            db, err := store.Open(ctx,filepath.Join(state,"janitor.db"))
            if err != nil { t.Fatal(err) }; defer db.Close()
            quarantine := filepath.Join(state,"quarantine")
            now := time.Now().UTC()
            e := &Engine{DB:db,QuarantineDir:quarantine,
                Policy:safety.Policy{StateDir:state,QuarantineDir:quarantine,ProtectedPaths:[]string{state,quarantine}},
                Collect:collect.Options{Git:true,Processes:true,Services:true,ProcRoot:proc,ServiceSources:collect.ServiceSources{SystemdDirs:[]string{units}},
                    Limits:collect.Limits{GitTimeout:5*time.Second,CommandTimeout:5*time.Second,MaxEntries:300,MaxDirEntries:300,DeepSizeMaxEntries:300,DeepSizeMaxDepth:5}},
                Now:func() time.Time{return now}}
            receiptPath := filepath.Join(base,"old-receipt.json")
            if os.Getenv("LEGACY_SMOKE_PHASE")=="produce" {
                source, remote := filepath.Join(root,"repo"), filepath.Join(base,"remote.git")
                if err := os.Mkdir(source,0700); err != nil {t.Fatal(err)}
                if err := os.Mkdir(remote,0700); err != nil {t.Fatal(err)}
                fixtureGit(t,base,source,"init")
                if err := os.WriteFile(filepath.Join(source,"README"),[]byte("retained payload\n"),0600); err != nil {t.Fatal(err)}
                fixtureGit(t,base,source,"add","README")
                fixtureGit(t,base,source,"commit","-m","fixture")
                fixtureGit(t,base,remote,"init","--bare")
                fixtureGit(t,base,source,"remote","add","origin",remote)
                fixtureGit(t,base,source,"push","-u","origin","HEAD")
                item := prepareFixture(t,e,source,core.Retention30Days)
                item,err = e.Quarantine(ctx,item)
                if err != nil {t.Fatal(err)}
                raw,err := json.Marshal(item); if err != nil {t.Fatal(err)}
                if err := os.WriteFile(receiptPath,raw,0600); err != nil {t.Fatal(err)}
                t.Logf("old receipt created: state=%s",item.State)
                return
            }
            raw,err := os.ReadFile(receiptPath); if err != nil {t.Fatal(err)}
            var original core.CleanupItem
            if err := json.Unmarshal(raw,&original); err != nil {t.Fatal(err)}
            // Read the actual persisted receipt, not an in-memory replacement.
            items,err := e.Items(ctx,original.CleanupID)
            if err != nil || len(items)!=1 {t.Fatalf("receipt load: %v %+v",err,items)}
            item := items[0]
            now = item.MovedAt.Add(31*24*time.Hour)
            switch scenario {
            case "edited":
                if err := os.WriteFile(filepath.Join(item.Destination,"README"),[]byte("new unpublished payload\n"),0600); err != nil {t.Fatal(err)}
            case "replaced":
                if err := os.Rename(item.Destination,item.Destination+"-original"); err != nil {t.Fatal(err)}
                if err := os.Mkdir(item.Destination,0700); err != nil {t.Fatal(err)}
            case "activity":
                changed := item.Quarantined.Git.LastActivity.Add(time.Minute)
                if err := os.Chtimes(filepath.Join(item.Destination,".git","index"),changed,changed); err != nil {t.Fatal(err)}
            case "active":
                pid := filepath.Join(proc,"123")
                if err := os.Mkdir(pid,0700); err != nil {t.Fatal(err)}
                if err := os.Symlink(item.Destination,filepath.Join(pid,"cwd")); err != nil {t.Fatal(err)}
            }
            result,err := e.Delete(ctx,item)
            if scenario=="unchanged" {
                if err != nil || result.State!=core.CleanupDeleted {t.Fatalf("unchanged old receipt cannot expire: %s %v",result.State,err)}
                if _,err := os.Lstat(item.Destination); !os.IsNotExist(err) {t.Fatal("expired object still present")}
            } else {
                if err==nil || result.State==core.CleanupDeleted {t.Fatalf("unsafe %s accepted: %+v %v",scenario,result,err)}
                if _,err := os.Lstat(item.Destination); err != nil {t.Fatalf("refused object removed: %v",err)}
                t.Logf("unsafe %s refused: %v",scenario,err)
            }
        })
    }
}
'''

root = Path.cwd()
output = Path(sys.argv[1]).resolve()
results = []
def run(tree, phase, home, expected):
    instrument = tree / 'internal/action/cross_version_smoke_test.go'
    assert not instrument.exists()
    instrument.write_text(SOURCE)
    try:
        env = dict(os.environ, LEGACY_SMOKE_HOME=str(home), LEGACY_SMOKE_PHASE=phase)
        cmd = ['go','test','-p','1','./internal/action','-v','-count=1','-run','^TestCrossVersionReceiptSmoke$']
        p = subprocess.run(cmd,cwd=tree,env=env,text=True,capture_output=True,timeout=180)
        results.append({'tree':str(tree),'phase':phase,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        assert (p.returncode==0)==expected, results[-1]
        if not expected:
            assert 'unchanged old receipt cannot expire' in p.stdout and 'identity_changed' in p.stdout,results[-1]
    finally:
        instrument.unlink()

with tempfile.TemporaryDirectory(prefix='janitor-legacy-') as temporary:
    base=Path(temporary)
    old,broken=base/'old',base/'broken'
    for tree,head in [(old,OLD),(broken,BROKEN)]:
        subprocess.run(['git','worktree','add','--detach',str(tree),head],check=True)
    try:
        # Separate real old-created stores: the broken consumer may journal a refusal.
        for consumer,label,expected in [(broken,'before',False),(root,'after',True)]:
            home=base/label
            run(old,'produce',home,True)
            run(consumer,'consume',home,expected)
    finally:
        for tree in [old,broken]: subprocess.run(['git','worktree','remove','--force',str(tree)],check=True)
output.write_text(json.dumps({'producer_head':OLD,'broken_head':BROKEN,'candidate_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'production_mutation':False,'results':results},indent=2)+'\n')
print('Old-produced receipts: broken consumer refuses unchanged; fixed consumer deletes unchanged and preserves edited/replaced/active/activity cases.')
