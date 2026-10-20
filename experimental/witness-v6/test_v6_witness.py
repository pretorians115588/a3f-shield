import hashlib, os, secrets, sqlite3, threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from witness_v6 import WitnessStore,WitnessError,verify_receipt

K = secrets.token_bytes(32)
S = secrets.token_bytes(32)

def test_v6_idempotent_registration_and_signed_verification(tmp_path):
    doc=secrets.token_bytes(16); d=hashlib.sha256(b'example').digest()
    with WitnessStore(tmp_path/'state.sqlite',K,S) as w:
        seq=w.register(doc,1,d)
        assert w.register(doc,1,d)==seq
        challenge=secrets.token_bytes(32)
        receipt=w.verify(doc,1,d,challenge=challenge)
        assert verify_receipt(receipt,w.public_key(),doc=doc,generation=1,digest=d,challenge=challenge)==1
        assert w.audit()['events']==1
        with pytest.raises(WitnessError):w.register(doc,1,bytes(32))

def test_v6_valid_old_ciphertext_rejected_and_floor_check(tmp_path):
    doc=secrets.token_bytes(16);d1=secrets.token_bytes(32);d2=secrets.token_bytes(32)
    with WitnessStore(tmp_path/'state.sqlite',K,S) as w:
        w.register(doc,1,d1);w.register(doc,2,d2)
        with pytest.raises(WitnessError):w.verify(doc,1,d1,challenge=secrets.token_bytes(32))
        with pytest.raises(WitnessError):w.verify(doc,2,d2,challenge=secrets.token_bytes(32),min_checkpoint=3)
        assert w.audit()['events']==2

def test_v6_challenge_signature_splicing_and_checkpoint(tmp_path):
    doc=secrets.token_bytes(16);d=secrets.token_bytes(32)
    with WitnessStore(tmp_path/'db',K,S) as w:
        w.register(doc,1,d);c=secrets.token_bytes(32);r=w.verify(doc,1,d,challenge=c)
        pub=w.public_key()
        with pytest.raises(WitnessError):verify_receipt(r,pub,doc=doc,generation=1,digest=d,challenge=secrets.token_bytes(32))
        with pytest.raises(WitnessError):verify_receipt(r,pub,doc=doc,generation=1,digest=d,challenge=c,min_checkpoint=2)
        r['record']['digest']='00'*32
        with pytest.raises(WitnessError):verify_receipt(r,pub,doc=doc,generation=1,digest=d,challenge=c)

def test_v6_tampered_ledger_is_detected(tmp_path):
    doc=secrets.token_bytes(16);d=secrets.token_bytes(32);db=tmp_path/'db'
    with WitnessStore(db,K,S) as w:w.register(doc,1,d)
    con=sqlite3.connect(db);con.execute('UPDATE log SET digest=?',(bytes(32),));con.commit();con.close()
    with WitnessStore(db,K,S) as w:
        with pytest.raises(WitnessError):w.audit()
        with pytest.raises(WitnessError):w.verify(doc,1,d,challenge=secrets.token_bytes(32))

def test_v6_selective_head_rollback_is_rejected_before_receipt(tmp_path):
    """A stale unsigned head row must never authorize an old log record."""
    doc=secrets.token_bytes(16);d1=secrets.token_bytes(32);d2=secrets.token_bytes(32)
    db=tmp_path/'db'
    with WitnessStore(db,K,S) as w:
        w.register(doc,1,d1);w.register(doc,2,d2)
    con=sqlite3.connect(db)
    con.execute('UPDATE heads SET seq=1,gen=1,digest=? WHERE doc=?',(d1,doc));con.commit();con.close()
    with WitnessStore(db,K,S) as w:
        with pytest.raises(WitnessError):w.verify(doc,1,d1,challenge=secrets.token_bytes(32),min_checkpoint=2)

def test_v6_concurrent_writers_are_serialized(tmp_path):
    db=tmp_path/'db';doc=secrets.token_bytes(16);d1=secrets.token_bytes(32);d2=secrets.token_bytes(32)
    with WitnessStore(db,K,S) as w:w.register(doc,1,d1)
    def attempt(_):
        try:
            with WitnessStore(db,K,S) as w:return w.register(doc,2,d2)
        except Exception as e:return str(e)
    with ThreadPoolExecutor(max_workers=8) as pool:
        attempts=list(pool.map(attempt,range(20)))
    assert len(set(attempts))==1 and isinstance(attempts[0],int)
    with WitnessStore(db,K,S) as w:assert w.audit()['events']==2

def test_v6_whole_snapshot_rollback_limitation_is_explicit(tmp_path):
    db=tmp_path/'db';doc=secrets.token_bytes(16);d1=secrets.token_bytes(32);d2=secrets.token_bytes(32)
    with WitnessStore(db,K,S) as w:w.register(doc,1,d1)
    import shutil
    snap=tmp_path/'snapshot'
    src=sqlite3.connect(db);dest=sqlite3.connect(snap)
    try:src.backup(dest)
    finally:src.close();dest.close()
    with WitnessStore(db,K,S) as w:w.register(doc,2,d2)
    # Remove WAL sidecars when restoring a whole on-disk snapshot.
    # (Both state and sidecars are attacker controlled under this test model.)
    for ext in ('-wal','-shm'):
        sidecar = db.with_name(db.name+ext)
        sidecar.unlink(missing_ok=True)
    shutil.copy2(snap,db)
    with WitnessStore(db,K,S) as w:
        assert w.audit()['events']==1
        c=secrets.token_bytes(32)
        r=w.verify(doc,1,d1,challenge=c)
        with pytest.raises(WitnessError):verify_receipt(r,w.public_key(),doc=doc,generation=1,digest=d1,challenge=c,min_checkpoint=2)
