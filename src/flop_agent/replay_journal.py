"""Sealed offline replay ledger and side-effect journal; no effect adapter."""
from __future__ import annotations

import hashlib, hmac, json, os, re, secrets, sqlite3, threading, weakref
import stat as stat_module
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, Callable, Mapping

POLICY_VERSION="local-replay-side-effect-policy-v2"
SCHEMA_VERSION="replay-journal-v2"
VERIFIER_REVISION="replay-evidence-verifier-v1"
HEX64=re.compile(r"^[0-9a-f]{64}$")
SAFE_TEXT=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}$")
DECIMAL=re.compile(r"^(?:0|[1-9][0-9]*)$")
ACTION_CLASSES=frozenset({"SIGNED_ACTION","SIGNED_TEST_ACTION","FAUCET_CLAIM","INFERENCE_SPEND","PAYMENT","AGENT_TASK","REPUTATION_CREDIT"})

class ReplaySafetyError(ValueError):
    def __init__(self,code:str,field:str,reason:str):
        super().__init__(f"{code}: {field}: {reason}"); self.code=code
        self.metadata=MappingProxyType({"field":field,"reason":reason})
class ReplayState(str,Enum):
    OBSERVED="OBSERVED"; VALIDATED="VALIDATED"; REJECTED="REJECTED"
    REPLAY_IDENTITY_CONFLICT="REPLAY_IDENTITY_CONFLICT"; EFFECT_RESERVED="EFFECT_RESERVED"
    EFFECT_ATTEMPTED="EFFECT_ATTEMPTED"; EFFECT_CONFIRMED="EFFECT_CONFIRMED"
    EFFECT_FAILED_SAFE="EFFECT_FAILED_SAFE"; EFFECT_OUTCOME_UNKNOWN="EFFECT_OUTCOME_UNKNOWN"
class RetryClassification(str,Enum):
    SAFE_TO_RETRY="SAFE_TO_RETRY"; DO_NOT_RETRY="DO_NOT_RETRY"
    RECONCILIATION_REQUIRED="RECONCILIATION_REQUIRED"; HUMAN_REVIEW_REQUIRED="HUMAN_REVIEW_REQUIRED"
class EffectClass(str,Enum):
    FAUCET_CLAIM="FAUCET_CLAIM"; INFERENCE_SPEND="INFERENCE_SPEND"; PAYMENT="PAYMENT"
    AGENT_TASK="AGENT_TASK"; REPUTATION_CREDIT="REPUTATION_CREDIT"
class ConfirmationEvidenceType(str,Enum):
    LOCAL_NO_EFFECT_PROOF="LOCAL_NO_EFFECT_PROOF"; FAUCET_RESULT="FAUCET_RESULT"
    INFERENCE_RESULT="INFERENCE_RESULT"; RAIL_FINALITY="RAIL_FINALITY"
    READ_BACK_CONFIRMATION="READ_BACK_CONFIRMATION"; AGENT_TASK_RECEIPT="AGENT_TASK_RECEIPT"
    REPUTATION_RECEIPT="REPUTATION_RECEIPT"
class ReconciliationResult(str,Enum):
    NO_EXTERNAL_EFFECT="NO_EXTERNAL_EFFECT"; EXTERNAL_EFFECT_CONFIRMED="EXTERNAL_EFFECT_CONFIRMED"
class ReviewedEvidenceFixture(str,Enum):
    FAUCET_CONFIRMED="FAUCET_CONFIRMED"; INFERENCE_CONFIRMED="INFERENCE_CONFIRMED"
    PAYMENT_FINAL="PAYMENT_FINAL"; AGENT_TASK_CONFIRMED="AGENT_TASK_CONFIRMED"
    REPUTATION_CONFIRMED="REPUTATION_CONFIRMED"; RESERVED_NOT_INVOKED="RESERVED_NOT_INVOKED"
    READBACK_PROVES_ABSENCE="READBACK_PROVES_ABSENCE"; READBACK_PROVES_EFFECT="READBACK_PROVES_EFFECT"

@dataclass(frozen=True)
class CanonicalAction:
    actor_did:str; action_class:str; context:str; nonce:str
    signed_payload_sha256:str; signing_bytes_sha256:str; target:str; schema_version:str
    def __post_init__(self)->None:
        for field in ("actor_did","action_class","context","target","schema_version"):
            value=getattr(self,field)
            if not isinstance(value,str) or SAFE_TEXT.fullmatch(value) is None:
                raise ReplaySafetyError("IDENTIFIER_INVALID",field,"bounded exact text required")
        if not isinstance(self.nonce,str) or DECIMAL.fullmatch(self.nonce) is None:
            raise ReplaySafetyError("NONCE_INVALID","nonce","exact canonical decimal string required")
        for field in ("signed_payload_sha256","signing_bytes_sha256"):
            if not isinstance(getattr(self,field),str) or HEX64.fullmatch(getattr(self,field)) is None:
                raise ReplaySafetyError("HASH_INVALID",field,"lowercase SHA-256 hex required")
class _Opaque:
    __slots__=("__weakref__",); _label="authority"
    def __new__(cls,*_a:Any,**_k:Any)->Any: raise PermissionError(f"{cls._label} is sealed")
    def __copy__(self)->Any: raise TypeError(f"{self._label} cannot be copied")
    def __deepcopy__(self,_memo:dict[int,Any])->Any: raise TypeError(f"{self._label} cannot be copied")
    def __reduce__(self)->Any: raise TypeError(f"{self._label} cannot be serialized")
class ValidationAuthority(_Opaque): _label="validation authority"
class EffectAuthority(_Opaque): _label="effect authority"
class Reservation(_Opaque): _label="reservation"
class VerifiedEffectConfirmation(_Opaque): _label="verified confirmation"
class VerifiedReconciliation(_Opaque): _label="verified reconciliation"
@dataclass(frozen=True)
class _Binding:
    replay_id:str; effect_identity:str; reservation_id:str; attempt_number:str
    effect_class:EffectClass; target:str; request_hash:str
@dataclass(frozen=True)
class _Evidence:
    binding:_Binding; evidence_type:ConfirmationEvidenceType; evidence_hash:str
    related_identity:str; verifier_revision:str; policy_version:str
    result:Any=None

def _build_service_family(trusted_root:Path,store_kind:str,clock:Callable[[],datetime],store_id:str,family_secret:bytes)->SimpleNamespace:
    sha,digest,jsonm,sql,osm,stm,closer=hashlib.sha256,hmac.compare_digest,json,sqlite3,os,stat_module,closing
    safe,hex64,decimal=SAFE_TEXT.fullmatch,HEX64.fullmatch,DECIMAL.fullmatch
    dt,utc=datetime,timezone.utc; action_t,state_t,effect_t=CanonicalAction,ReplayState,EffectClass
    retry_t,error_t,proxy,namespace=RetryClassification,ReplaySafetyError,MappingProxyType,SimpleNamespace
    validation_t,authority_t,reservation_t=ValidationAuthority,EffectAuthority,Reservation
    confirmation_t,reconciliation_t=VerifiedEffectConfirmation,VerifiedReconciliation
    fixture_t,kind_t,result_t=ReviewedEvidenceFixture,ConfirmationEvidenceType,ReconciliationResult
    binding_t,evidence_t=_Binding,_Evidence; policy,schema,verifier=POLICY_VERSION,SCHEMA_VERSION,VERIFIER_REVISION
    allowed_actions=ACTION_CLASSES
    root=Path(trusted_root).absolute(); dirname,filename="replay-safety","ledger.sqlite3"; db=root/dirname/filename
    mutex=threading.RLock(); validations=weakref.WeakKeyDictionary(); authorities=weakref.WeakKeyDictionary()
    reservations=weakref.WeakKeyDictionary(); confirmations=weakref.WeakKeyDictionary(); reconciliations=weakref.WeakKeyDictionary()
    transitions=proxy({state_t.OBSERVED:frozenset({state_t.VALIDATED,state_t.REJECTED,state_t.REPLAY_IDENTITY_CONFLICT}),state_t.VALIDATED:frozenset({state_t.EFFECT_RESERVED,state_t.REJECTED,state_t.REPLAY_IDENTITY_CONFLICT}),state_t.EFFECT_RESERVED:frozenset({state_t.EFFECT_ATTEMPTED,state_t.EFFECT_FAILED_SAFE}),state_t.EFFECT_ATTEMPTED:frozenset({state_t.EFFECT_CONFIRMED,state_t.EFFECT_FAILED_SAFE,state_t.EFFECT_OUTCOME_UNKNOWN}),state_t.EFFECT_OUTCOME_UNKNOWN:frozenset({state_t.EFFECT_CONFIRMED,state_t.EFFECT_FAILED_SAFE}),state_t.EFFECT_FAILED_SAFE:frozenset({state_t.EFFECT_RESERVED}),state_t.REJECTED:frozenset(),state_t.REPLAY_IDENTITY_CONFLICT:frozenset(),state_t.EFFECT_CONFIRMED:frozenset()})
    retries=proxy({state_t.OBSERVED:retry_t.HUMAN_REVIEW_REQUIRED,state_t.VALIDATED:retry_t.HUMAN_REVIEW_REQUIRED,state_t.REJECTED:retry_t.DO_NOT_RETRY,state_t.REPLAY_IDENTITY_CONFLICT:retry_t.HUMAN_REVIEW_REQUIRED,state_t.EFFECT_RESERVED:retry_t.RECONCILIATION_REQUIRED,state_t.EFFECT_ATTEMPTED:retry_t.RECONCILIATION_REQUIRED,state_t.EFFECT_CONFIRMED:retry_t.DO_NOT_RETRY,state_t.EFFECT_FAILED_SAFE:retry_t.SAFE_TO_RETRY,state_t.EFFECT_OUTCOME_UNKNOWN:retry_t.RECONCILIATION_REQUIRED})
    unknown=proxy({effect_t.FAUCET_CLAIM:retry_t.RECONCILIATION_REQUIRED,effect_t.INFERENCE_SPEND:retry_t.RECONCILIATION_REQUIRED,effect_t.PAYMENT:retry_t.RECONCILIATION_REQUIRED,effect_t.AGENT_TASK:retry_t.HUMAN_REVIEW_REQUIRED,effect_t.REPUTATION_CREDIT:retry_t.HUMAN_REVIEW_REQUIRED})
    confirm_specs=proxy({fixture_t.FAUCET_CONFIRMED:(effect_t.FAUCET_CLAIM,kind_t.FAUCET_RESULT),fixture_t.INFERENCE_CONFIRMED:(effect_t.INFERENCE_SPEND,kind_t.INFERENCE_RESULT),fixture_t.PAYMENT_FINAL:(effect_t.PAYMENT,kind_t.RAIL_FINALITY),fixture_t.AGENT_TASK_CONFIRMED:(effect_t.AGENT_TASK,kind_t.AGENT_TASK_RECEIPT),fixture_t.REPUTATION_CONFIRMED:(effect_t.REPUTATION_CREDIT,kind_t.REPUTATION_RECEIPT)})
    reconcile_specs=proxy({fixture_t.RESERVED_NOT_INVOKED:(frozenset({state_t.EFFECT_RESERVED}),result_t.NO_EXTERNAL_EFFECT,kind_t.LOCAL_NO_EFFECT_PROOF),fixture_t.READBACK_PROVES_ABSENCE:(frozenset({state_t.EFFECT_ATTEMPTED,state_t.EFFECT_OUTCOME_UNKNOWN}),result_t.NO_EXTERNAL_EFFECT,kind_t.READ_BACK_CONFIRMATION),fixture_t.READBACK_PROVES_EFFECT:(frozenset({state_t.EFFECT_ATTEMPTED,state_t.EFFECT_OUTCOME_UNKNOWN}),result_t.EXTERNAL_EFFECT_CONFIRMED,kind_t.READ_BACK_CONFIRMATION)})
    def now()->str:
        value=clock()
        if not isinstance(value,dt) or value.tzinfo is None or value.utcoffset() is None: raise error_t("CLOCK_INVALID","clock","aware datetime required")
        return value.astimezone(utc).isoformat()
    def validate_action(a:CanonicalAction)->None:
        if type(a) is not action_t: raise error_t("ACTION_INVALID","action","exact canonical action required")
        for field in ("actor_did","context","target","schema_version"):
            value=getattr(a,field,None)
            if type(value) is not str or safe(value) is None: raise error_t("IDENTIFIER_INVALID",field,"bounded exact text required")
        if type(a.action_class) is not str or a.action_class not in allowed_actions: raise error_t("ACTION_CLASS_INVALID","action_class","reviewed action class required")
        if type(a.nonce) is not str or decimal(a.nonce) is None: raise error_t("NONCE_INVALID","nonce","exact canonical decimal string required")
        for field in ("signed_payload_sha256","signing_bytes_sha256"):
            value=getattr(a,field,None)
            if type(value) is not str or hex64(value) is None: raise error_t("HASH_INVALID",field,"lowercase SHA-256 hex required")
    def material(a:CanonicalAction)->bytes:
        validate_action(a)
        return jsonm.dumps({"actor_did":a.actor_did,"action_class":a.action_class,"context":a.context,"nonce":a.nonce,"signed_payload_sha256":a.signed_payload_sha256,"signing_bytes_sha256":a.signing_bytes_sha256,"target":a.target,"schema_version":a.schema_version,"policy_version":policy},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    def replay_id(a:CanonicalAction)->str: return sha(b"FLOP-REPLAY-ID\0"+material(a)).hexdigest()
    def nonce_scope(a:CanonicalAction)->str:
        value=jsonm.dumps({"actor_did":a.actor_did,"context":a.context,"nonce":a.nonce,"schema_version":a.schema_version},sort_keys=True,separators=(",",":")).encode(); return sha(b"FLOP-NONCE-SCOPE\0"+value).hexdigest()
    def secure_file()->tuple[int,int,int,int,int]:
        info=osm.lstat(root)
        if not stm.S_ISDIR(info.st_mode) or stm.S_ISLNK(info.st_mode) or info.st_uid!=osm.getuid() or info.st_mode&0o022: raise error_t("STORAGE_ROOT_UNSAFE","storage","owned non-writable real directory required")
        dflags=osm.O_RDONLY|getattr(osm,"O_DIRECTORY",0)|getattr(osm,"O_NOFOLLOW",0); rfd=osm.open(root,dflags)
        try:
            try: osm.mkdir(dirname,0o700,dir_fd=rfd)
            except FileExistsError: pass
            cfd=osm.open(dirname,dflags,dir_fd=rfd)
            try:
                ci=osm.fstat(cfd)
                if not stm.S_ISDIR(ci.st_mode) or ci.st_uid!=osm.getuid() or ci.st_mode&0o077: raise error_t("STORAGE_DIRECTORY_UNSAFE","storage","private owned directory required")
                fd=osm.open(filename,osm.O_RDWR|osm.O_CREAT|getattr(osm,"O_NOFOLLOW",0),0o600,dir_fd=cfd)
                try:
                    osm.fchmod(fd,0o600); fi=osm.fstat(fd); pi=osm.stat(filename,dir_fd=cfd,follow_symlinks=False)
                    if not stm.S_ISREG(fi.st_mode) or fi.st_uid!=osm.getuid() or (fi.st_dev,fi.st_ino)!=(pi.st_dev,pi.st_ino): raise error_t("STORAGE_FILE_UNSAFE","storage","owned regular file required")
                except Exception:
                    osm.close(fd); raise
                return rfd,cfd,fd,fi.st_dev,fi.st_ino
            except Exception:
                osm.close(cfd); raise
        except Exception:
            osm.close(rfd); raise
    def connect()->sqlite3.Connection:
        rfd,cfd,fd,device,inode=secure_file()
        try:
            con=sql.connect(str(db),timeout=10,isolation_level=None)
            opened=osm.stat(filename,dir_fd=cfd,follow_symlinks=False)
            held=osm.fstat(fd)
            if (opened.st_dev,opened.st_ino)!=(device,inode) or (held.st_dev,held.st_ino)!=(device,inode):
                con.close(); raise error_t("STORAGE_PATH_CHANGED","storage","validated database path changed before SQLite open")
            con.execute("PRAGMA foreign_keys=ON")
            con.executescript("""CREATE TABLE IF NOT EXISTS store_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id TEXT NOT NULL,store_kind TEXT NOT NULL,schema_version TEXT NOT NULL,policy_version TEXT NOT NULL,authority_digest TEXT NOT NULL);CREATE TABLE IF NOT EXISTS replay_records(replay_id TEXT PRIMARY KEY,nonce_scope TEXT NOT NULL UNIQUE,actor_did TEXT NOT NULL,action_class TEXT NOT NULL,context TEXT NOT NULL,nonce TEXT NOT NULL,payload_hash TEXT NOT NULL,signing_hash TEXT NOT NULL,target TEXT NOT NULL,schema_version TEXT NOT NULL,state TEXT NOT NULL,observation_count INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS replay_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,replay_id TEXT NOT NULL,from_state TEXT,to_state TEXT NOT NULL,occurred_at TEXT NOT NULL,event_hash TEXT NOT NULL UNIQUE,FOREIGN KEY(replay_id) REFERENCES replay_records(replay_id));CREATE TABLE IF NOT EXISTS replay_conflicts(conflict_id TEXT PRIMARY KEY,nonce_scope TEXT NOT NULL,authoritative_replay_id TEXT NOT NULL,conflicting_replay_id TEXT NOT NULL,conflicting_material_hash TEXT NOT NULL,observed_at TEXT NOT NULL,UNIQUE(authoritative_replay_id,conflicting_replay_id),FOREIGN KEY(authoritative_replay_id) REFERENCES replay_records(replay_id));CREATE TABLE IF NOT EXISTS effects(reservation_id TEXT PRIMARY KEY,replay_id TEXT NOT NULL,effect_identity TEXT NOT NULL,authority_ref_hash TEXT NOT NULL,effect_class TEXT NOT NULL,target TEXT NOT NULL,request_hash TEXT NOT NULL,attempt_number TEXT NOT NULL,started_at TEXT,result_state TEXT NOT NULL,confirmation_evidence_type TEXT,confirmation_evidence_hash TEXT,related_evidence_identity TEXT,verifier_revision TEXT,UNIQUE(replay_id,attempt_number),FOREIGN KEY(replay_id) REFERENCES replay_records(replay_id));""")
            authority_digest=sha(b"FLOP-STORE-FAMILY\0"+family_secret+store_id.encode()+str(device).encode()+b":"+str(inode).encode()).hexdigest()
            con.execute("BEGIN IMMEDIATE"); row=con.execute("SELECT store_id,store_kind,schema_version,policy_version,authority_digest FROM store_metadata WHERE singleton=1").fetchone(); expected=(store_id,store_kind,schema,policy,authority_digest)
            if row is None: con.execute("INSERT INTO store_metadata VALUES(1,?,?,?,?,?)",expected)
            elif not all(digest(str(left),str(right)) for left,right in zip(row,expected)): con.rollback(); con.close(); raise error_t("STORE_AUTHORITY_MISMATCH","storage","sealed store family provenance does not match")
            con.commit(); return con
        finally:
            osm.close(fd);osm.close(cfd);osm.close(rfd)
    def event(con:sqlite3.Connection,rid:str,old:str|None,new:str,when:str)->None:
        count=con.execute("SELECT COUNT(*) FROM replay_events WHERE replay_id=?",(rid,)).fetchone()[0]; digest=sha(f"{rid}|{count}|{old}|{new}|{when}".encode()).hexdigest(); con.execute("INSERT INTO replay_events(replay_id,from_state,to_state,occurred_at,event_hash) VALUES(?,?,?,?,?)",(rid,old,new,when,digest))
    def transition(con:sqlite3.Connection,rid:str,new:ReplayState,when:str)->None:
        row=con.execute("SELECT state FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
        if row is None: raise error_t("REPLAY_NOT_FOUND","replay_id","record not found")
        old=state_t(row[0])
        if new not in transitions[old]: raise error_t("TRANSITION_INVALID","state","transition denied")
        con.execute("UPDATE replay_records SET state=?,updated_at=? WHERE replay_id=?",(new.value,when,rid)); event(con,rid,old.value,new.value,when)
    def conflict_exists(con:sqlite3.Connection,rid:str)->bool:return con.execute("SELECT 1 FROM replay_conflicts WHERE authoritative_replay_id=? LIMIT 1",(rid,)).fetchone() is not None
    def observe(a:CanonicalAction)->Mapping[str,Any]:
        rid,scope,when=replay_id(a),nonce_scope(a),now()
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE"); prior=con.execute("SELECT replay_id,state,observation_count FROM replay_records WHERE nonce_scope=?",(scope,)).fetchone()
            if prior and prior[0]!=rid:
                conflict_id=sha(f"FLOP-CONFLICT|{scope}|{prior[0]}|{rid}".encode()).hexdigest()
                con.execute("INSERT OR IGNORE INTO replay_conflicts VALUES(?,?,?,?,?,?)",(conflict_id,scope,prior[0],rid,sha(material(a)).hexdigest(),when));con.commit()
                return proxy({"status":"DESCRIPTIVE_ONLY","decision":"REPLAY_IDENTITY_CONFLICT","replay_id":rid,"authoritative_replay_id":prior[0],"authoritative_state":prior[1],"state":state_t.REPLAY_IDENTITY_CONFLICT.value,"retry_classification":retry_t.HUMAN_REVIEW_REQUIRED.value})
            if prior is None: con.execute("INSERT INTO replay_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,scope,a.actor_did,a.action_class,a.context,a.nonce,a.signed_payload_sha256,a.signing_bytes_sha256,a.target,a.schema_version,state_t.OBSERVED.value,1,when,when)); event(con,rid,None,state_t.OBSERVED.value,when); decision,count,current="FIRST_OBSERVATION",1,state_t.OBSERVED
            else: decision,count,current="DUPLICATE_OBSERVATION",prior[2]+1,state_t(prior[1]); con.execute("UPDATE replay_records SET observation_count=?,updated_at=? WHERE replay_id=?",(count,when,rid))
            con.commit()
        return proxy({"status":"DESCRIPTIVE_ONLY","decision":decision,"replay_id":rid,"state":current.value,"observation_count":count,"retry_classification":retries[current].value})
    def latest(con:sqlite3.Connection,rid:str)->_Binding:
        row=con.execute("SELECT effect_identity,reservation_id,attempt_number,effect_class,target,request_hash FROM effects WHERE replay_id=? ORDER BY length(attempt_number) DESC,attempt_number DESC LIMIT 1",(rid,)).fetchone()
        if row is None: raise error_t("EFFECT_NOT_FOUND","effect","effect record required")
        return binding_t(rid,row[0],row[1],row[2],effect_t(row[3]),row[4],row[5])
    def inspect_id(rid:str)->Mapping[str,Any]:
        with closer(connect()) as con:
            row=con.execute("SELECT replay_id,action_class,state,created_at,updated_at,observation_count FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
            if row is None:return proxy({"status":"DESCRIPTIVE_ONLY","decision":"NOT_SEEN","replay_id":rid})
            effect=con.execute("SELECT effect_class,confirmation_evidence_type,confirmation_evidence_hash FROM effects WHERE replay_id=? ORDER BY length(attempt_number) DESC,attempt_number DESC LIMIT 1",(rid,)).fetchone()
        current=state_t(row[2]); classification=unknown[effect_t(effect[0])] if current is state_t.EFFECT_OUTCOME_UNKNOWN and effect else retries[current]
        return proxy({"status":"DESCRIPTIVE_ONLY","authority":"NOT_SERIALIZED","replay_id":row[0],"action_class":row[1],"state":current.value,"created_at":row[3],"updated_at":row[4],"observation_count":row[5],"effect_class":effect[0] if effect else None,"confirmation_evidence_type":effect[1] if effect else None,"confirmation_evidence_hash":effect[2] if effect else None,"retry_classification":classification.value})
    def inspect(a:CanonicalAction)->Mapping[str,Any]:return inspect_id(replay_id(a))
    def issue_validation(a:CanonicalAction)->ValidationAuthority: token=object.__new__(validation_t);validations[token]=replay_id(a);return token
    def validate(a:CanonicalAction,proof:ValidationAuthority)->Mapping[str,Any]:
        rid,when=replay_id(a),now()
        if type(proof) is not validation_t or validations.get(proof)!=rid:raise PermissionError("validation authority invalid or foreign")
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            if conflict_exists(con,rid):con.rollback();raise error_t("REPLAY_IDENTITY_CONFLICT","nonce","conflicted action cannot be validated")
            transition(con,rid,state_t.VALIDATED,when);con.commit()
        return inspect(a)
    def issue_authority(a:CanonicalAction,reference:str)->EffectAuthority:
        if not isinstance(reference,str) or safe(reference) is None:raise error_t("AUTHORITY_REFERENCE_INVALID","authority_reference","safe reference required")
        token=object.__new__(authority_t);authorities[token]=(replay_id(a),sha(reference.encode()).hexdigest());return token
    def reserve(a:CanonicalAction,authority:EffectAuthority,effect_class:EffectClass,target:str,request_hash:str)->Reservation:
        rid,when=replay_id(a),now();auth=authorities.get(authority) if type(authority) is authority_t else None
        if auth is None or auth[0]!=rid:raise PermissionError("effect authority invalid or foreign")
        if type(effect_class) is not effect_t or not isinstance(target,str) or safe(target) is None or not isinstance(request_hash,str) or hex64(request_hash) is None:raise error_t("EFFECT_IDENTITY_INVALID","effect","reviewed exact identity required")
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE");row=con.execute("SELECT state FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
            if conflict_exists(con,rid):con.rollback();raise error_t("REPLAY_IDENTITY_CONFLICT","nonce","conflicted action cannot reserve an effect")
            if row is None or state_t(row[0]) not in {state_t.VALIDATED,state_t.EFFECT_FAILED_SAFE}:con.rollback();raise error_t("EFFECT_RESERVATION_DENIED","state","validated or proven-safe state required")
            prior=con.execute("SELECT attempt_number FROM effects WHERE replay_id=? ORDER BY length(attempt_number) DESC,attempt_number DESC LIMIT 1",(rid,)).fetchone();attempt=str(int(prior[0])+1) if prior else "1";eid=sha(f"{rid}|{effect_class.value}|{target}|{request_hash}".encode()).hexdigest();resid=sha(f"FLOP-RESERVATION|{eid}|{attempt}".encode()).hexdigest();con.execute("INSERT INTO effects(reservation_id,replay_id,effect_identity,authority_ref_hash,effect_class,target,request_hash,attempt_number,started_at,result_state) VALUES(?,?,?,?,?,?,?,?,?,?)",(resid,rid,eid,auth[1],effect_class.value,target,request_hash,attempt,None,state_t.EFFECT_RESERVED.value));transition(con,rid,state_t.EFFECT_RESERVED,when);con.commit()
        binding=binding_t(rid,eid,resid,attempt,effect_class,target,request_hash);token=object.__new__(reservation_t);reservations[token]=binding;return token
    def attempted(reservation:Reservation)->Mapping[str,Any]:
        binding=reservations.get(reservation) if type(reservation) is reservation_t else None
        if binding is None:raise PermissionError("reservation invalid or foreign")
        when=now()
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            if conflict_exists(con,binding.replay_id):con.rollback();raise error_t("REPLAY_IDENTITY_CONFLICT","nonce","conflicted action cannot start an effect")
            transition(con,binding.replay_id,state_t.EFFECT_ATTEMPTED,when);con.execute("UPDATE effects SET started_at=?,result_state=? WHERE reservation_id=?",(when,state_t.EFFECT_ATTEMPTED.value,binding.reservation_id));con.commit()
        return inspect_id(binding.replay_id)
    def current_binding(a:CanonicalAction)->tuple[_Binding,ReplayState]:
        rid=replay_id(a)
        with closer(connect()) as con:binding=latest(con,rid);row=con.execute("SELECT state FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
        return binding,state_t(row[0])
    def issue_confirmation(reservation:Reservation,fixture:ReviewedEvidenceFixture)->VerifiedEffectConfirmation:
        binding=reservations.get(reservation) if type(reservation) is reservation_t else None;spec=confirm_specs.get(fixture) if type(fixture) is fixture_t else None
        if binding is None or spec is None or spec[0] is not binding.effect_class:raise PermissionError("confirmation fixture mismatched")
        evidence=evidence_t(binding,spec[1],sha(f"{fixture.value}|{binding}".encode()).hexdigest(),sha(f"RELATED|{fixture.value}|{binding.effect_identity}".encode()).hexdigest(),verifier,policy);token=object.__new__(confirmation_t);confirmations[token]=evidence;return token
    def write_evidence(con:sqlite3.Connection,binding:_Binding,evidence:_Evidence,new:ReplayState,when:str)->None:
        if latest(con,binding.replay_id)!=binding:raise error_t("EVIDENCE_BINDING_MISMATCH","effect","latest exact attempt required")
        transition(con,binding.replay_id,new,when);con.execute("UPDATE effects SET result_state=?,confirmation_evidence_type=?,confirmation_evidence_hash=?,related_evidence_identity=?,verifier_revision=? WHERE reservation_id=?",(new.value,evidence.evidence_type.value,evidence.evidence_hash,evidence.related_identity,verifier,binding.reservation_id))
    def confirm(reservation:Reservation,evidence:VerifiedEffectConfirmation)->Mapping[str,Any]:
        binding=reservations.get(reservation) if type(reservation) is reservation_t else None;record=confirmations.get(evidence) if type(evidence) is confirmation_t else None
        if binding is None or record is None or record.binding!=binding or record.verifier_revision!=verifier or record.policy_version!=policy:raise PermissionError("confirmation invalid, mismatched, or foreign")
        with mutex,closer(connect()) as con:con.execute("BEGIN IMMEDIATE");write_evidence(con,binding,record,state_t.EFFECT_CONFIRMED,now());con.commit()
        return inspect_id(binding.replay_id)
    def issue_reconciliation(a:CanonicalAction,fixture:ReviewedEvidenceFixture)->VerifiedReconciliation:
        binding,current=current_binding(a);spec=reconcile_specs.get(fixture) if type(fixture) is fixture_t else None
        if spec is None or current not in spec[0]:raise PermissionError("reconciliation fixture does not apply")
        evidence=evidence_t(binding,spec[2],sha(f"{fixture.value}|{binding}|{current.value}".encode()).hexdigest(),sha(f"RELATED|{fixture.value}|{binding.effect_identity}".encode()).hexdigest(),verifier,policy,spec[1]);token=object.__new__(reconciliation_t);reconciliations[token]=evidence;return token
    def reconcile(a:CanonicalAction,evidence:VerifiedReconciliation)->Mapping[str,Any]:
        rid=replay_id(a);record=reconciliations.get(evidence) if type(evidence) is reconciliation_t else None
        if record is None or record.binding.replay_id!=rid or record.verifier_revision!=verifier or record.policy_version!=policy:raise PermissionError("reconciliation invalid, mismatched, or foreign")
        new=state_t.EFFECT_FAILED_SAFE if record.result is result_t.NO_EXTERNAL_EFFECT else state_t.EFFECT_CONFIRMED
        with mutex,closer(connect()) as con:con.execute("BEGIN IMMEDIATE");write_evidence(con,record.binding,record,new,now());con.commit()
        return inspect_id(rid)
    def recover()->int:
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE");rows=con.execute("SELECT replay_id FROM replay_records WHERE state=?",(state_t.EFFECT_ATTEMPTED.value,)).fetchall()
            for (rid,) in rows:transition(con,rid,state_t.EFFECT_OUTCOME_UNKNOWN,now());con.execute("UPDATE effects SET result_state=? WHERE replay_id=? AND result_state=?",(state_t.EFFECT_OUTCOME_UNKNOWN.value,rid,state_t.EFFECT_ATTEMPTED.value))
            con.commit()
        return len(rows)
    def worker()->SimpleNamespace:return namespace(observe=observe,inspect=inspect,replay_id=replay_id,validate=validate,reserve=reserve,attempted=attempted,confirm=confirm,reconcile=reconcile,recover=recover)
    return namespace(worker=worker,issue_validation=issue_validation,issue_effect_authority=issue_authority,issue_confirmation=issue_confirmation,issue_reconciliation=issue_reconciliation)

_PRODUCTION_ROOT=Path(__file__).resolve().parents[2]/"secrets"
def _production_clock(_dt:type[datetime]=datetime,_utc:timezone=timezone.utc)->datetime:return _dt.now(_utc)
def _production_facade()->tuple[Callable[...,Any],...]:
    store_id=hashlib.sha256(b"FLOP-PRODUCTION-REPLAY-STORE-v1").hexdigest()
    family=_build_service_family(_PRODUCTION_ROOT,"PRODUCTION",_production_clock,store_id,secrets.token_bytes(32));worker=family.worker();return worker.observe,worker.inspect,worker.replay_id
observe_action,inspect_action,canonical_replay_id=_production_facade()
del _build_service_family
del _production_facade

def _new_test_family(root:Path,clock:Callable[[],datetime])->SimpleNamespace:
    sha,digest,jsonm,sql,osm,stm,closer=hashlib.sha256,hmac.compare_digest,json,sqlite3,os,stat_module,closing
    selected=Path(root).absolute();forbidden=_PRODUCTION_ROOT
    if selected==forbidden or forbidden in selected.parents:raise ReplaySafetyError("PRODUCTION_STORE_FORBIDDEN","storage","test family cannot attach to production root")
    if (selected/"replay-safety").exists() or (selected/"replay-safety").is_symlink():raise ReplaySafetyError("EXISTING_STORE_FORBIDDEN","storage","test provisioning requires a new empty store")
    trusted_root,store_kind,store_id,family_secret=selected,"TEST",secrets.token_hex(32),secrets.token_bytes(32)
    safe,hex64,decimal=SAFE_TEXT.fullmatch,HEX64.fullmatch,DECIMAL.fullmatch
    dt,utc=datetime,timezone.utc; action_t,state_t,effect_t=CanonicalAction,ReplayState,EffectClass
    retry_t,error_t,proxy,namespace=RetryClassification,ReplaySafetyError,MappingProxyType,SimpleNamespace
    validation_t,authority_t,reservation_t=ValidationAuthority,EffectAuthority,Reservation
    confirmation_t,reconciliation_t=VerifiedEffectConfirmation,VerifiedReconciliation
    fixture_t,kind_t,result_t=ReviewedEvidenceFixture,ConfirmationEvidenceType,ReconciliationResult
    binding_t,evidence_t=_Binding,_Evidence; policy,schema,verifier=POLICY_VERSION,SCHEMA_VERSION,VERIFIER_REVISION
    allowed_actions=ACTION_CLASSES
    root=Path(trusted_root).absolute(); dirname,filename="replay-safety","ledger.sqlite3"; db=root/dirname/filename
    mutex=threading.RLock(); validations=weakref.WeakKeyDictionary(); authorities=weakref.WeakKeyDictionary()
    reservations=weakref.WeakKeyDictionary(); confirmations=weakref.WeakKeyDictionary(); reconciliations=weakref.WeakKeyDictionary()
    transitions=proxy({state_t.OBSERVED:frozenset({state_t.VALIDATED,state_t.REJECTED,state_t.REPLAY_IDENTITY_CONFLICT}),state_t.VALIDATED:frozenset({state_t.EFFECT_RESERVED,state_t.REJECTED,state_t.REPLAY_IDENTITY_CONFLICT}),state_t.EFFECT_RESERVED:frozenset({state_t.EFFECT_ATTEMPTED,state_t.EFFECT_FAILED_SAFE}),state_t.EFFECT_ATTEMPTED:frozenset({state_t.EFFECT_CONFIRMED,state_t.EFFECT_FAILED_SAFE,state_t.EFFECT_OUTCOME_UNKNOWN}),state_t.EFFECT_OUTCOME_UNKNOWN:frozenset({state_t.EFFECT_CONFIRMED,state_t.EFFECT_FAILED_SAFE}),state_t.EFFECT_FAILED_SAFE:frozenset({state_t.EFFECT_RESERVED}),state_t.REJECTED:frozenset(),state_t.REPLAY_IDENTITY_CONFLICT:frozenset(),state_t.EFFECT_CONFIRMED:frozenset()})
    retries=proxy({state_t.OBSERVED:retry_t.HUMAN_REVIEW_REQUIRED,state_t.VALIDATED:retry_t.HUMAN_REVIEW_REQUIRED,state_t.REJECTED:retry_t.DO_NOT_RETRY,state_t.REPLAY_IDENTITY_CONFLICT:retry_t.HUMAN_REVIEW_REQUIRED,state_t.EFFECT_RESERVED:retry_t.RECONCILIATION_REQUIRED,state_t.EFFECT_ATTEMPTED:retry_t.RECONCILIATION_REQUIRED,state_t.EFFECT_CONFIRMED:retry_t.DO_NOT_RETRY,state_t.EFFECT_FAILED_SAFE:retry_t.SAFE_TO_RETRY,state_t.EFFECT_OUTCOME_UNKNOWN:retry_t.RECONCILIATION_REQUIRED})
    unknown=proxy({effect_t.FAUCET_CLAIM:retry_t.RECONCILIATION_REQUIRED,effect_t.INFERENCE_SPEND:retry_t.RECONCILIATION_REQUIRED,effect_t.PAYMENT:retry_t.RECONCILIATION_REQUIRED,effect_t.AGENT_TASK:retry_t.HUMAN_REVIEW_REQUIRED,effect_t.REPUTATION_CREDIT:retry_t.HUMAN_REVIEW_REQUIRED})
    confirm_specs=proxy({fixture_t.FAUCET_CONFIRMED:(effect_t.FAUCET_CLAIM,kind_t.FAUCET_RESULT),fixture_t.INFERENCE_CONFIRMED:(effect_t.INFERENCE_SPEND,kind_t.INFERENCE_RESULT),fixture_t.PAYMENT_FINAL:(effect_t.PAYMENT,kind_t.RAIL_FINALITY),fixture_t.AGENT_TASK_CONFIRMED:(effect_t.AGENT_TASK,kind_t.AGENT_TASK_RECEIPT),fixture_t.REPUTATION_CONFIRMED:(effect_t.REPUTATION_CREDIT,kind_t.REPUTATION_RECEIPT)})
    reconcile_specs=proxy({fixture_t.RESERVED_NOT_INVOKED:(frozenset({state_t.EFFECT_RESERVED}),result_t.NO_EXTERNAL_EFFECT,kind_t.LOCAL_NO_EFFECT_PROOF),fixture_t.READBACK_PROVES_ABSENCE:(frozenset({state_t.EFFECT_ATTEMPTED,state_t.EFFECT_OUTCOME_UNKNOWN}),result_t.NO_EXTERNAL_EFFECT,kind_t.READ_BACK_CONFIRMATION),fixture_t.READBACK_PROVES_EFFECT:(frozenset({state_t.EFFECT_ATTEMPTED,state_t.EFFECT_OUTCOME_UNKNOWN}),result_t.EXTERNAL_EFFECT_CONFIRMED,kind_t.READ_BACK_CONFIRMATION)})
    def now()->str:
        value=clock()
        if not isinstance(value,dt) or value.tzinfo is None or value.utcoffset() is None: raise error_t("CLOCK_INVALID","clock","aware datetime required")
        return value.astimezone(utc).isoformat()
    def validate_action(a:CanonicalAction)->None:
        if type(a) is not action_t: raise error_t("ACTION_INVALID","action","exact canonical action required")
        for field in ("actor_did","context","target","schema_version"):
            value=getattr(a,field,None)
            if type(value) is not str or safe(value) is None: raise error_t("IDENTIFIER_INVALID",field,"bounded exact text required")
        if type(a.action_class) is not str or a.action_class not in allowed_actions: raise error_t("ACTION_CLASS_INVALID","action_class","reviewed action class required")
        if type(a.nonce) is not str or decimal(a.nonce) is None: raise error_t("NONCE_INVALID","nonce","exact canonical decimal string required")
        for field in ("signed_payload_sha256","signing_bytes_sha256"):
            value=getattr(a,field,None)
            if type(value) is not str or hex64(value) is None: raise error_t("HASH_INVALID",field,"lowercase SHA-256 hex required")
    def material(a:CanonicalAction)->bytes:
        validate_action(a)
        return jsonm.dumps({"actor_did":a.actor_did,"action_class":a.action_class,"context":a.context,"nonce":a.nonce,"signed_payload_sha256":a.signed_payload_sha256,"signing_bytes_sha256":a.signing_bytes_sha256,"target":a.target,"schema_version":a.schema_version,"policy_version":policy},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    def replay_id(a:CanonicalAction)->str: return sha(b"FLOP-REPLAY-ID\0"+material(a)).hexdigest()
    def nonce_scope(a:CanonicalAction)->str:
        value=jsonm.dumps({"actor_did":a.actor_did,"context":a.context,"nonce":a.nonce,"schema_version":a.schema_version},sort_keys=True,separators=(",",":")).encode(); return sha(b"FLOP-NONCE-SCOPE\0"+value).hexdigest()
    def secure_file()->tuple[int,int,int,int,int]:
        info=osm.lstat(root)
        if not stm.S_ISDIR(info.st_mode) or stm.S_ISLNK(info.st_mode) or info.st_uid!=osm.getuid() or info.st_mode&0o022: raise error_t("STORAGE_ROOT_UNSAFE","storage","owned non-writable real directory required")
        dflags=osm.O_RDONLY|getattr(osm,"O_DIRECTORY",0)|getattr(osm,"O_NOFOLLOW",0); rfd=osm.open(root,dflags)
        try:
            try: osm.mkdir(dirname,0o700,dir_fd=rfd)
            except FileExistsError: pass
            cfd=osm.open(dirname,dflags,dir_fd=rfd)
            try:
                ci=osm.fstat(cfd)
                if not stm.S_ISDIR(ci.st_mode) or ci.st_uid!=osm.getuid() or ci.st_mode&0o077: raise error_t("STORAGE_DIRECTORY_UNSAFE","storage","private owned directory required")
                fd=osm.open(filename,osm.O_RDWR|osm.O_CREAT|getattr(osm,"O_NOFOLLOW",0),0o600,dir_fd=cfd)
                try:
                    osm.fchmod(fd,0o600); fi=osm.fstat(fd); pi=osm.stat(filename,dir_fd=cfd,follow_symlinks=False)
                    if not stm.S_ISREG(fi.st_mode) or fi.st_uid!=osm.getuid() or (fi.st_dev,fi.st_ino)!=(pi.st_dev,pi.st_ino): raise error_t("STORAGE_FILE_UNSAFE","storage","owned regular file required")
                except Exception:
                    osm.close(fd); raise
                return rfd,cfd,fd,fi.st_dev,fi.st_ino
            except Exception:
                osm.close(cfd); raise
        except Exception:
            osm.close(rfd); raise
    def connect()->sqlite3.Connection:
        rfd,cfd,fd,device,inode=secure_file()
        try:
            con=sql.connect(str(db),timeout=10,isolation_level=None)
            opened=osm.stat(filename,dir_fd=cfd,follow_symlinks=False)
            held=osm.fstat(fd)
            if (opened.st_dev,opened.st_ino)!=(device,inode) or (held.st_dev,held.st_ino)!=(device,inode):
                con.close(); raise error_t("STORAGE_PATH_CHANGED","storage","validated database path changed before SQLite open")
            con.execute("PRAGMA foreign_keys=ON")
            con.executescript("""CREATE TABLE IF NOT EXISTS store_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id TEXT NOT NULL,store_kind TEXT NOT NULL,schema_version TEXT NOT NULL,policy_version TEXT NOT NULL,authority_digest TEXT NOT NULL);CREATE TABLE IF NOT EXISTS replay_records(replay_id TEXT PRIMARY KEY,nonce_scope TEXT NOT NULL UNIQUE,actor_did TEXT NOT NULL,action_class TEXT NOT NULL,context TEXT NOT NULL,nonce TEXT NOT NULL,payload_hash TEXT NOT NULL,signing_hash TEXT NOT NULL,target TEXT NOT NULL,schema_version TEXT NOT NULL,state TEXT NOT NULL,observation_count INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS replay_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,replay_id TEXT NOT NULL,from_state TEXT,to_state TEXT NOT NULL,occurred_at TEXT NOT NULL,event_hash TEXT NOT NULL UNIQUE,FOREIGN KEY(replay_id) REFERENCES replay_records(replay_id));CREATE TABLE IF NOT EXISTS replay_conflicts(conflict_id TEXT PRIMARY KEY,nonce_scope TEXT NOT NULL,authoritative_replay_id TEXT NOT NULL,conflicting_replay_id TEXT NOT NULL,conflicting_material_hash TEXT NOT NULL,observed_at TEXT NOT NULL,UNIQUE(authoritative_replay_id,conflicting_replay_id),FOREIGN KEY(authoritative_replay_id) REFERENCES replay_records(replay_id));CREATE TABLE IF NOT EXISTS effects(reservation_id TEXT PRIMARY KEY,replay_id TEXT NOT NULL,effect_identity TEXT NOT NULL,authority_ref_hash TEXT NOT NULL,effect_class TEXT NOT NULL,target TEXT NOT NULL,request_hash TEXT NOT NULL,attempt_number TEXT NOT NULL,started_at TEXT,result_state TEXT NOT NULL,confirmation_evidence_type TEXT,confirmation_evidence_hash TEXT,related_evidence_identity TEXT,verifier_revision TEXT,UNIQUE(replay_id,attempt_number),FOREIGN KEY(replay_id) REFERENCES replay_records(replay_id));""")
            authority_digest=sha(b"FLOP-STORE-FAMILY\0"+family_secret+store_id.encode()+str(device).encode()+b":"+str(inode).encode()).hexdigest()
            con.execute("BEGIN IMMEDIATE"); row=con.execute("SELECT store_id,store_kind,schema_version,policy_version,authority_digest FROM store_metadata WHERE singleton=1").fetchone(); expected=(store_id,store_kind,schema,policy,authority_digest)
            if row is None: con.execute("INSERT INTO store_metadata VALUES(1,?,?,?,?,?)",expected)
            elif not all(digest(str(left),str(right)) for left,right in zip(row,expected)): con.rollback(); con.close(); raise error_t("STORE_AUTHORITY_MISMATCH","storage","sealed store family provenance does not match")
            con.commit(); return con
        finally:
            osm.close(fd);osm.close(cfd);osm.close(rfd)
    def event(con:sqlite3.Connection,rid:str,old:str|None,new:str,when:str)->None:
        count=con.execute("SELECT COUNT(*) FROM replay_events WHERE replay_id=?",(rid,)).fetchone()[0]; digest=sha(f"{rid}|{count}|{old}|{new}|{when}".encode()).hexdigest(); con.execute("INSERT INTO replay_events(replay_id,from_state,to_state,occurred_at,event_hash) VALUES(?,?,?,?,?)",(rid,old,new,when,digest))
    def transition(con:sqlite3.Connection,rid:str,new:ReplayState,when:str)->None:
        row=con.execute("SELECT state FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
        if row is None: raise error_t("REPLAY_NOT_FOUND","replay_id","record not found")
        old=state_t(row[0])
        if new not in transitions[old]: raise error_t("TRANSITION_INVALID","state","transition denied")
        con.execute("UPDATE replay_records SET state=?,updated_at=? WHERE replay_id=?",(new.value,when,rid)); event(con,rid,old.value,new.value,when)
    def conflict_exists(con:sqlite3.Connection,rid:str)->bool:return con.execute("SELECT 1 FROM replay_conflicts WHERE authoritative_replay_id=? LIMIT 1",(rid,)).fetchone() is not None
    def observe(a:CanonicalAction)->Mapping[str,Any]:
        rid,scope,when=replay_id(a),nonce_scope(a),now()
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE"); prior=con.execute("SELECT replay_id,state,observation_count FROM replay_records WHERE nonce_scope=?",(scope,)).fetchone()
            if prior and prior[0]!=rid:
                conflict_id=sha(f"FLOP-CONFLICT|{scope}|{prior[0]}|{rid}".encode()).hexdigest()
                con.execute("INSERT OR IGNORE INTO replay_conflicts VALUES(?,?,?,?,?,?)",(conflict_id,scope,prior[0],rid,sha(material(a)).hexdigest(),when));con.commit()
                return proxy({"status":"DESCRIPTIVE_ONLY","decision":"REPLAY_IDENTITY_CONFLICT","replay_id":rid,"authoritative_replay_id":prior[0],"authoritative_state":prior[1],"state":state_t.REPLAY_IDENTITY_CONFLICT.value,"retry_classification":retry_t.HUMAN_REVIEW_REQUIRED.value})
            if prior is None: con.execute("INSERT INTO replay_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,scope,a.actor_did,a.action_class,a.context,a.nonce,a.signed_payload_sha256,a.signing_bytes_sha256,a.target,a.schema_version,state_t.OBSERVED.value,1,when,when)); event(con,rid,None,state_t.OBSERVED.value,when); decision,count,current="FIRST_OBSERVATION",1,state_t.OBSERVED
            else: decision,count,current="DUPLICATE_OBSERVATION",prior[2]+1,state_t(prior[1]); con.execute("UPDATE replay_records SET observation_count=?,updated_at=? WHERE replay_id=?",(count,when,rid))
            con.commit()
        return proxy({"status":"DESCRIPTIVE_ONLY","decision":decision,"replay_id":rid,"state":current.value,"observation_count":count,"retry_classification":retries[current].value})
    def latest(con:sqlite3.Connection,rid:str)->_Binding:
        row=con.execute("SELECT effect_identity,reservation_id,attempt_number,effect_class,target,request_hash FROM effects WHERE replay_id=? ORDER BY length(attempt_number) DESC,attempt_number DESC LIMIT 1",(rid,)).fetchone()
        if row is None: raise error_t("EFFECT_NOT_FOUND","effect","effect record required")
        return binding_t(rid,row[0],row[1],row[2],effect_t(row[3]),row[4],row[5])
    def inspect_id(rid:str)->Mapping[str,Any]:
        with closer(connect()) as con:
            row=con.execute("SELECT replay_id,action_class,state,created_at,updated_at,observation_count FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
            if row is None:return proxy({"status":"DESCRIPTIVE_ONLY","decision":"NOT_SEEN","replay_id":rid})
            effect=con.execute("SELECT effect_class,confirmation_evidence_type,confirmation_evidence_hash FROM effects WHERE replay_id=? ORDER BY length(attempt_number) DESC,attempt_number DESC LIMIT 1",(rid,)).fetchone()
        current=state_t(row[2]); classification=unknown[effect_t(effect[0])] if current is state_t.EFFECT_OUTCOME_UNKNOWN and effect else retries[current]
        return proxy({"status":"DESCRIPTIVE_ONLY","authority":"NOT_SERIALIZED","replay_id":row[0],"action_class":row[1],"state":current.value,"created_at":row[3],"updated_at":row[4],"observation_count":row[5],"effect_class":effect[0] if effect else None,"confirmation_evidence_type":effect[1] if effect else None,"confirmation_evidence_hash":effect[2] if effect else None,"retry_classification":classification.value})
    def inspect(a:CanonicalAction)->Mapping[str,Any]:return inspect_id(replay_id(a))
    def issue_validation(a:CanonicalAction)->ValidationAuthority: token=object.__new__(validation_t);validations[token]=replay_id(a);return token
    def validate(a:CanonicalAction,proof:ValidationAuthority)->Mapping[str,Any]:
        rid,when=replay_id(a),now()
        if type(proof) is not validation_t or validations.get(proof)!=rid:raise PermissionError("validation authority invalid or foreign")
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            if conflict_exists(con,rid):con.rollback();raise error_t("REPLAY_IDENTITY_CONFLICT","nonce","conflicted action cannot be validated")
            transition(con,rid,state_t.VALIDATED,when);con.commit()
        return inspect(a)
    def issue_authority(a:CanonicalAction,reference:str)->EffectAuthority:
        if not isinstance(reference,str) or safe(reference) is None:raise error_t("AUTHORITY_REFERENCE_INVALID","authority_reference","safe reference required")
        token=object.__new__(authority_t);authorities[token]=(replay_id(a),sha(reference.encode()).hexdigest());return token
    def reserve(a:CanonicalAction,authority:EffectAuthority,effect_class:EffectClass,target:str,request_hash:str)->Reservation:
        rid,when=replay_id(a),now();auth=authorities.get(authority) if type(authority) is authority_t else None
        if auth is None or auth[0]!=rid:raise PermissionError("effect authority invalid or foreign")
        if type(effect_class) is not effect_t or not isinstance(target,str) or safe(target) is None or not isinstance(request_hash,str) or hex64(request_hash) is None:raise error_t("EFFECT_IDENTITY_INVALID","effect","reviewed exact identity required")
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE");row=con.execute("SELECT state FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
            if conflict_exists(con,rid):con.rollback();raise error_t("REPLAY_IDENTITY_CONFLICT","nonce","conflicted action cannot reserve an effect")
            if row is None or state_t(row[0]) not in {state_t.VALIDATED,state_t.EFFECT_FAILED_SAFE}:con.rollback();raise error_t("EFFECT_RESERVATION_DENIED","state","validated or proven-safe state required")
            prior=con.execute("SELECT attempt_number FROM effects WHERE replay_id=? ORDER BY length(attempt_number) DESC,attempt_number DESC LIMIT 1",(rid,)).fetchone();attempt=str(int(prior[0])+1) if prior else "1";eid=sha(f"{rid}|{effect_class.value}|{target}|{request_hash}".encode()).hexdigest();resid=sha(f"FLOP-RESERVATION|{eid}|{attempt}".encode()).hexdigest();con.execute("INSERT INTO effects(reservation_id,replay_id,effect_identity,authority_ref_hash,effect_class,target,request_hash,attempt_number,started_at,result_state) VALUES(?,?,?,?,?,?,?,?,?,?)",(resid,rid,eid,auth[1],effect_class.value,target,request_hash,attempt,None,state_t.EFFECT_RESERVED.value));transition(con,rid,state_t.EFFECT_RESERVED,when);con.commit()
        binding=binding_t(rid,eid,resid,attempt,effect_class,target,request_hash);token=object.__new__(reservation_t);reservations[token]=binding;return token
    def attempted(reservation:Reservation)->Mapping[str,Any]:
        binding=reservations.get(reservation) if type(reservation) is reservation_t else None
        if binding is None:raise PermissionError("reservation invalid or foreign")
        when=now()
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            if conflict_exists(con,binding.replay_id):con.rollback();raise error_t("REPLAY_IDENTITY_CONFLICT","nonce","conflicted action cannot start an effect")
            transition(con,binding.replay_id,state_t.EFFECT_ATTEMPTED,when);con.execute("UPDATE effects SET started_at=?,result_state=? WHERE reservation_id=?",(when,state_t.EFFECT_ATTEMPTED.value,binding.reservation_id));con.commit()
        return inspect_id(binding.replay_id)
    def current_binding(a:CanonicalAction)->tuple[_Binding,ReplayState]:
        rid=replay_id(a)
        with closer(connect()) as con:binding=latest(con,rid);row=con.execute("SELECT state FROM replay_records WHERE replay_id=?",(rid,)).fetchone()
        return binding,state_t(row[0])
    def issue_confirmation(reservation:Reservation,fixture:ReviewedEvidenceFixture)->VerifiedEffectConfirmation:
        binding=reservations.get(reservation) if type(reservation) is reservation_t else None;spec=confirm_specs.get(fixture) if type(fixture) is fixture_t else None
        if binding is None or spec is None or spec[0] is not binding.effect_class:raise PermissionError("confirmation fixture mismatched")
        evidence=evidence_t(binding,spec[1],sha(f"{fixture.value}|{binding}".encode()).hexdigest(),sha(f"RELATED|{fixture.value}|{binding.effect_identity}".encode()).hexdigest(),verifier,policy);token=object.__new__(confirmation_t);confirmations[token]=evidence;return token
    def write_evidence(con:sqlite3.Connection,binding:_Binding,evidence:_Evidence,new:ReplayState,when:str)->None:
        if latest(con,binding.replay_id)!=binding:raise error_t("EVIDENCE_BINDING_MISMATCH","effect","latest exact attempt required")
        transition(con,binding.replay_id,new,when);con.execute("UPDATE effects SET result_state=?,confirmation_evidence_type=?,confirmation_evidence_hash=?,related_evidence_identity=?,verifier_revision=? WHERE reservation_id=?",(new.value,evidence.evidence_type.value,evidence.evidence_hash,evidence.related_identity,verifier,binding.reservation_id))
    def confirm(reservation:Reservation,evidence:VerifiedEffectConfirmation)->Mapping[str,Any]:
        binding=reservations.get(reservation) if type(reservation) is reservation_t else None;record=confirmations.get(evidence) if type(evidence) is confirmation_t else None
        if binding is None or record is None or record.binding!=binding or record.verifier_revision!=verifier or record.policy_version!=policy:raise PermissionError("confirmation invalid, mismatched, or foreign")
        with mutex,closer(connect()) as con:con.execute("BEGIN IMMEDIATE");write_evidence(con,binding,record,state_t.EFFECT_CONFIRMED,now());con.commit()
        return inspect_id(binding.replay_id)
    def issue_reconciliation(a:CanonicalAction,fixture:ReviewedEvidenceFixture)->VerifiedReconciliation:
        binding,current=current_binding(a);spec=reconcile_specs.get(fixture) if type(fixture) is fixture_t else None
        if spec is None or current not in spec[0]:raise PermissionError("reconciliation fixture does not apply")
        evidence=evidence_t(binding,spec[2],sha(f"{fixture.value}|{binding}|{current.value}".encode()).hexdigest(),sha(f"RELATED|{fixture.value}|{binding.effect_identity}".encode()).hexdigest(),verifier,policy,spec[1]);token=object.__new__(reconciliation_t);reconciliations[token]=evidence;return token
    def reconcile(a:CanonicalAction,evidence:VerifiedReconciliation)->Mapping[str,Any]:
        rid=replay_id(a);record=reconciliations.get(evidence) if type(evidence) is reconciliation_t else None
        if record is None or record.binding.replay_id!=rid or record.verifier_revision!=verifier or record.policy_version!=policy:raise PermissionError("reconciliation invalid, mismatched, or foreign")
        new=state_t.EFFECT_FAILED_SAFE if record.result is result_t.NO_EXTERNAL_EFFECT else state_t.EFFECT_CONFIRMED
        with mutex,closer(connect()) as con:con.execute("BEGIN IMMEDIATE");write_evidence(con,record.binding,record,new,now());con.commit()
        return inspect_id(rid)
    def recover()->int:
        with mutex,closer(connect()) as con:
            con.execute("BEGIN IMMEDIATE");rows=con.execute("SELECT replay_id FROM replay_records WHERE state=?",(state_t.EFFECT_ATTEMPTED.value,)).fetchall()
            for (rid,) in rows:transition(con,rid,state_t.EFFECT_OUTCOME_UNKNOWN,now());con.execute("UPDATE effects SET result_state=? WHERE replay_id=? AND result_state=?",(state_t.EFFECT_OUTCOME_UNKNOWN.value,rid,state_t.EFFECT_ATTEMPTED.value))
            con.commit()
        return len(rows)
    def worker()->SimpleNamespace:return namespace(observe=observe,inspect=inspect,replay_id=replay_id,validate=validate,reserve=reserve,attempted=attempted,confirm=confirm,reconcile=reconcile,recover=recover)
    family=namespace(worker=worker,issue_validation=issue_validation,issue_effect_authority=issue_authority,issue_confirmation=issue_confirmation,issue_reconciliation=issue_reconciliation);worker().recover();return family


__all__=("CanonicalAction","ConfirmationEvidenceType","EffectClass","ReplaySafetyError","ReplayState","RetryClassification","canonical_replay_id","inspect_action","observe_action")
