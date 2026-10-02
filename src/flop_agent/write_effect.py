"""Hash-only, durable one-shot fence for signed writes; no sender or retry loop.

Uses the existing read-back state vocabulary. A reservation is deliberately never
released: a crash before send cannot be distinguished from a crash after send.
Sonnet keeps its stronger fixed-contest journal and receipt verifier unchanged.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from pathlib import Path

from .wire_evidence import ReadBackStage


class WriteEffectError(RuntimeError):
    def __init__(self, stage: ReadBackStage, *, _unknown=ReadBackStage.EFFECT_UNKNOWN.value):
        self.stage = stage
        # Even a definitive verification failure does not prove write absence.
        self.effect_certainty = _unknown
        self.retry_allowed = False
        super().__init__(stage.value)


class WriteAttemptJournal:
    """Private directory and SQLite FULL commit before transport, across restarts."""
    __slots__ = ("root",)

    def __init__(self, root: Path):
        object.__setattr__(self, "root", Path(os.path.abspath(root)))

    def __setattr__(self, _name, _value):
        raise AttributeError("fixed write journal")

    def reserve(self, nonce_scope: str, operation: str, *,
                _error=WriteEffectError, _stages=ReadBackStage) -> None:
        if any(type(x) is not str or re.fullmatch(r"[0-9a-f]{64}", x) is None
               for x in (nonce_scope, operation)):
            raise _error(_stages.FAILED)
        connection = None
        try:
            # Refuse symlinks rather than resolving a caller-selected destination.
            for parent in reversed((self.root, *self.root.parents)):
                if parent.is_symlink():
                    raise OSError("unsafe directory")
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = self.root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise OSError("private directory required")
            database = self.root / "attempts.sqlite3"
            try:
                fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
            info = database.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise OSError("private database required")
            connection = sqlite3.connect(str(database), timeout=5)
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("CREATE TABLE IF NOT EXISTS attempts "
                               "(nonce_scope TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL)")
            expected = [(0, "nonce_scope", "TEXT", 0, None, 1),
                        (1, "operation", "TEXT", 1, None, 0)]
            if (connection.execute("PRAGMA table_info(attempts)").fetchall() != expected
                    or len(connection.execute("PRAGMA index_list(attempts)").fetchall()) != 2
                    or connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]):
                raise sqlite3.DatabaseError("journal schema invalid")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO attempts VALUES (?, ?)", (nonce_scope, operation))
            connection.commit()
            fd = os.open(self.root, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except sqlite3.IntegrityError:
            raise _error(_stages.DUPLICATE_SUPPRESSED) from None
        except (OSError, sqlite3.Error):
            raise _error(_stages.FAILED) from None
        finally:
            if connection is not None:
                connection.close()


def attempt_keys(did: str, room: str, nonce: str, text: str) -> tuple[str, str]:
    """Nonce reuse AND same-content/new-nonce retries are fenced independently."""
    def digest(parts: tuple[str, ...]) -> str:
        return hashlib.sha256(b"FLOP_WRITE_ATTEMPT_V1\0" + b"\0".join(
            part.encode("utf-8") for part in parts)).hexdigest()
    return digest((did, room, nonce)), digest((did, room, text))


_PRODUCTION_JOURNAL = WriteAttemptJournal(
    Path(__file__).resolve().parents[2] / "runtime" / "signed-write-attempts")
record_write_attempt = _PRODUCTION_JOURNAL.reserve
