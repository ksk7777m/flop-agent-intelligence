"""Load only reviewed, hash-pinned, repository-owned offline reference code."""
import hashlib
import importlib.util
import sys
from pathlib import Path

_REFERENCES = {
    "yellowpaper": (
        "vendor/yellowpaper/3c97bbc8d6ba68cf2ea003ab88bc154aafdf105e/compute_channel.py",
        "fbe09cd2ba88b0e2f82ace7775c10e1642002c2030fa5b344d4d4f8ac10666c5"),
    "close_call": (
        "vendor/close_call/0ae6b063107b77e3a6cb794186fdd341a947e5e1/close_call_fold.py",
        "19e13cd15dd4e9078b608a94776947bb52bba86367446d0a405c0b05c85173d4"),
}


def load_reference(name):
    relative, digest = _REFERENCES[name]
    root = Path(__file__).resolve().parents[2]
    path = root / relative
    if (path.is_symlink() or root not in path.resolve().parents
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        raise ValueError("OFFLINE_REFERENCE_HASH_MISMATCH")
    module_name = "_flop_offline_" + name
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
