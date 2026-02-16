"""
Crystal Lattice Security Systems
================================

Echo Chamber Key Exchange Module v2.1

A post-quantum key encapsulation system based on CRYSTALS-Kyber.

WARNING: This implementation contains intentional vulnerabilities
for educational purposes. DO NOT use in production.
"""

from .crystal_kem import CrystalKEM
from .echo_chamber import EchoChamber
from .fo_transform import FOTransform
from .key_store import KeyStore
from .protocol_handler import ProtocolHandler

__version__ = "2.1.0"
__author__ = "Crystal Lattice Security Systems"
__all__ = [
    "CrystalKEM",
    "EchoChamber",
    "FOTransform",
    "KeyStore",
    "ProtocolHandler",
]
