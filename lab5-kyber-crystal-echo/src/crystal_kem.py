"""
Crystal KEM - Kyber Key Encapsulation Mechanism Wrapper
=======================================================

This module provides a high-level wrapper around the liboqs Kyber
implementation, used by the Echo Chamber system.
"""

import oqs
import hashlib
import os
from typing import Tuple, Optional

import sys
sys.path.insert(0, '..')
from include.constants import (
    KYBER_VARIANT,
    KYBER768_PUBLIC_KEY_BYTES,
    KYBER768_SECRET_KEY_BYTES,
    KYBER768_CIPHERTEXT_BYTES,
    KYBER768_SHARED_SECRET_BYTES,
)


class CrystalKEM:
    """
    Crystal KEM: A Kyber-based Key Encapsulation Mechanism.
    
    This class wraps the liboqs Kyber implementation and provides
    the cryptographic primitives used by the Echo Chamber.
    """
    
    def __init__(self, variant: str = KYBER_VARIANT):
        """
        Initialize the Crystal KEM with specified Kyber variant.
        
        Args:
            variant: Kyber variant to use (Kyber512, Kyber768, Kyber1024)
        """
        self.variant = variant
        self._kem = oqs.KeyEncapsulation(variant)
        self._public_key: Optional[bytes] = None
        self._secret_key: Optional[bytes] = None
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Kyber keypair.
        
        Returns:
            Tuple of (public_key, secret_key)
        """
        self._public_key = self._kem.generate_keypair()
        self._secret_key = self._kem.export_secret_key()
        return self._public_key, self._secret_key
    
    def encapsulate(self, public_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the public key.
        
        Args:
            public_key: Public key to encapsulate to (uses stored key if None)
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        pk = public_key if public_key else self._public_key
        if pk is None:
            raise ValueError("No public key available for encapsulation")
        
        ciphertext, shared_secret = self._kem.encap_secret(pk)
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes, secret_key: Optional[bytes] = None) -> bytes:
        """
        Decapsulate a ciphertext to recover the shared secret.
        
        Note: This is the RAW decapsulation without FO transform.
        The Echo Chamber uses FOTransform for the full IND-CCA decapsulation.
        
        Args:
            ciphertext: The ciphertext to decapsulate
            secret_key: Secret key to use (uses stored key if None)
            
        Returns:
            The shared secret
        """
        if secret_key:
            # Create new KEM instance with the provided secret key
            temp_kem = oqs.KeyEncapsulation(self.variant, secret_key)
            return temp_kem.decap_secret(ciphertext)
        
        if self._secret_key is None:
            raise ValueError("No secret key available for decapsulation")
        
        return self._kem.decap_secret(ciphertext)
    
    def get_public_key(self) -> Optional[bytes]:
        """Get the stored public key."""
        return self._public_key
    
    def get_secret_key(self) -> Optional[bytes]:
        """Get the stored secret key."""
        return self._secret_key
    
    @staticmethod
    def hash_to_key(data: bytes, length: int = KYBER768_SHARED_SECRET_BYTES) -> bytes:
        """
        Hash arbitrary data to derive a key.
        
        Args:
            data: Data to hash
            length: Desired output length
            
        Returns:
            Derived key bytes
        """
        return hashlib.shake_256(data).digest(length)
    
    @staticmethod
    def get_random_bytes(length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes
        """
        return os.urandom(length)
    
    @property
    def ciphertext_length(self) -> int:
        """Get the ciphertext length for this variant."""
        return self._kem.details['length_ciphertext']
    
    @property
    def public_key_length(self) -> int:
        """Get the public key length for this variant."""
        return self._kem.details['length_public_key']
    
    @property
    def secret_key_length(self) -> int:
        """Get the secret key length for this variant."""
        return self._kem.details['length_secret_key']
    
    @property
    def shared_secret_length(self) -> int:
        """Get the shared secret length for this variant."""
        return self._kem.details['length_shared_secret']


class CrystalKEMFactory:
    """Factory for creating Crystal KEM instances."""
    
    _instances = {}
    
    @classmethod
    def get_instance(cls, variant: str = KYBER_VARIANT) -> CrystalKEM:
        """
        Get or create a Crystal KEM instance.
        
        Args:
            variant: Kyber variant to use
            
        Returns:
            CrystalKEM instance
        """
        if variant not in cls._instances:
            cls._instances[variant] = CrystalKEM(variant)
        return cls._instances[variant]
    
    @classmethod
    def clear_instances(cls):
        """Clear all cached instances."""
        cls._instances.clear()
