"""
Key Store - Secure Key Storage Module
=====================================

This module handles storage and retrieval of Kyber keypairs.
"""

import time
import hashlib
from typing import Optional, Dict, List
from dataclasses import dataclass, field

import sys
sys.path.insert(0, '..')
from include.constants import (
    MAX_KEY_STORE_SIZE,
    KEY_ROTATION_INTERVAL,
)


@dataclass
class KeyPair:
    """Represents a Kyber keypair."""
    key_id: str
    public_key: bytes
    secret_key: bytes
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        if self.expires_at is None:
            self.expires_at = self.created_at + KEY_ROTATION_INTERVAL
    
    def is_expired(self) -> bool:
        """Check if the keypair has expired."""
        return time.time() > self.expires_at
    
    def fingerprint(self) -> str:
        """Get a fingerprint of the public key."""
        return hashlib.sha256(self.public_key).hexdigest()[:16]


class KeyStore:
    """
    Secure storage for Kyber keypairs.
    
    Provides:
    - Key storage and retrieval
    - Key rotation
    - Expiration handling
    """
    
    def __init__(self, max_size: int = MAX_KEY_STORE_SIZE):
        """
        Initialize the key store.
        
        Args:
            max_size: Maximum number of keypairs to store
        """
        self._store: Dict[str, KeyPair] = {}
        self._max_size = max_size
        self._access_log: List[Dict] = []
    
    def store(self, keypair: KeyPair) -> bool:
        """
        Store a keypair.
        
        Args:
            keypair: The keypair to store
            
        Returns:
            True if stored successfully
        """
        # Check capacity
        if len(self._store) >= self._max_size:
            self._evict_oldest()
        
        self._store[keypair.key_id] = keypair
        self._log_access('store', keypair.key_id)
        return True
    
    def retrieve(self, key_id: str) -> Optional[KeyPair]:
        """
        Retrieve a keypair by ID.
        
        Args:
            key_id: The key identifier
            
        Returns:
            KeyPair if found, None otherwise
        """
        keypair = self._store.get(key_id)
        
        if keypair is None:
            self._log_access('retrieve_miss', key_id)
            return None
        
        if keypair.is_expired():
            self._log_access('retrieve_expired', key_id)
            del self._store[key_id]
            return None
        
        self._log_access('retrieve_hit', key_id)
        return keypair
    
    def delete(self, key_id: str) -> bool:
        """
        Delete a keypair.
        
        Args:
            key_id: The key identifier
            
        Returns:
            True if deleted, False if not found
        """
        if key_id in self._store:
            del self._store[key_id]
            self._log_access('delete', key_id)
            return True
        return False
    
    def get_by_fingerprint(self, fingerprint: str) -> Optional[KeyPair]:
        """
        Find a keypair by its public key fingerprint.
        
        Args:
            fingerprint: The public key fingerprint
            
        Returns:
            KeyPair if found, None otherwise
        """
        for keypair in self._store.values():
            if keypair.fingerprint() == fingerprint:
                return keypair
        return None
    
    def list_keys(self) -> List[Dict]:
        """
        List all stored keys (metadata only).
        
        Returns:
            List of key metadata dictionaries
        """
        return [
            {
                'key_id': kp.key_id,
                'fingerprint': kp.fingerprint(),
                'created_at': kp.created_at,
                'expires_at': kp.expires_at,
                'expired': kp.is_expired(),
            }
            for kp in self._store.values()
        ]
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired keypairs.
        
        Returns:
            Number of keypairs removed
        """
        expired = [
            key_id for key_id, kp in self._store.items()
            if kp.is_expired()
        ]
        
        for key_id in expired:
            del self._store[key_id]
        
        return len(expired)
    
    def _evict_oldest(self):
        """Evict the oldest keypair to make room."""
        if not self._store:
            return
        
        oldest_id = min(
            self._store.keys(),
            key=lambda k: self._store[k].created_at
        )
        del self._store[oldest_id]
        self._log_access('evict', oldest_id)
    
    def _log_access(self, action: str, key_id: str):
        """Log an access to the key store."""
        self._access_log.append({
            'action': action,
            'key_id': key_id,
            'timestamp': time.time(),
        })
        
        # Keep log size bounded
        if len(self._access_log) > 1000:
            self._access_log = self._access_log[-500:]
    
    def get_access_log(self) -> List[Dict]:
        """Get the access log."""
        return self._access_log.copy()
    
    def __len__(self) -> int:
        return len(self._store)
    
    def __contains__(self, key_id: str) -> bool:
        return key_id in self._store
