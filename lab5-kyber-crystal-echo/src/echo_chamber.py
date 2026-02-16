"""
Echo Chamber - Key Exchange Module (VULNERABLE)
================================================

The Echo Chamber is the main key exchange system built on top of the
vulnerable FO Transform. It provides a high-level API for key establishment
between parties.

"""

import oqs
import hashlib
import time
import json
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass, field
from enum import IntEnum

import sys
sys.path.insert(0, '..')
from include.constants import (
    KYBER_VARIANT,
    DEBUG_MODE,
    VERBOSE_ERRORS,
    LOG_TIMING,
    PROTOCOL_VERSION,
)
from .fo_transform import FOTransform, FOTransformSecure, DecapsulationResult
from .key_store import KeyStore, KeyPair


class SessionState(IntEnum):
    """State of a key exchange session."""
    INITIALIZED = 0
    KEYS_GENERATED = 1
    ENCAPSULATED = 2
    COMPLETED = 3
    FAILED = 4


@dataclass
class EchoSession:
    """Represents a key exchange session."""
    session_id: str
    state: SessionState = SessionState.INITIALIZED
    public_key: Optional[bytes] = None
    secret_key: Optional[bytes] = None
    ciphertext: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Debugging/Forensics information
    _internal_state: Dict[str, Any] = field(default_factory=dict)


class EchoChamber:
    """
    Echo Chamber Key Exchange System.
    
    This is the main interface for performing post-quantum key exchanges
    using the Kyber KEM.
    
    """
    
    def __init__(
        self, 
        variant: str = KYBER_VARIANT,
        use_secure_transform: bool = False
    ):
        """
        Initialize the Echo Chamber.
        
        Args:
            variant: Kyber variant to use
            use_secure_transform: If True, uses secure FO transform (for testing)
        """
        self.variant = variant
        self._kem = oqs.KeyEncapsulation(variant)
        self._key_store = KeyStore()
        
        # Choose transform implementation
        if use_secure_transform:
            self._transform = FOTransformSecure(variant)
        else:
            self._transform = FOTransform(variant)
        
        self._sessions: Dict[str, EchoSession] = {}
        self._stats = {
            'total_decapsulations': 0,
            'successful_decapsulations': 0,
            'failed_decapsulations': 0,
            'skipped_reencryption': 0,
        }
        
    def create_session(self, session_id: Optional[str] = None) -> EchoSession:
        """
        Create a new key exchange session.
        
        Args:
            session_id: Optional session identifier
            
        Returns:
            New EchoSession instance
        """
        if session_id is None:
            session_id = hashlib.sha256(
                str(time.time()).encode() + 
                oqs.randombytes(16)
            ).hexdigest()[:16]
        
        session = EchoSession(session_id=session_id)
        self._sessions[session_id] = session
        
        if DEBUG_MODE:
            print(f"[SESSION] Created session: {session_id}")
        
        return session
    
    def generate_keys(self, session_id: str) -> Tuple[bytes, bytes]:
        """
        Generate a keypair for a session.
        
        Args:
            session_id: The session to generate keys for
            
        Returns:
            Tuple of (public_key, secret_key)
        """
        if session_id not in self._sessions:
            raise ValueError(f"Unknown session: {session_id}")
        
        session = self._sessions[session_id]
        
        # Generate new keypair
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        
        # Store in session
        session.public_key = public_key
        session.secret_key = secret_key
        session.state = SessionState.KEYS_GENERATED
        
        # Also store in key store
        key_pair = KeyPair(
            key_id=session_id,
            public_key=public_key,
            secret_key=secret_key
        )
        self._key_store.store(key_pair)
        
        if DEBUG_MODE:
            print(f"[SESSION] Generated keys for session: {session_id}")
            print(f"[DEBUG] Public key length: {len(public_key)}")
        
        return public_key, secret_key
    
    def encapsulate(
        self, 
        public_key: bytes,
        session_id: Optional[str] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret to a public key.
        
        Args:
            public_key: The public key to encapsulate to
            session_id: Optional session to associate with
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            session.ciphertext = ciphertext
            session.shared_secret = shared_secret
            session.state = SessionState.ENCAPSULATED
        
        if DEBUG_MODE:
            print(f"[ENCAPS] Created ciphertext of length: {len(ciphertext)}")
        
        return ciphertext, shared_secret
    
    def decapsulate(
        self,
        ciphertext: bytes,
        session_id: Optional[str] = None,
        secret_key: Optional[bytes] = None,
        public_key: Optional[bytes] = None
    ) -> Tuple[bytes, DecapsulationResult]:
        """
        Decapsulate a ciphertext to recover the shared secret.
        
        
        Args:
            ciphertext: The ciphertext to decapsulate
            session_id: Session to use keys from
            secret_key: Secret key (overrides session key)
            public_key: Public key (needed for FO transform)
            
        Returns:
            Tuple of (shared_secret, result_code)
        """
        start_time = time.perf_counter()
        self._stats['total_decapsulations'] += 1
        
        # Get keys from session or parameters
        sk = secret_key
        pk = public_key
        
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            if sk is None:
                sk = session.secret_key
            if pk is None:
                pk = session.public_key
        
        if sk is None:
            raise ValueError("No secret key available")
        if pk is None:
            raise ValueError("No public key available for FO transform")
        
        # Perform decapsulation using the (vulnerable) FO transform
        if isinstance(self._transform, FOTransformSecure):
            # Secure path
            shared_secret = self._transform.decapsulate(ciphertext, sk)
            result = DecapsulationResult.SUCCESS
        else:
            # Vulnerable path
            shared_secret, result = self._transform.decapsulate(ciphertext, sk, pk)
        
        # Update statistics
        if result == DecapsulationResult.SUCCESS:
            self._stats['successful_decapsulations'] += 1
        else:
            self._stats['failed_decapsulations'] += 1
        
        # Record timing
        elapsed = time.perf_counter() - start_time
        
        if LOG_TIMING:
            print(f"[TIMING] Decapsulation took: {elapsed*1000:.3f}ms")
        
        # Update session state
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            session.shared_secret = shared_secret
            session._internal_state['last_decaps_time'] = elapsed
            session._internal_state['last_decaps_result'] = result
            
            if result == DecapsulationResult.SUCCESS:
                session.state = SessionState.COMPLETED
                session.completed_at = time.time()
            else:
                session.state = SessionState.FAILED
                session._internal_state['failure_reason'] = result.name
        
        return shared_secret, result
    
    def decapsulate_batch(
        self,
        ciphertexts: list,
        secret_key: bytes,
        public_key: bytes
    ) -> list:
        """
        Decapsulate multiple ciphertexts.
        
        """
        Decapsulate multiple ciphertexts.
        
        
        Args:
            ciphertexts: List of ciphertexts to decapsulate
            secret_key: The secret key to use
            public_key: The public key for FO transform
            
        Returns:
            List of (shared_secret, result_code) tuples
        """
        results = []
        timings = []
        
        for ct in ciphertexts:
            start = time.perf_counter()
            result = self.decapsulate(ct, secret_key=secret_key, public_key=public_key)
            elapsed = time.perf_counter() - start
            
            results.append(result)
            timings.append(elapsed)
        
        # Log timing information
        if DEBUG_MODE:
            for i, (t, r) in enumerate(zip(timings, results)):
                print(f"[BATCH] CT {i}: {t*1000:.3f}ms, result={r[1].name}")
        
        return results
    
    def get_session(self, session_id: str) -> Optional[EchoSession]:
        """Get a session by ID."""
        return self._sessions.get(session_id)
    
    def get_session_state(self, session_id: str) -> Dict[str, Any]:
        """
        Get the internal state of a session.
        
        Get the internal state of a session.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return {}
        
        return {
            'state': session.state.name,
            'created_at': session.created_at,
            'completed_at': session.completed_at,
            'has_shared_secret': session.shared_secret is not None,
            'internal': session._internal_state,
        }
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get system statistics.
        
        Get system statistics.
        """
        return self._stats.copy()
    
    def get_last_transform_state(self):
        """
        Get the state from the last FO transform operation.
        
        """
        Get the state from the last FO transform operation.
        """
        if isinstance(self._transform, FOTransform):
            return self._transform.get_last_state()
        return None
    
    def validate_ciphertext(self, ciphertext: bytes) -> Dict[str, Any]:
        """
        Validate a ciphertext without decapsulating.
        
        Validate a ciphertext without decapsulating.
        
        
        Args:
            ciphertext: The ciphertext to validate
            
        Returns:
            Dictionary with validation results
        """
        result = {
            'length_valid': len(ciphertext) == self._kem.details['length_ciphertext'],
            'length_actual': len(ciphertext),
            'length_expected': self._kem.details['length_ciphertext'],
        }
        
        # Additional checks
        if result['length_valid']:
            byte_set = set(ciphertext)
            result['unique_bytes'] = len(byte_set)
            result['entropy_estimate'] = len(byte_set) / 256.0
            
            # Check for obvious patterns
            result['all_zeros'] = all(b == 0 for b in ciphertext)
            result['all_ones'] = all(b == 0xFF for b in ciphertext)
            
            # Check if re-encryption would be skipped
            if isinstance(self._transform, FOTransform):
                result['would_skip_reencryption'] = self._transform._should_skip_reencryption(ciphertext)
        
        return result
    
    def compare_with_reference(
        self,
        ciphertext: bytes,
        secret_key: bytes
    ) -> Dict[str, Any]:
        """
        Compare vulnerable decapsulation with reference implementation.
        
        This is for testing/debugging - reveals if there's a discrepancy.
        
        Compare vulnerable decapsulation with reference implementation.
        """
        # Get public key
        temp_kem = oqs.KeyEncapsulation(self.variant, secret_key)
        public_key = temp_kem.export_public_key() if hasattr(temp_kem, 'export_public_key') else None
        
        # If we can't get public key, generate new keypair
        if public_key is None:
            temp_kem = oqs.KeyEncapsulation(self.variant)
            public_key = temp_kem.generate_keypair()
            secret_key = temp_kem.export_secret_key()
        
        # Vulnerable implementation
        vuln_transform = FOTransform(self.variant)
        try:
            vuln_ss, vuln_result = vuln_transform.decapsulate(ciphertext, secret_key, public_key)
        except Exception as e:
            vuln_ss = None
            vuln_result = str(e)
        
        # Reference implementation
        ref_transform = FOTransformSecure(self.variant)
        try:
            ref_ss = ref_transform.decapsulate(ciphertext, secret_key)
        except Exception as e:
            ref_ss = None
        
        # Compare results
        return {
            'vulnerable_result': vuln_result if isinstance(vuln_result, str) else vuln_result.name,
            'results_match': vuln_ss == ref_ss,
            'vulnerable_ss_hex': vuln_ss.hex() if vuln_ss else None,
            'reference_ss_hex': ref_ss.hex() if ref_ss else None,
        }


class EchoChamberFactory:
    """Factory for creating Echo Chamber instances."""
    
    @staticmethod
    def create_vulnerable(variant: str = KYBER_VARIANT) -> EchoChamber:
        """Create a vulnerable Echo Chamber instance."""
        return EchoChamber(variant, use_secure_transform=False)
    
    @staticmethod
    def create_secure(variant: str = KYBER_VARIANT) -> EchoChamber:
        """Create a secure Echo Chamber instance (for comparison)."""
        return EchoChamber(variant, use_secure_transform=True)
