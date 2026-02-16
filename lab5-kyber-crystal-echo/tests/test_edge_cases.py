"""
Test Edge Cases - Edge Case Testing
====================================

These tests cover edge cases but STILL don't detect the vulnerability.
The vulnerability requires specific crafted inputs that these tests
don't generate.
"""

import pytest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crystal_kem import CrystalKEM
from src.echo_chamber import EchoChamber, EchoChamberFactory
from src.fo_transform import FOTransform, FOTransformSecure, DecapsulationResult
from src.key_store import KeyStore, KeyPair


class TestCiphertextEdgeCases:
    """Edge case tests for ciphertext handling."""
    
    def test_zero_ciphertext(self):
        """Test handling of all-zero ciphertext."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        
        transform = FOTransform()
        zero_ct = b'\x00' * 1088
        
        # Should handle gracefully (not crash)
        ss, result = transform.decapsulate(zero_ct, sk, pk)
        
        assert ss is not None
        # Result may vary, but shouldn't crash
    
    def test_max_ciphertext(self):
        """Test handling of all-0xFF ciphertext."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        
        transform = FOTransform()
        max_ct = b'\xFF' * 1088
        
        ss, result = transform.decapsulate(max_ct, sk, pk)
        assert ss is not None
    
    def test_truncated_ciphertext(self):
        """Test handling of truncated ciphertext."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        
        # Generate valid ciphertext then truncate
        ct, _ = kem.encap_secret(pk)
        truncated = ct[:500]
        
        transform = FOTransform()
        ss, result = transform.decapsulate(truncated, sk, pk)
        
        assert result == DecapsulationResult.INVALID_LENGTH
    
    def test_extended_ciphertext(self):
        """Test handling of extended ciphertext."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        
        # Generate valid ciphertext then extend
        ct, _ = kem.encap_secret(pk)
        extended = ct + b'\x00' * 100
        
        transform = FOTransform()
        ss, result = transform.decapsulate(extended, sk, pk)
        
        assert result == DecapsulationResult.INVALID_LENGTH
    
    def test_random_ciphertext(self):
        """Test handling of random ciphertext."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        
        transform = FOTransform()
        random_ct = os.urandom(1088)
        
        # Should handle gracefully
        ss, result = transform.decapsulate(random_ct, sk, pk)
        assert ss is not None


class TestSessionEdgeCases:
    """Edge case tests for session handling."""
    
    def test_reuse_session_id(self):
        """Test reusing a session ID."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        # Create session
        session1 = chamber.create_session("reuse_test")
        chamber.generate_keys("reuse_test")
        
        # Create another with same ID (should work or replace)
        session2 = chamber.create_session("reuse_test")
        
        # Both should reference same session
        retrieved = chamber.get_session("reuse_test")
        assert retrieved is not None
    
    def test_empty_session_id(self):
        """Test with empty session ID."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        # Should auto-generate ID
        session = chamber.create_session(None)
        assert session.session_id is not None
        assert len(session.session_id) > 0
    
    def test_many_sessions(self):
        """Test creating many sessions."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        sessions = []
        for i in range(100):
            session = chamber.create_session(f"session_{i:03d}")
            sessions.append(session)
        
        assert len(sessions) == 100
        
        # All should be retrievable
        for i in range(100):
            s = chamber.get_session(f"session_{i:03d}")
            assert s is not None


class TestKeyStoreEdgeCases:
    """Edge case tests for key store."""
    
    def test_store_many_keys(self):
        """Test storing many keys."""
        store = KeyStore(max_size=50)
        
        for i in range(100):
            kp = KeyPair(
                key_id=f"key_{i}",
                public_key=os.urandom(1184),
                secret_key=os.urandom(2400),
            )
            store.store(kp)
        
        # Should have evicted old keys
        assert len(store) <= 50
    
    def test_retrieve_nonexistent(self):
        """Test retrieving nonexistent key."""
        store = KeyStore()
        
        result = store.retrieve("nonexistent")
        assert result is None
    
    def test_delete_nonexistent(self):
        """Test deleting nonexistent key."""
        store = KeyStore()
        
        result = store.delete("nonexistent")
        assert result is False


class TestTimingBehavior:
    """
    Tests for timing behavior.
    
    NOTE: These tests check that operations complete in reasonable time,
    but they DON'T test for constant-time behavior (which is the vulnerability).
    """
    
    def test_decapsulation_completes(self):
        """Test that decapsulation completes in reasonable time."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        ct, _ = kem.encap_secret(pk)
        
        transform = FOTransform()
        
        start = time.time()
        ss, result = transform.decapsulate(ct, sk, pk)
        elapsed = time.time() - start
        
        # Should complete quickly (< 1 second)
        assert elapsed < 1.0
    
    def test_batch_decapsulation_timing(self):
        """Test batch decapsulation timing."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        
        # Generate batch of ciphertexts
        ciphertexts = []
        for _ in range(10):
            ct, _ = kem.encap_secret(pk)
            ciphertexts.append(ct)
        
        chamber = EchoChamberFactory.create_vulnerable()
        session = chamber.create_session("timing_test")
        chamber._sessions[session.session_id].secret_key = sk
        chamber._sessions[session.session_id].public_key = pk
        
        start = time.time()
        results = chamber.decapsulate_batch(ciphertexts, sk, pk)
        elapsed = time.time() - start
        
        assert len(results) == 10
        # Should complete reasonably fast
        assert elapsed < 5.0


class TestValidation:
    """Tests for input validation."""
    
    def test_validate_ciphertext_oracle(self):
        """Test the ciphertext validation oracle."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        # Valid length
        valid_ct = os.urandom(1088)
        result = chamber.validate_ciphertext(valid_ct)
        assert result['length_valid'] is True
        
        # Invalid length
        invalid_ct = os.urandom(500)
        result = chamber.validate_ciphertext(invalid_ct)
        assert result['length_valid'] is False
    
    def test_entropy_estimation(self):
        """Test entropy estimation in validation."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        # High entropy
        high_entropy_ct = os.urandom(1088)
        result = chamber.validate_ciphertext(high_entropy_ct)
        assert result['entropy_estimate'] > 0.5
        
        # Low entropy
        low_entropy_ct = bytes([i % 16 for i in range(1088)])
        result = chamber.validate_ciphertext(low_entropy_ct)
        assert result['entropy_estimate'] < 0.1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
