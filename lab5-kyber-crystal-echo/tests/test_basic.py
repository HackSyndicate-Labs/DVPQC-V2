"""
Test Basic - Basic functionality tests
======================================

These tests verify that the basic functionality works correctly.
They should all pass, but they don't detect the vulnerability.
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crystal_kem import CrystalKEM
from src.echo_chamber import EchoChamber, EchoChamberFactory, SessionState
from src.fo_transform import FOTransform, DecapsulationResult
from src.key_store import KeyStore, KeyPair


class TestCrystalKEM:
    """Tests for the CrystalKEM class."""
    
    def test_keypair_generation(self):
        """Test that keypair generation works."""
        kem = CrystalKEM()
        public_key, secret_key = kem.generate_keypair()
        
        assert public_key is not None
        assert secret_key is not None
        assert len(public_key) == 1184  # Kyber768
        assert len(secret_key) == 2400  # Kyber768
    
    def test_encapsulation(self):
        """Test that encapsulation produces correct output."""
        kem = CrystalKEM()
        public_key, _ = kem.generate_keypair()
        
        ciphertext, shared_secret = kem.encapsulate()
        
        assert ciphertext is not None
        assert shared_secret is not None
        assert len(ciphertext) == 1088  # Kyber768
        assert len(shared_secret) == 32
    
    def test_decapsulation(self):
        """Test that decapsulation recovers the shared secret."""
        kem = CrystalKEM()
        public_key, secret_key = kem.generate_keypair()
        
        ciphertext, shared_secret_enc = kem.encapsulate()
        shared_secret_dec = kem.decapsulate(ciphertext)
        
        assert shared_secret_enc == shared_secret_dec
    
    def test_different_keys_different_secrets(self):
        """Test that different keys produce different shared secrets."""
        kem1 = CrystalKEM()
        kem2 = CrystalKEM()
        
        pk1, _ = kem1.generate_keypair()
        pk2, _ = kem2.generate_keypair()
        
        ct1, ss1 = kem1.encapsulate()
        ct2, ss2 = kem2.encapsulate()
        
        # Different ciphertexts and shared secrets
        assert ct1 != ct2
        assert ss1 != ss2


class TestEchoChamber:
    """Tests for the EchoChamber class."""
    
    def test_session_creation(self):
        """Test session creation."""
        chamber = EchoChamberFactory.create_vulnerable()
        session = chamber.create_session()
        
        assert session is not None
        assert session.session_id is not None
        assert session.state == SessionState.INITIALIZED
    
    def test_key_generation(self):
        """Test key generation for a session."""
        chamber = EchoChamberFactory.create_vulnerable()
        session = chamber.create_session("test_session")
        
        pk, sk = chamber.generate_keys(session.session_id)
        
        assert pk is not None
        assert sk is not None
        assert session.state == SessionState.KEYS_GENERATED
    
    def test_full_key_exchange(self):
        """Test a full key exchange."""
        # Server side
        server = EchoChamberFactory.create_vulnerable()
        server_session = server.create_session("server")
        server_pk, server_sk = server.generate_keys("server")
        
        # Client side encapsulates to server's public key
        client = EchoChamberFactory.create_vulnerable()
        ciphertext, client_ss = client.encapsulate(server_pk)
        
        # Server decapsulates
        server_ss, result = server.decapsulate(
            ciphertext,
            session_id="server"
        )
        
        # Both should have same shared secret
        assert result == DecapsulationResult.SUCCESS
        assert client_ss == server_ss
    
    def test_multiple_sessions(self):
        """Test multiple concurrent sessions."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        sessions = []
        for i in range(5):
            session = chamber.create_session(f"session_{i}")
            chamber.generate_keys(session.session_id)
            sessions.append(session)
        
        assert len(sessions) == 5
        for session in sessions:
            assert session.public_key is not None


class TestKeyStore:
    """Tests for the KeyStore class."""
    
    def test_store_and_retrieve(self):
        """Test storing and retrieving a keypair."""
        store = KeyStore()
        
        keypair = KeyPair(
            key_id="test_key",
            public_key=b"public" * 100,
            secret_key=b"secret" * 100,
        )
        
        assert store.store(keypair)
        retrieved = store.retrieve("test_key")
        
        assert retrieved is not None
        assert retrieved.public_key == keypair.public_key
    
    def test_delete(self):
        """Test deleting a keypair."""
        store = KeyStore()
        
        keypair = KeyPair(
            key_id="to_delete",
            public_key=b"public",
            secret_key=b"secret",
        )
        
        store.store(keypair)
        assert store.delete("to_delete")
        assert store.retrieve("to_delete") is None
    
    def test_fingerprint(self):
        """Test keypair fingerprint."""
        keypair = KeyPair(
            key_id="test",
            public_key=b"test_public_key",
            secret_key=b"test_secret_key",
        )
        
        fingerprint = keypair.fingerprint()
        assert len(fingerprint) == 16  # 16 hex chars


class TestFOTransform:
    """Tests for the FO Transform."""
    
    def test_valid_decapsulation(self):
        """Test decapsulation with valid ciphertext."""
        import oqs
        
        # Generate keys
        kem = oqs.KeyEncapsulation("Kyber768")
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        
        # Encapsulate
        ciphertext, expected_ss = kem.encap_secret(public_key)
        
        # Decapsulate using our transform
        transform = FOTransform()
        actual_ss, result = transform.decapsulate(ciphertext, secret_key, public_key)
        
        # Should succeed (or at least not crash)
        assert actual_ss is not None
        assert len(actual_ss) == 32
    
    def test_invalid_length_ciphertext(self):
        """Test decapsulation with wrong length ciphertext."""
        import oqs
        
        kem = oqs.KeyEncapsulation("Kyber768")
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        
        transform = FOTransform()
        
        # Too short
        short_ct = b'\x00' * 100
        ss, result = transform.decapsulate(short_ct, secret_key, public_key)
        assert result == DecapsulationResult.INVALID_LENGTH
        
        # Too long
        long_ct = b'\x00' * 2000
        ss, result = transform.decapsulate(long_ct, secret_key, public_key)
        assert result == DecapsulationResult.INVALID_LENGTH


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
