"""
Test Compliance - Standards Compliance Tests
=============================================

These tests verify compliance with Kyber/ML-KEM specifications.
They pass, but they don't detect the vulnerability because they
only test "happy path" scenarios.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crystal_kem import CrystalKEM
from src.echo_chamber import EchoChamber, EchoChamberFactory
from src.fo_transform import FOTransform, DecapsulationResult


class TestKyberCompliance:
    """Tests for Kyber specification compliance."""
    
    def test_kyber768_key_sizes(self):
        """Verify Kyber768 key sizes match specification."""
        kem = CrystalKEM("Kyber768")
        pk, sk = kem.generate_keypair()
        
        # Kyber768 sizes from NIST specification
        assert len(pk) == 1184, f"Public key should be 1184 bytes, got {len(pk)}"
        assert len(sk) == 2400, f"Secret key should be 2400 bytes, got {len(sk)}"
    
    def test_kyber768_ciphertext_size(self):
        """Verify Kyber768 ciphertext size matches specification."""
        kem = CrystalKEM("Kyber768")
        pk, _ = kem.generate_keypair()
        ct, _ = kem.encapsulate()
        
        assert len(ct) == 1088, f"Ciphertext should be 1088 bytes, got {len(ct)}"
    
    def test_kyber768_shared_secret_size(self):
        """Verify shared secret size is 32 bytes."""
        kem = CrystalKEM("Kyber768")
        pk, _ = kem.generate_keypair()
        _, ss = kem.encapsulate()
        
        assert len(ss) == 32, f"Shared secret should be 32 bytes, got {len(ss)}"
    
    def test_deterministic_shared_secret(self):
        """Verify that encaps/decaps produce matching secrets."""
        kem = CrystalKEM("Kyber768")
        pk, sk = kem.generate_keypair()
        
        ct, ss_enc = kem.encapsulate()
        ss_dec = kem.decapsulate(ct)
        
        assert ss_enc == ss_dec, "Encapsulated and decapsulated secrets must match"
    
    def test_different_encapsulations(self):
        """Verify each encapsulation produces different ciphertext."""
        kem = CrystalKEM("Kyber768")
        pk, _ = kem.generate_keypair()
        
        ciphertexts = set()
        for _ in range(10):
            ct, _ = kem.encapsulate()
            ciphertexts.add(ct)
        
        assert len(ciphertexts) == 10, "Each encapsulation should produce unique ciphertext"


class TestProtocolCompliance:
    """Tests for protocol compliance."""
    
    def test_session_state_transitions(self):
        """Verify correct session state transitions."""
        from src.echo_chamber import SessionState
        
        chamber = EchoChamberFactory.create_vulnerable()
        
        # Initial state
        session = chamber.create_session("compliance_test")
        assert session.state == SessionState.INITIALIZED
        
        # After key generation
        chamber.generate_keys(session.session_id)
        session = chamber.get_session(session.session_id)
        assert session.state == SessionState.KEYS_GENERATED
    
    def test_encapsulation_to_external_key(self):
        """Verify encapsulation works with external public key."""
        import oqs
        
        # Generate external key
        external_kem = oqs.KeyEncapsulation("Kyber768")
        external_pk = external_kem.generate_keypair()
        external_sk = external_kem.export_secret_key()
        
        # Our chamber encapsulates to external key
        chamber = EchoChamberFactory.create_vulnerable()
        ct, ss_our = chamber.encapsulate(external_pk)
        
        # External party decapsulates
        ss_external = external_kem.decap_secret(ct)
        
        assert ss_our == ss_external
    
    def test_multiple_key_exchanges(self):
        """Verify multiple key exchanges work correctly."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        for i in range(5):
            session = chamber.create_session(f"exchange_{i}")
            pk, sk = chamber.generate_keys(session.session_id)
            
            # Simulate client
            client_chamber = EchoChamberFactory.create_vulnerable()
            ct, client_ss = client_chamber.encapsulate(pk)
            
            # Server decapsulates
            server_ss, result = chamber.decapsulate(ct, session_id=session.session_id)
            
            assert result == DecapsulationResult.SUCCESS
            assert client_ss == server_ss


class TestInteroperability:
    """Tests for interoperability with liboqs."""
    
    def test_liboqs_to_crystal(self):
        """Test key exchange: liboqs encapsulates, Crystal decapsulates."""
        import oqs
        
        # Crystal generates keys
        chamber = EchoChamberFactory.create_vulnerable()
        session = chamber.create_session("interop_1")
        pk, _ = chamber.generate_keys(session.session_id)
        
        # liboqs encapsulates
        liboqs_kem = oqs.KeyEncapsulation("Kyber768")
        ct, liboqs_ss = liboqs_kem.encap_secret(pk)
        
        # Crystal decapsulates
        crystal_ss, result = chamber.decapsulate(ct, session_id=session.session_id)
        
        assert result == DecapsulationResult.SUCCESS
        assert liboqs_ss == crystal_ss
    
    def test_crystal_to_liboqs(self):
        """Test key exchange: Crystal encapsulates, liboqs decapsulates."""
        import oqs
        
        # liboqs generates keys
        liboqs_kem = oqs.KeyEncapsulation("Kyber768")
        pk = liboqs_kem.generate_keypair()
        sk = liboqs_kem.export_secret_key()
        
        # Crystal encapsulates
        chamber = EchoChamberFactory.create_vulnerable()
        ct, crystal_ss = chamber.encapsulate(pk)
        
        # liboqs decapsulates
        liboqs_ss = liboqs_kem.decap_secret(ct)
        
        assert crystal_ss == liboqs_ss


class TestErrorHandling:
    """Tests for error handling (basic cases only)."""
    
    def test_missing_secret_key_raises(self):
        """Verify error when no secret key available."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        # Create session but don't generate keys
        session = chamber.create_session("no_keys")
        
        with pytest.raises(ValueError):
            chamber.decapsulate(b'\x00' * 1088, session_id=session.session_id)
    
    def test_unknown_session_raises(self):
        """Verify error for unknown session."""
        chamber = EchoChamberFactory.create_vulnerable()
        
        with pytest.raises(ValueError):
            chamber.generate_keys("nonexistent_session")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
