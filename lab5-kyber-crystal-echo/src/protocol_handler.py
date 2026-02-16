"""
Protocol Handler - Network Protocol Implementation
==================================================

This module implements the network protocol for the Echo Chamber
key exchange system.
"""

import struct
import hashlib
import time
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from enum import IntEnum

import sys
sys.path.insert(0, '..')
from include.constants import (
    PROTOCOL_VERSION,
    MAGIC_HEADER,
    MESSAGE_TYPE_KEYGEN,
    MESSAGE_TYPE_ENCAPS,
    MESSAGE_TYPE_DECAPS,
    MESSAGE_TYPE_ERROR,
    ERROR_SUCCESS,
    ERROR_INVALID_CIPHERTEXT,
    ERROR_DECRYPTION_FAILED,
    ERROR_KEY_NOT_FOUND,
    DEBUG_MODE,
    VERBOSE_ERRORS,
)
from .echo_chamber import EchoChamber, DecapsulationResult


class MessageType(IntEnum):
    """Protocol message types."""
    KEYGEN = MESSAGE_TYPE_KEYGEN
    ENCAPS = MESSAGE_TYPE_ENCAPS
    DECAPS = MESSAGE_TYPE_DECAPS
    ERROR = MESSAGE_TYPE_ERROR


@dataclass
class ProtocolMessage:
    """Represents a protocol message."""
    msg_type: MessageType
    session_id: bytes
    payload: bytes
    timestamp: float
    checksum: bytes
    
    def serialize(self) -> bytes:
        """Serialize the message to bytes."""
        header = struct.pack(
            '>4sBB16sQ',
            MAGIC_HEADER,
            len(PROTOCOL_VERSION.encode()),
            self.msg_type,
            self.session_id[:16].ljust(16, b'\x00'),
            int(self.timestamp * 1000),
        )
        
        payload_len = struct.pack('>I', len(self.payload))
        checksum = hashlib.sha256(header + payload_len + self.payload).digest()[:8]
        
        return header + payload_len + self.payload + checksum
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'ProtocolMessage':
        """Deserialize a message from bytes."""
        if len(data) < 32:
            raise ValueError("Message too short")
        
        magic = data[:4]
        if magic != MAGIC_HEADER:
            raise ValueError(f"Invalid magic header: {magic}")
        
        version_len, msg_type, session_id, timestamp_ms = struct.unpack(
            '>BB16sQ', data[4:30]
        )
        
        payload_len = struct.unpack('>I', data[30:34])[0]
        payload = data[34:34+payload_len]
        checksum = data[34+payload_len:34+payload_len+8]
        
        return cls(
            msg_type=MessageType(msg_type),
            session_id=session_id.rstrip(b'\x00'),
            payload=payload,
            timestamp=timestamp_ms / 1000.0,
            checksum=checksum,
        )


class ProtocolHandler:
    """
    Handles the Crystal Echo protocol messages.
    
    This class provides the server-side logic for processing
    key exchange protocol messages.
    """
    
    def __init__(self, echo_chamber: EchoChamber):
        """
        Initialize the protocol handler.
        
        Args:
            echo_chamber: The Echo Chamber instance to use
        """
        self._chamber = echo_chamber
        self._sessions: Dict[bytes, Dict[str, Any]] = {}
        self._message_count = 0
    
    def process_message(self, data: bytes) -> bytes:
        """
        Process an incoming protocol message.
        
        Args:
            data: The raw message bytes
            
        Returns:
            Response message bytes
        """
        self._message_count += 1
        
        try:
            msg = ProtocolMessage.deserialize(data)
        except Exception as e:
            if VERBOSE_ERRORS:
                print(f"[PROTO] Failed to deserialize: {e}")
            return self._make_error_response(b'', ERROR_INVALID_CIPHERTEXT)
        
        if DEBUG_MODE:
            print(f"[PROTO] Received {msg.msg_type.name} from session {msg.session_id.hex()}")
        
        if msg.msg_type == MessageType.KEYGEN:
            return self._handle_keygen(msg)
        elif msg.msg_type == MessageType.ENCAPS:
            return self._handle_encaps(msg)
        elif msg.msg_type == MessageType.DECAPS:
            return self._handle_decaps(msg)
        else:
            return self._make_error_response(msg.session_id, ERROR_INVALID_CIPHERTEXT)
    
    def _handle_keygen(self, msg: ProtocolMessage) -> bytes:
        """Handle key generation request."""
        session_id = msg.session_id.hex() if msg.session_id else None
        
        # Create session and generate keys
        session = self._chamber.create_session(session_id)
        public_key, _ = self._chamber.generate_keys(session.session_id)
        
        # Store session info
        self._sessions[msg.session_id] = {
            'session_id': session.session_id,
            'state': 'keys_generated',
        }
        
        # Return public key
        response = ProtocolMessage(
            msg_type=MessageType.KEYGEN,
            session_id=msg.session_id,
            payload=public_key,
            timestamp=time.time(),
            checksum=b'',
        )
        
        return response.serialize()
    
    def _handle_encaps(self, msg: ProtocolMessage) -> bytes:
        """Handle encapsulation request."""
        # Payload should be the public key to encapsulate to
        public_key = msg.payload
        
        session_id = msg.session_id.hex() if msg.session_id else None
        
        try:
            ciphertext, shared_secret = self._chamber.encapsulate(
                public_key, 
                session_id
            )
        except Exception as e:
            if VERBOSE_ERRORS:
                print(f"[PROTO] Encapsulation failed: {e}")
            return self._make_error_response(msg.session_id, ERROR_INVALID_CIPHERTEXT)
        
        # Response contains ciphertext
        response = ProtocolMessage(
            msg_type=MessageType.ENCAPS,
            session_id=msg.session_id,
            payload=ciphertext,
            timestamp=time.time(),
            checksum=b'',
        )
        
        return response.serialize()
    
    def _handle_decaps(self, msg: ProtocolMessage) -> bytes:
        """
        Handle decapsulation request.
        
        """
        """
        ciphertext = msg.payload
        session_id_hex = msg.session_id.hex() if msg.session_id else None
        
        # Get session info
        session_info = self._sessions.get(msg.session_id, {})
        internal_session_id = session_info.get('session_id', session_id_hex)
        
        session = self._chamber.get_session(internal_session_id)
        if session is None:
            if VERBOSE_ERRORS:
                print(f"[PROTO] Session not found: {session_id_hex}")
            return self._make_error_response(msg.session_id, ERROR_KEY_NOT_FOUND)
        
        # Perform decapsulation
        try:
            shared_secret, result = self._chamber.decapsulate(
                ciphertext,
                session_id=internal_session_id
            )
        except Exception as e:
            if VERBOSE_ERRORS:
                print(f"[PROTO] Decapsulation error: {e}")
            return self._make_error_response(msg.session_id, ERROR_DECRYPTION_FAILED)
        
        # Check result
        if result == DecapsulationResult.SUCCESS:
            # Success - return indication (but not the shared secret directly)
            payload = struct.pack('>B', ERROR_SUCCESS) + hashlib.sha256(shared_secret).digest()[:8]
        else:
            # Handle error codes
            if VERBOSE_ERRORS:
                print(f"[PROTO] Decapsulation result: {result.name}")
            
            error_code = {
                DecapsulationResult.INVALID_LENGTH: ERROR_INVALID_CIPHERTEXT,
                DecapsulationResult.DECRYPTION_ERROR: ERROR_DECRYPTION_FAILED,
                DecapsulationResult.REENCRYPTION_MISMATCH: ERROR_INVALID_CIPHERTEXT,
                DecapsulationResult.VALIDATION_FAILED: ERROR_INVALID_CIPHERTEXT,
            }.get(result, ERROR_DECRYPTION_FAILED)
            
            payload = struct.pack('>B', error_code)
        
        response = ProtocolMessage(
            msg_type=MessageType.DECAPS,
            session_id=msg.session_id,
            payload=payload,
            timestamp=time.time(),
            checksum=b'',
        )
        
        return response.serialize()
    
    def _make_error_response(self, session_id: bytes, error_code: int) -> bytes:
        """Create an error response message."""
        response = ProtocolMessage(
            msg_type=MessageType.ERROR,
            session_id=session_id,
            payload=struct.pack('>B', error_code),
            timestamp=time.time(),
            checksum=b'',
        )
        return response.serialize()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get protocol handler statistics."""
        return {
            'messages_processed': self._message_count,
            'active_sessions': len(self._sessions),
            'chamber_stats': self._chamber.get_statistics(),
        }
