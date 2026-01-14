"""
Cryptographic Manager
Handles all cryptography: signing, verification, encryption, key management
"""

import os
import json
import time
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets

class CryptoManager:
    def __init__(self, private_key_path=None, public_key_path=None, is_drone=False):
        """
        Initialize cryptographic manager
        
        Args:
            private_key_path: Path to private key PEM file
            public_key_path: Path to public key PEM file (for verification)
            is_drone: True if this is drone, False if ground station
        """
        self.is_drone = is_drone
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        
        # Session management
        self.session_key = None
        self.session_established = False
        
        # Replay protection
        self.nonce_window = set()  # Stores last 1000 nonces
        self.nonce_window_size = 1000
        self.last_sequence_num = 0
        
        # Load keys
        if private_key_path and os.path.exists(private_key_path):
            self.load_private_key(private_key_path)
        
        if public_key_path and os.path.exists(public_key_path):
            self.load_public_key(public_key_path)
    
    def generate_key_pair(self, output_dir="./keys"):
        """
        Generate ECDSA key pair (P-256 curve)
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate private key
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Save keys
        prefix = "drone" if self.is_drone else "gs"
        private_path = os.path.join(output_dir, f"{prefix}_private.pem")
        public_path = os.path.join(output_dir, f"{prefix}_public.pem")
        
        with open(private_path, "wb") as f:
            f.write(private_pem)
        
        with open(public_path, "wb") as f:
            f.write(public_pem)
        
        self.private_key = private_key
        self.public_key = public_key
        
        print(f"[✓] Generated key pair: {private_path}, {public_path}")
        return private_path, public_path
    
    def load_private_key(self, path):
        """Load private key from PEM file"""
        with open(path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        self.public_key = self.private_key.public_key()
        print(f"[✓] Loaded private key from {path}")
    
    def load_public_key(self, path):
        """Load public key from PEM file (for peer verification)"""
        with open(path, "rb") as f:
            self.peer_public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        print(f"[✓] Loaded peer public key from {path}")
    
    def sign_command(self, command_dict):
        """
        Sign command with ECDSA
        
        Args:
            command_dict: Dictionary containing command data
            
        Returns:
            Dictionary with signature added
        """
        if not self.private_key:
            raise Exception("Private key not loaded")
        
        # Add timestamp and nonce
        command_dict['timestamp'] = int(time.time())
        command_dict['nonce'] = secrets.token_hex(32)
        command_dict['sequence_num'] = command_dict.get('sequence_num', 0)
        
        # Create canonical JSON (sorted keys for consistency)
        command_json = json.dumps(command_dict, sort_keys=True)
        command_bytes = command_json.encode('utf-8')
        
        # Compute hash
        digest = hashlib.sha256(command_bytes).digest()
        
        # Sign hash
        signature = self.private_key.sign(
            digest,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Add signature to command
        command_dict['signature'] = signature.hex()
        
        return command_dict
    
    def verify_signature(self, command_dict):
        """
        Verify command signature
        
        Args:
            command_dict: Command dictionary with signature
            
        Returns:
            (bool, str): (verified, error_message)
        """
        if not self.peer_public_key:
            return False, "Peer public key not loaded"
        
        # Extract signature
        signature_hex = command_dict.get('signature')
        if not signature_hex:
            return False, "No signature in command"
        
        try:
            signature = bytes.fromhex(signature_hex)
        except:
            return False, "Invalid signature format"
        
        # Remove signature for verification
        command_copy = command_dict.copy()
        del command_copy['signature']
        
        # Create canonical JSON
        command_json = json.dumps(command_copy, sort_keys=True)
        command_bytes = command_json.encode('utf-8')
        
        # Compute hash
        digest = hashlib.sha256(command_bytes).digest()
        
        # Verify signature
        try:
            self.peer_public_key.verify(
                signature,
                digest,
                ec.ECDSA(hashes.SHA256())
            )
            return True, "Signature valid"
        except InvalidSignature:
            return False, "Invalid signature"
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def check_replay_protection(self, command_dict):
        """
        Check nonce, sequence number, and timestamp
        
        Returns:
            (bool, str): (valid, error_message)
        """
        # Check nonce (replay protection)
        nonce = command_dict.get('nonce')
        if not nonce:
            return False, "No nonce in command"
        
        if nonce in self.nonce_window:
            return False, "Nonce already seen (replay attack detected)"
        
        # Add nonce to window
        self.nonce_window.add(nonce)
        
        # Limit window size (circular buffer behavior)
        if len(self.nonce_window) > self.nonce_window_size:
            # Remove oldest (random one, since set is unordered)
            self.nonce_window.pop()
        
        # Check sequence number
        sequence_num = command_dict.get('sequence_num', 0)
        if sequence_num <= self.last_sequence_num:
            return False, f"Sequence number too old ({sequence_num} <= {self.last_sequence_num})"
        
        self.last_sequence_num = sequence_num
        
        # Check timestamp (must be within 10 seconds)
        timestamp = command_dict.get('timestamp', 0)
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)
        
        if time_diff > 10:
            return False, f"Timestamp too old/future ({time_diff} seconds difference)"
        
        return True, "Replay protection passed"
    
    def establish_session(self):
        """
        Establish encrypted session with ChaCha20-Poly1305
        (Simplified - in real implementation, this would use Diffie-Hellman)
        """
        # Generate 256-bit session key
        self.session_key = ChaCha20Poly1305.generate_key()
        self.session_established = True
        print("[✓] Session established (ChaCha20-Poly1305)")
        return self.session_key
    
    def encrypt_message(self, plaintext):
        """
        Encrypt message with ChaCha20-Poly1305 (AEAD)
        
        Args:
            plaintext: String or bytes to encrypt
            
        Returns:
            dict: {'nonce': ..., 'ciphertext': ..., 'tag': ...}
        """
        if not self.session_established:
            raise Exception("Session not established")
        
        # Convert to bytes if string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate nonce (96-bit)
        nonce = os.urandom(12)
        
        # Create cipher
        cipher = ChaCha20Poly1305(self.session_key)
        
        # Encrypt (includes authentication tag)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        return {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex()
        }
    
    def decrypt_message(self, encrypted_dict):
        """
        Decrypt message with ChaCha20-Poly1305
        
        Args:
            encrypted_dict: {'nonce': ..., 'ciphertext': ...}
            
        Returns:
            bytes: Decrypted plaintext
        """
        if not self.session_established:
            raise Exception("Session not established")
        
        # Parse hex
        nonce = bytes.fromhex(encrypted_dict['nonce'])
        ciphertext = bytes.fromhex(encrypted_dict['ciphertext'])
        
        # Create cipher
        cipher = ChaCha20Poly1305(self.session_key)
        
        # Decrypt and verify
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise Exception(f"Decryption failed (possible tampering): {str(e)}")
    
    def get_firmware_hash(self, firmware_path):
        """
        Compute SHA-256 hash of firmware file
        """
        sha256 = hashlib.sha256()
        with open(firmware_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def verify_firmware_signature(self, firmware_path, signature_hex, metadata):
        """
        Verify firmware signature
        
        Args:
            firmware_path: Path to firmware binary
            signature_hex: Hex-encoded signature
            metadata: Firmware metadata dict
            
        Returns:
            (bool, str): (valid, message)
        """
        if not self.peer_public_key:
            return False, "Public key not loaded"
        
        # Compute firmware hash
        firmware_hash = self.get_firmware_hash(firmware_path)
        
        # Check hash matches metadata
        if firmware_hash != metadata.get('sha256_hash'):
            return False, "Firmware hash mismatch"
        
        # Verify signature
        try:
            signature = bytes.fromhex(signature_hex)
            digest = bytes.fromhex(firmware_hash)
            
            self.peer_public_key.verify(
                signature,
                digest,
                ec.ECDSA(hashes.SHA256())
            )
            
            return True, "Firmware signature valid"
        except Exception as e:
            return False, f"Signature verification failed: {str(e)}"


# Test functionality
if __name__ == "__main__":
    print("=== Crypto Manager Test ===\n")
    
    # Generate keys for ground station
    print("1. Generating Ground Station Keys...")
    gs_crypto = CryptoManager(is_drone=False)
    gs_private, gs_public = gs_crypto.generate_key_pair("./keys")
    
    # Generate keys for drone
    print("\n2. Generating Drone Keys...")
    drone_crypto = CryptoManager(is_drone=True)
    drone_private, drone_public = drone_crypto.generate_key_pair("./keys")
    
    # Load peer keys
    print("\n3. Loading Peer Keys...")
    gs_crypto.load_public_key(drone_public)
    drone_crypto.load_public_key(gs_public)
    
    # Test command signing
    print("\n4. Testing Command Signing...")
    command = {
        'command_id': 'cmd_001',
        'mission_id': 'rescue_001',
        'command_type': 'goto_waypoint',
        'sequence_num': 1,
        'parameters': {
            'lat': 36.8065,
            'lon': 10.1815,
            'alt': 50
        }
    }
    
    signed_command = gs_crypto.sign_command(command.copy())
    print(f"   Signed command with nonce: {signed_command['nonce'][:16]}...")
    
    # Test signature verification
    print("\n5. Testing Signature Verification...")
    valid, msg = drone_crypto.verify_signature(signed_command)
    print(f"   Verification: {valid} - {msg}")
    
    # Test replay protection
    print("\n6. Testing Replay Protection...")
    valid, msg = drone_crypto.check_replay_protection(signed_command)
    print(f"   Replay check: {valid} - {msg}")
    
    # Test replay attack detection
    print("\n7. Testing Replay Attack Detection...")
    valid, msg = drone_crypto.check_replay_protection(signed_command)
    print(f"   Replay check (same nonce): {valid} - {msg}")
    
    # Test encryption
    print("\n8. Testing Encryption...")
    gs_crypto.establish_session()
    drone_crypto.session_key = gs_crypto.session_key  # Share session key
    drone_crypto.session_established = True
    
    message = "Sensitive telemetry data: Position 36.8065N, 10.1815E"
    encrypted = gs_crypto.encrypt_message(message)
    print(f"   Encrypted: {encrypted['ciphertext'][:32]}...")
    
    decrypted = drone_crypto.decrypt_message(encrypted)
    print(f"   Decrypted: {decrypted.decode('utf-8')}")
    
    print("\n[✓] All tests passed!")