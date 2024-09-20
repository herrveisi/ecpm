# IMPORT
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES with GCM mode (Authenticated Encryption)
from cryptography.hazmat.primitives.hmac import HMAC  # HMAC (Hash-based Message Authentication Code) for message integrity
from cryptography.hazmat.primitives.asymmetric import ec  # Elliptic curve cryptography for key generation and exchange
from cryptography.hazmat.primitives import serialization  # Key serialization and deserialization
from cryptography.hazmat.primitives.kdf import pbkdf2  # Password-based key derivation function
from cryptography.hazmat.primitives import hashes  # Cryptographic hash functions
from cryptography.hazmat.backends import default_backend  # Backend for cryptography operations
from typing import Union, Tuple  # Type hinting for better code readability
import hashlib  # Provides hash functions for password and mnemonic management
import string  # String operations for password generation
import random  # Random data generation for passwords and mnemonics
import os  # For handling system-level operations like random bytes generation

# MAIN
class encryption:
    """
    The `encryption` class contains multiple nested classes:
    - ecc: Elliptic curve cryptography methods (key generation, signing, verification).
    - aes: Symmetric AES encryption and decryption using GCM mode.
    - exchange: Key exchange mechanism using ECC (ECDH) and shared secret derivation.
    - extra: Additional utilities such as password generation and mnemonic creation.
    """
    
    class ecc:
        """
        The `ecc` class handles Elliptic Curve Cryptography (ECC) for secure key generation, 
        message signing, and signature verification.
        """
        
        @staticmethod
        def keygen() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
            """
            Generates a new ECC private and public key pair using the Brainpool P512R1 curve.
            
            Returns:
                Tuple of (privatekey, publickey)
            """
            privatekey = ec.generate_private_key(curve=ec.BrainpoolP512R1(), backend=default_backend())
            publickey = privatekey.public_key()
            return privatekey, publickey

        @staticmethod
        def serialize(key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]) -> str:
            """
            Serializes the given private or public key into a PEM format string, converted to hexadecimal.
            
            Args:
                key: Either a private or public ECC key to be serialized.
            
            Returns:
                Hexadecimal string of the serialized key.
            """
            if isinstance(key, ec.EllipticCurvePrivateKey):
                privatekeypem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()).hex()
                return privatekeypem
            elif isinstance(key, ec.EllipticCurvePublicKey):
                publickeypem = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
                return publickeypem
            else:
                raise ValueError("CHECK THE KEY")
        
        @staticmethod
        def deserialize(keytype: str, key: str) -> Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
            """
            Deserializes a hexadecimal string back into an ECC private or public key.
            
            Args:
                keytype: Type of key, either "private" or "public".
                key: The serialized key in hexadecimal format.
            
            Returns:
                Deserialized ECC private or public key.
            """
            key = bytes.fromhex(key)
            if keytype == "private":
                key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
                return key
            elif keytype == "public":
                key = serialization.load_pem_public_key(key, backend=default_backend())
                return key
            else:
                raise ValueError("CHECK THE KEY")
        
        @staticmethod
        def sign(privatekey: ec.EllipticCurvePrivateKey, value: str) -> str:
            """
            Signs a string value using the given ECC private key with ECDSA and SHA3-512.
            
            Args:
                privatekey: ECC private key used for signing.
                value: The message or data to be signed.
            
            Returns:
                Hexadecimal string of the generated signature.
            """
            signature = privatekey.sign(
                data=value.encode(),
                signature_algorithm=ec.ECDSA(hashes.SHA3_512())).hex()
            return signature
        
        @staticmethod
        def verify(publickey: ec.EllipticCurvePublicKey, signature: str, value: str) -> bool:
            """
            Verifies a signed message using the public key and signature.
            
            Args:
                publickey: ECC public key used for verification.
                signature: The signature to be verified, in hexadecimal.
                value: The original message that was signed.
            
            Returns:
                True if the signature is valid, False otherwise.
            """
            try:
                publickey.verify(
                    data=value.encode(),
                    signature=bytes.fromhex(signature),
                    signature_algorithm=ec.ECDSA(hashes.SHA3_512()))
                return True
            except Exception:
                return False
    
    class aes:
        """
        The `aes` class handles symmetric encryption and decryption using AES in GCM mode.
        It supports encryption via both a secret key and a password-derived key.
        """
        
        @staticmethod
        def encrypt(keytype: str, secret: str, container: str, value: str) -> None:
            """
            Encrypts a message using AES-GCM and writes the output (nonce + ciphertext + tag) to a file.
            
            Args:
                keytype: Either "key" or "password". Determines how the secret is treated.
                secret: The encryption key (in hex) or password to be hashed.
                container: The filename where the encrypted data will be saved.
                value: The plaintext message to encrypt.
            """
            nonce = os.urandom(12)  # Generate a random 12-byte nonce
            if keytype == "key":
                aesgcm = AESGCM(bytes.fromhex(secret))  # AES-GCM with provided key
            elif keytype == "password":
                aesgcm = AESGCM(hashlib.sha3_256(secret.encode()).digest())  # Derive key from password
            else:
                raise ValueError("CHECK THE KEYTYPE")
            
            # Encrypt the message
            ciphertext = aesgcm.encrypt(nonce, value.encode(), None)
            
            # Generate an HMAC tag to ensure integrity
            mac = HMAC(bytes.fromhex(secret), hashes.SHA3_512())
            mac.update(nonce + ciphertext)
            tag = mac.finalize()
            
            # Write the nonce, ciphertext, and tag to the file
            with open(container, "wb") as file:
                file.write(nonce + ciphertext + tag)
        
        @staticmethod
        def decrypt(keytype: str, secret: str, container: str) -> str:
            """
            Decrypts a file containing AES-GCM encrypted data (nonce + ciphertext + tag).
            
            Args:
                keytype: Either "key" or "password". Determines how the secret is treated.
                secret: The decryption key (in hex) or password to be hashed.
                container: The filename where the encrypted data is saved.
            
            Returns:
                The decrypted plaintext message.
            """
            with open(container, "rb") as file:
                filedata = file.read()  # Read the file data
            
            # Extract the nonce, ciphertext, and tag
            nonce, ciphertext, tag = filedata[:12], filedata[12:-64], filedata[-64:]
            
            # Determine the key from the secret
            if keytype == "key":
                aesgcm = AESGCM(bytes.fromhex(secret))  # AES-GCM with provided key
            elif keytype == "password":
                aesgcm = AESGCM(hashlib.sha3_256(secret.encode()).digest())  # Derive key from password
            else:
                raise ValueError("CHECK THE KEYTYPE")
            
            # Verify the HMAC tag for integrity
            mac = HMAC(bytes.fromhex(secret), hashes.SHA3_512())
            mac.update(nonce + ciphertext)
            try:
                mac.verify(tag)  # Raises an exception if MAC is invalid
            except Exception as e:
                raise ValueError("MAC verification failed")
            
            # Decrypt the ciphertext
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
    
    class exchange:
        """
        The `exchange` class handles the Diffie-Hellman (ECDH) key exchange process, 
        allowing two parties to generate a shared secret securely.
        """
        
        @staticmethod
        def sharedkey(privatekey: ec.EllipticCurvePrivateKey, peerpublickey: ec.EllipticCurvePublicKey, salt: str) -> str:
            """
            Generates a shared secret using the ECDH key exchange protocol and a salt.
            
            Args:
                privatekey: ECC private key of one party.
                peerpublickey: ECC public key of the other party.
                salt: Hexadecimal salt used in key derivation.
            
            Returns:
                A hexadecimal string representing the derived shared secret.
            """
            sharedsecret = privatekey.exchange(ec.ECDH(), peerpublickey)  # Perform ECDH key exchange
            kdf = pbkdf2.PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes.fromhex(salt),
                iterations=100000,
                backend=default_backend())
            return kdf.derive(sharedsecret).hex()  # Derive a shared key using PBKDF2
    
    class extra:
        """
        The `extra` class provides additional utilities for password generation and mnemonic-based encryption.
        """
        
        @staticmethod
        def password(length: int = 128) -> str:
            """
            Generates a random password of the specified length, consisting of lowercase letters and digits.
            
            Args:
                length: Length of the password. Default is 128.
            
            Returns:
                Randomly generated password.
            """
            return "".join(random.choice(string.ascii_lowercase + string.digits) for char in range(length))
        
        class mnemonic:
            """
            The `mnemonic` class generates and manages mnemonic phrases for additional encryption security.
            """
            
            @staticmethod
            def create(length: int = 12) -> list:
                """
                Generates a mnemonic phrase consisting of random words from a wordlist file.
                
                Args:
                    length: Number of words in the mnemonic phrase. Default is 12.
                
                Returns:
                    A list of randomly chosen words.
                """
                with open("words.txt", "r") as wordlist:
                    words = wordlist.read().splitlines()
                return random.sample(words, length)
            
            @staticmethod
            def derive(mnemonic: list) -> str:
                """
                Derives a key or hash from the given mnemonic phrase using SHA3-512.
                
                Args:
                    mnemonic: List of words used for derivation.
                
                Returns:
                    A hexadecimal string derived from the mnemonic.
                """
                return hashlib.sha3_512("".join(mnemonic).encode()).hexdigest()
