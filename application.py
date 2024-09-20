# CONFIG
import sys
sys.dont_write_bytecode = True  # Prevent Python from generating .pyc files (bytecode cache)

# IMPORT
from security import encryption  # Import the encryption module (ECC, AES, etc.)
import shutil  # Import shutil for terminal window size management
import os  # Import os for file management

# EXTRA: Terminal Output Formatting Functions
window = shutil.get_terminal_size().columns  # Get the width of the terminal window

def line() -> None:
    """Print a horizontal line across the terminal window."""
    print("-" * window)

def red(text: str) -> str:
    """Return red colored text for terminal output."""
    return "\u001b[31m" + text + "\u001b[0m"

def green(text: str) -> str:
    """Return green colored text for terminal output."""
    return "\u001b[32m" + text + "\u001b[0m"

def blue(text: str) -> str:
    """Return blue colored text for terminal output."""
    return "\u001b[34m" + text + "\u001b[0m"

def yellow(text: str) -> str:
    """Return yellow colored text for terminal output."""
    return "\u001b[33m" + text + "\u001b[0m"

def center(text: str, char: str = " ", uppercase: bool = True) -> str:
    """Return text centered with padding characters and optional uppercase."""
    whitespace = int((window - (len(text) + 2)) / 2)
    if uppercase:
        return f"{char * whitespace} {text.upper()} {char * whitespace}"
    else:
        return f"{char * whitespace} {text} {char * whitespace}"

def right(text: str, char: str = " ", uppercase: bool = True) -> str:
    """Return text aligned to the right with padding characters and optional uppercase."""
    whitespace = int(window - (len(text) + 1))
    if uppercase:
        return f"{char * whitespace} {text.upper()}"
    else:
        return f"{char * whitespace} {text}"

def left(text: str, char: str = " ", uppercase: bool = True) -> str:
    """Return text aligned to the left with padding characters and optional uppercase."""
    whitespace = int(window - (len(text) + 1))
    if uppercase:
        return f"{text.upper()} {char * whitespace}"
    else:
        return f"{text} {char * whitespace}"

# MAIN
# Generate key pair for Alice (ECC Private and Public keys)
alice = encryption.ecc.keygen()
aliceprivatekey = alice[0]
alicepublickey = alice[1]
aliceid = "0123456789"

# Generate key pair for Bob (ECC Private and Public keys)
bob = encryption.ecc.keygen()
bobprivatekey = bob[0]
bobpublickey = bob[1]
bobid = "9876543210"

# Begin the process
print(center("start", "-"))

# Alice validates her own public key
print(blue(center("alice checks if her public key is valid")))
if alice[1] == alicepublickey:
    print(green(center("alice's public key is valid")))
else:
    print(red(center("alice's public key is not valid")))
    exit(1)  # Exit if validation fails

line()

# Bob validates his own public key
print(blue(center("bob checks if his public key is valid")))
if bob[1] == bobpublickey:
    print(green(center("bob's public key is valid")))
else:
    print(red(center("bob's public key is not valid")))
    exit(1)  # Exit if validation fails

line()

# Bob sends a connection request to Alice (Bob signs his ID)
print(blue(center("bob sends a connection request to alice")))
request = [encryption.ecc.sign(bobprivatekey, bobid), bobid]  # Request contains the signed ID

approve = False
validate = False

# Bob waits for Alice to approve the request
print(blue(center("bob waits for the request to be approved")))

line()

# Alice retrieves Bob's public key and checks the request
print(blue(center("alice retrieves bob's public key")))
print(blue(center("alice checks the request and approves if valid")))
if encryption.ecc.verify(bobpublickey, request[0], request[1]):
    print(green(center("bob's signature is valid")))
else:
    print(red(center("bob's signature is not valid")))
    exit(1)  # Exit if signature verification fails
approve = True

line()

# Bob retrieves Alice's public key
print(blue(center("bob retrieves alice's public key")))

line()

# Alice generates a salt, signs it, and sends it to Bob
print(blue(center("alice generates a salt, signs it, and sends it to bob")))
basesalt = os.urandom(16).hex()  # Create random salt
salt = [encryption.ecc.sign(aliceprivatekey, basesalt), basesalt]

line()

# Bob verifies the salt received from Alice
print(blue(center("bob verifies the salt")))
if encryption.ecc.verify(alicepublickey, salt[0], salt[1]):
    print(green(center("alice's salt is valid")))
else:
    print(red(center("alice's salt is not valid")))
    exit(1)  # Exit if salt verification fails

line()

# Alice generates a shared key using Bob's public key and the salt
print(blue(center("alice generates a shared key using bob's public key and the salt")))
alicesharedkey = encryption.exchange.sharedkey(aliceprivatekey, bobpublickey, basesalt)
print(red(center(alicesharedkey, uppercase=False)))  # Display the shared key

line()

# Bob generates a shared key using Alice's public key and the salt
print(blue(center("bob generates a shared key using alice's public key and the salt")))
bobsharedkey = encryption.exchange.sharedkey(bobprivatekey, alicepublickey, basesalt)
print(red(center(bobsharedkey, uppercase=False)))  # Display the shared key

line()

# Alice sends Bob a signed and encrypted handshake message
print(blue(center("alice sends bob a handshake message")))
alice_challenge = os.urandom(16).hex()  # Create a challenge for handshake
alice_signed_challenge = encryption.ecc.sign(aliceprivatekey, alice_challenge)  # Sign the challenge
encrypted_handshake_from_alice = encryption.aes.encrypt("key", alicesharedkey, "message.bin", alice_signed_challenge)

line()

# Bob decrypts Alice's handshake message and verifies it
print(blue(center("bob decrypts alice's handshake message")))
decrypted_handshake_from_alice = encryption.aes.decrypt("key", bobsharedkey, "message.bin")
if encryption.ecc.verify(alicepublickey, decrypted_handshake_from_alice, alice_challenge):
    print(green(center("alice's handshake is valid")))
else:
    print(red(center("alice's handshake is not valid")))
    exit(1)  # Exit if verification fails

line()

# Bob sends Alice a signed and encrypted handshake message
print(blue(center("bob sends his handshake message")))
bob_challenge = os.urandom(16).hex()  # Create a challenge for handshake
bob_signed_challenge = encryption.ecc.sign(bobprivatekey, bob_challenge)  # Sign the challenge
encrypted_handshake_from_bob = encryption.aes.encrypt("key", bobsharedkey, "message.bin", bob_signed_challenge)

line()

# Alice decrypts Bob's handshake message and verifies it
print(blue(center("alice decrypts bob's handshake message")))
decrypted_handshake_from_bob = encryption.aes.decrypt("key", alicesharedkey, "message.bin")
if encryption.ecc.verify(bobpublickey, decrypted_handshake_from_bob, bob_challenge):
    print(green(center("bob's handshake is valid")))
else:
    print(red(center("bob's handshake is not valid")))
    exit(1)  # Exit if verification fails

line()

# Handshake successful! Secure communication is established
print(green(center("handshake successful! secure communication established.")))

line()

# Secure message exchange loop
while True:
    try:
        # Alice sends a signed and encrypted message
        alicemessage = input("Alice: ")
        alicesignedmessage = encryption.ecc.sign(aliceprivatekey, alicemessage)
        encryption.aes.encrypt("key", alicesharedkey, "message.bin", alicesignedmessage)
        print(blue(center("Message from Alice signed and encrypted.", uppercase=False)))
        
        # Bob decrypts and verifies Alice's message
        decrypted_alice_message = encryption.aes.decrypt("key", bobsharedkey, "message.bin")
        if encryption.ecc.verify(alicepublickey, decrypted_alice_message, alicemessage):
            print(green(center(f"Bob received (verified): {alicemessage}", uppercase=False)))
        else:
            print(red(center("Bob could not verify Alice's message!", uppercase=False)))
        
        line()

        # Bob sends a signed and encrypted message
        bobmessage = input("Bob: ")
        bobsignedmessage = encryption.ecc.sign(bobprivatekey, bobmessage)
        encryption.aes.encrypt("key", bobsharedkey, "message.bin", bobsignedmessage)
        print(blue(center("Message from Bob signed and encrypted.", uppercase=False)))

        # Alice decrypts and verifies Bob's message
        decrypted_bob_message = encryption.aes.decrypt("key", alicesharedkey, "message.bin")
        if encryption.ecc.verify(bobpublickey, decrypted_bob_message, bobmessage):
            print(green(center(f"Alice received (verified): {bobmessage}", uppercase=False)))
        else:
            print(red(center("Alice could not verify Bob's message!", uppercase=False)))

    # Exit loop and cleanup on keyboard interrupt
    except KeyboardInterrupt:
        if os.path.exists("message.bin"):
            os.remove("message.bin")  # Remove message history
            print("\n" + red(center("history cleared", char="-")))
            exit(0)
        else:
            print("\n" + red(center("Goodbye", char="-")))
            exit(0)
