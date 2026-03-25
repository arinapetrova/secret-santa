import json
import os
import base64
import secrets
import getpass
import random

import bcrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# ------------------ File Paths & Directories ------------------ #

USERS_FILE = "users.json"
SECRET_SANTA_FILE = "secret_santa.json"

KEYS_DIR = "keys"   # kept for clarity if you want to expand
CA_DIR = "ca"       # Root CA keys and wishlist key
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(CA_DIR, exist_ok=True)

ROOT_PRIV_PATH = os.path.join(CA_DIR, "root_private.pem")
ROOT_PUB_PATH = os.path.join(CA_DIR, "root_public.pem")
ROOT_CERT_PATH = os.path.join(CA_DIR, "root_cert.pem")
WISHLIST_KEY_PATH = os.path.join(CA_DIR, "wishlist_key.bin")


# ------------------ Generic JSON Helpers ------------------ #

def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def load_users():
    return load_json(USERS_FILE, [])


def save_users(users):
    save_json(USERS_FILE, users)


def find_user(username, users=None):
    if users is None:
        users = load_users()
    for u in users:
        if u["username"] == username:
            return u
    return None


# ------------------ Root CA & Wishlist Key ------------------ #

def init_root_ca():
    """Create Root CA keypair if it does not already exist."""
    # If any of the root artifacts exist, assume CA is initialized
    if os.path.exists(ROOT_PRIV_PATH) and os.path.exists(ROOT_CERT_PATH):
        return

    # Generate root RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    # Build a self-signed X.509 root certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Local Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    # Persist private key and certificate
    with open(ROOT_PRIV_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(ROOT_CERT_PATH, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))



def get_root_keys():
    # Return the root private key object and the root certificate object.
    with open(ROOT_PRIV_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(ROOT_CERT_PATH, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    return priv, root_cert


def get_wishlist_key():
    """
    Global symmetric key for encrypting wishlists with AES-GCM.
    For the purposes of this lab, we store it in a file.
    """
    if os.path.exists(WISHLIST_KEY_PATH):
        with open(WISHLIST_KEY_PATH, "rb") as f:
            return f.read()
    key = AESGCM.generate_key(bit_length=256)
    with open(WISHLIST_KEY_PATH, "wb") as f:
        f.write(key)
    return key


# ------------------ KDF & AEAD Helpers ------------------ #

def derive_key_from_password(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte key from password via Scrypt (for encrypting private key)."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password)


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ------------------ User Certificates & Key Management ------------------ #

def generate_user_keypair_and_cert(username: str, password: bytes):
    """
    Generate RSA keypair for user, encrypt the private key with a key
    derived from their password (AES-GCM), and create a certificate
    signed by the Root CA over (username || public_key).
    """
    # RSA keypair for the user
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Ensure Root CA exists and issue an X.509 certificate for this user
    init_root_ca()
    root_priv, root_cert = get_root_keys()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
    )

    certificate_obj = cert_builder.sign(root_priv, hashes.SHA256())
    certificate_pem = certificate_obj.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Encrypt private key with password-derived key
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    kdf_salt = os.urandom(16)
    enc_key = derive_key_from_password(password, kdf_salt)
    nonce, enc_priv = aesgcm_encrypt(enc_key, priv_pem)

    return {
        "kdf_salt": base64.b64encode(kdf_salt).decode("utf-8"),
        "enc_private_key": base64.b64encode(enc_priv).decode("utf-8"),
        "enc_private_key_nonce": base64.b64encode(nonce).decode("utf-8"),
        "certificate_pem": certificate_pem,
    }


def load_user_private_key(user: dict, password: bytes):
    """Decrypt and return the user's RSA private key object."""
    kdf_salt = base64.b64decode(user["kdf_salt"])
    enc_priv = base64.b64decode(user["enc_private_key"])
    nonce = base64.b64decode(user["enc_private_key_nonce"])

    enc_key = derive_key_from_password(password, kdf_salt)
    priv_pem = aesgcm_decrypt(enc_key, nonce, enc_priv)
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    return private_key


def get_user_public_key_from_cert(user: dict):
    """
    Verify the user's certificate with the Root CA and return the
    user's public key object if valid.
    """
    # Load certificate PEM stored for the user and verify it was signed by Root CA
    cert_pem = user.get("certificate_pem")
    if cert_pem is None:
        raise ValueError("User does not have a certificate")

    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    # Verify certificate signature using Root CA public key
    _, root_cert = get_root_keys()
    root_pub = root_cert.public_key()

    # Use the certificate's tbs_certificate_bytes and signature algorithm
    try:
        # For X.509 certs signed with RSA, the signature uses PKCS1v15
        root_pub.verify(
            cert_obj.signature,
            cert_obj.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_obj.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError(f"Certificate verification failed: {e}")

    return cert_obj.public_key()


# ------------------ Secret Santa Assignment Management ------------------ #

def mark_secret_santa_needs_reset():
    """If a valid assignment exists, mark it as needing reset when new users join."""
    if os.path.exists(SECRET_SANTA_FILE):
        data = load_json(SECRET_SANTA_FILE, {})
        if data.get("status") == "valid":
            data["status"] = "needs_reset"
            save_json(SECRET_SANTA_FILE, data)
            print("[INFO] Existing Secret Santa assignment was marked as needing reset "
                  "because a new participant joined.\n")


def generate_derangement(names):
    """
    Generate a random permutation of 'names' with no fixed points.
    Uses SystemRandom for better randomness.
    """
    if len(names) < 2:
        raise ValueError("Need at least 2 participants for Secret Santa.")

    rng = random.SystemRandom()
    while True:
        shuffled = names[:]
        rng.shuffle(shuffled)
        if all(a != b for a, b in zip(names, shuffled)):
            return dict(zip(names, shuffled))


def create_or_reset_secret_santa():
    """
    Create or reset the global Secret Santa assignments:
      - Generate a derangement of all usernames.
      - For each user u, encrypt recipient username with hybrid encryption:
          AES-GCM + RSA-OAEP using u's public key.
      - Sign the entire structure with the Root CA (digital signature).
    """
    users = load_users()
    usernames = [u["username"] for u in users]

    if len(usernames) < 2:
        print("❌ Need at least 2 users to create Secret Santa assignments.\n")
        return

    # Derangement: each user → different recipient, no self
    try:
        mapping = generate_derangement(usernames)
    except ValueError as e:
        print("❌", e, "\n")
        return

    assignments = {}
    for giver in usernames:
        recipient = mapping[giver]
        # Lookup giver user & public key from cert
        giver_user = find_user(giver, users)
        try:
            giver_pub = get_user_public_key_from_cert(giver_user)
        except Exception as e:
            print(f"❌ Certificate verification failed for user {giver}: {e}\n")
            return

        # Hybrid encryption of the assignment "recipient username"
        aes_key = AESGCM.generate_key(bit_length=128)
        nonce, ciphertext = aesgcm_encrypt(aes_key, recipient.encode("utf-8"),
                                           aad=giver.encode("utf-8"))

        enc_key = giver_pub.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        assignments[giver] = {
            "enc_key": base64.b64encode(enc_key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

    # Sign the assignments (mini-PKI digital signature)
    init_root_ca()
    root_priv, _ = get_root_keys()

    data_to_sign = {
        "participants": usernames,
        "assignments": assignments,
    }
    payload = json.dumps(data_to_sign, sort_keys=True).encode("utf-8")

    signature = root_priv.sign( # replace with self-signing certificate (X.509) in real systems
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )

    secret_santa_data = {
        "status": "valid",
        "participants": usernames,
        "assignments": assignments,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }

    save_json(SECRET_SANTA_FILE, secret_santa_data)
    print("🎄 Secret Santa assignments have been (re)created successfully!\n")


def verify_secret_santa_signature(data: dict) -> bool:
    """Verify the Root CA's signature over the Secret Santa structure."""
    if "signature" not in data:
        return False

    signature = base64.b64decode(data["signature"])
    payload = json.dumps({
        "participants": data.get("participants", []),
        "assignments": data.get("assignments", {}),
    }, sort_keys=True).encode("utf-8")

    # Load root certificate and extract its public key for verification
    _, root_cert = get_root_keys()
    root_pub = root_cert.public_key()
    try:
        root_pub.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def get_assigned_recipient(username: str, private_key):
    """
    Show the current user's assigned gift recipient and their wishlist.
    Uses:
      - Signature verification on the global assignment (digital signature).
      - Hybrid decryption (RSA-OAEP + AES-GCM) for the user's assignment.
      - AES-GCM decryption on the recipient's wishlist.
    """
    if not os.path.exists(SECRET_SANTA_FILE):
        print("❌ Secret Santa assignments have not been created yet.\n")
        return

    data = load_json(SECRET_SANTA_FILE, {})
    status = data.get("status")

    if status != "valid":
        print("⚠️ Secret Santa assignments are not valid right now.")
        print("    This typically happens when new members joined after the last assignment.")
        print("    Please ask the organizer to reset/recreate the assignments.\n")
        return

    # Verify the global signature
    if not verify_secret_santa_signature(data):
        print("❌ Secret Santa data signature is invalid! Data may be corrupted.\n")
        return

    assignments = data.get("assignments", {})
    if username not in assignments:
        print("❌ You are not part of the current Secret Santa assignments.\n")
        return

    my_record = assignments[username]
    enc_key = base64.b64decode(my_record["enc_key"])
    nonce = base64.b64decode(my_record["nonce"])
    ciphertext = base64.b64decode(my_record["ciphertext"])

    try:
        # First decrypt AES key using user's private key (RSA-OAEP)
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Then decrypt recipient username using AES-GCM
        recipient_username = aesgcm_decrypt(
            aes_key,
            nonce,
            ciphertext,
            aad=username.encode("utf-8")
        ).decode("utf-8")
    except Exception as e:
        print("❌ Error decrypting your assignment:", e, "\n")
        return

    # Load recipient's wishlist
    recipient = find_user(recipient_username)
    if not recipient:
        print("❌ Your assigned recipient does not exist anymore.\n")
        return

    wishlist_key = get_wishlist_key()
    cipher_b64 = recipient.get("wishlist_ciphertext")
    nonce_b64 = recipient.get("wishlist_nonce")

    if cipher_b64 is None or nonce_b64 is None:
        wishlist_items = []
    else:
        try:
            w_nonce = base64.b64decode(nonce_b64)
            w_ct = base64.b64decode(cipher_b64)
            wishlist_json = aesgcm_decrypt(wishlist_key, w_nonce, w_ct).decode("utf-8")
            wishlist_items = json.loads(wishlist_json)
        except Exception:
            wishlist_items = []

    print("🎁 Your Secret Santa assignment:")
    print(f"  You are buying a gift for: {recipient_username}")
    if wishlist_items:
        print("  Their wishlist:")
        for idx, item in enumerate(wishlist_items, 1):
            print(f"   {idx}. {item}")
    else:
        print("  They have not set a wishlist yet.")
    print("")


# ----- Wishlist Management -------- #

def edit_wishlist(username: str):
    """
    Let the current user view and edit their wishlist.
    Wishlist = list of items, encrypted with AES-GCM using a
    server-side key (wishlist_key).
    """
    users = load_users()
    user = find_user(username, users)
    if not user:
        print("❌ User not found (unexpected).\n")
        return

    wishlist_key = get_wishlist_key()
    cipher_b64 = user.get("wishlist_ciphertext")
    nonce_b64 = user.get("wishlist_nonce")

    current_items = []
    if cipher_b64 is not None and nonce_b64 is not None:
        try:
            nonce = base64.b64decode(nonce_b64)
            ct = base64.b64decode(cipher_b64)
            wishlist_json = aesgcm_decrypt(wishlist_key, nonce, ct).decode("utf-8")
            current_items = json.loads(wishlist_json)
        except Exception:
            current_items = []

    print("📜 Current wishlist items:")
    if current_items:
        for idx, item in enumerate(current_items, 1):
            print(f"   {idx}. {item}")
    else:
        print("   (no items yet)")

    print("\nEnter your new wishlist items separated by commas.")
    print("Example: socks, candles, chocolate")
    raw = input("New wishlist: ").strip()

    if not raw:
        new_items = []
    else:
        new_items = [x.strip() for x in raw.split(",") if x.strip()]

    # Encrypt and store
    wishlist_json = json.dumps(new_items).encode("utf-8")
    nonce, ct = aesgcm_encrypt(wishlist_key, wishlist_json)

    user["wishlist_ciphertext"] = base64.b64encode(ct).decode("utf-8")
    user["wishlist_nonce"] = base64.b64encode(nonce).decode("utf-8")

    save_users(users)
    print("✅ Wishlist updated.\n")


# ------------------ User Authentication ------------------ #

def sign_up():
    users = load_users()
    username = input("Choose a username: ").strip().lower()

    if find_user(username, users):
        print("❌ Username already exists.\n")
        return None, None

    password_str = getpass.getpass("Choose a password: ")
    password = password_str.encode("utf-8")

    # Password hashing (bcrypt) for authentication
    pwd_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode("utf-8")

    # Generate cryptographic material for this user
    crypto_data = generate_user_keypair_and_cert(username, password)

    # Empty wishlist by default
    user_record = {
        "username": username,
        "password_hash": pwd_hash,
        "wishlist_ciphertext": None,
        "wishlist_nonce": None,
        **crypto_data
    }

    users.append(user_record)
    save_users(users)
    print(f"✅ Account created successfully for {username}.\n")

    # Any existing Secret Santa assignments are now invalid (option C behavior)
    mark_secret_santa_needs_reset()

    # Load private key for current session
    private_key = load_user_private_key(user_record, password)
    return user_record, private_key


def sign_in():
    users = load_users()
    username = input("Username: ").strip().lower()
    password_str = getpass.getpass("Password: ")
    password = password_str.encode("utf-8")

    user = find_user(username, users)
    if not user:
        print("❌ User not found.\n")
        return None, None

    if bcrypt.checkpw(password, user["password_hash"].encode("utf-8")):
        print(f"✅ Welcome back, {username}.\n")
        try:
            private_key = load_user_private_key(user, password)
        except Exception as e:
            print("⚠️ Login ok, but could not decrypt your private key. "
                  "Did the password or files change?")
            print(e)
            return None, None
        return user, private_key
    else:
        print("❌ Incorrect password.\n")
        return None, None


# ------------------ Main CLI ------------------ #

def user_menu(username: str, private_key):
    """Per-user main menu (what your professor will see)."""
    while True:
        print("----- Secret Santa Menu -----")
        print("1) Add/Edit my wishlist")
        print("2) Get your assigned gift recipient & wishlist")
        print("3) Log out")
        choice = input("Select an option: ").strip()

        if choice == "1":
            edit_wishlist(username)
        elif choice == "2":
            get_assigned_recipient(username, private_key)
        elif choice == "3":
            print("🔐 Logged out.\n")
            break
        else:
            print("Invalid option.\n")


def main():
    print("=== Secret Santa App ===")

    init_root_ca()
    get_wishlist_key()  # ensure wishlist key exists

    while True:
        print("----- Main Menu -----")
        print("1) Sign up")
        print("2) Log in")
        print("3) Create/Reset Secret Santa assignments")
        print("4) Quit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            user, priv = sign_up()
            if user and priv:
                user_menu(user["username"], priv)

        elif choice == "2":
            user, priv = sign_in()
            if user and priv:
                user_menu(user["username"], priv)

        elif choice == "3":
            create_or_reset_secret_santa()

        elif choice == "4":
            print("Bye! 🎄")
            break

        else:
            print("Invalid option.\n")


if __name__ == "__main__":
    main()
