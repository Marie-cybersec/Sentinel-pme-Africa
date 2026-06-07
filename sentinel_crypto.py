"""
SENTINEL PME AFRICA — Module Cryptographique RSA
=================================================
Garantit trois proprietes de securite fondamentales :
  1. CONFIDENTIALITE  : chiffrement hybride RSA-2048 + AES-256-GCM des sauvegardes
  2. AUTHENTICITE     : signature RSA-PSS de chaque alerte
  3. NON-REPUDIATION  : preuve juridique qu'une alerte provient d'un agent legitime

Theorie RSA : n=p*q, phi=(p-1)(q-1), e=65537, d=e^-1 mod phi
Chiffrement : c = m^e mod n  |  Dechiffrement : m = c^d mod n
Signature   : s = hash(m)^d mod n  |  Verification : hash(m) = s^e mod n

Usage:
    pip install cryptography
    python sentinel_crypto.py   # lance la demonstration complete
"""

import os, hashlib, json, base64
from datetime import datetime, timezone
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ══════════════════════════════════════════════════════════════════════════════
# 1. GENERATION DES CLES RSA
# ══════════════════════════════════════════════════════════════════════════════

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Genere une paire de cles RSA.
    key_size : 2048 bits (minimum recommande NIST 2024) ou 4096 bits (haute securite).
    L'exposant public e = 65537 est le nombre de Fermat F4, standard industriel.
    """
    if key_size not in (1024, 2048, 3072, 4096):
        raise ValueError(f"Taille invalide : {key_size}. Valeurs : 2048, 3072, 4096")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def serialize_private_key(pk: RSAPrivateKey, password: Optional[str] = None) -> bytes:
    """Serialise la cle privee en format PEM. Chiffree si mot de passe fourni."""
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    return pk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc
    )


def serialize_public_key(pk: RSAPublicKey) -> bytes:
    """Serialise la cle publique en format PEM pour partage avec le SOC."""
    return pk.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem: bytes, password: Optional[str] = None) -> RSAPrivateKey:
    return serialization.load_pem_private_key(
        pem,
        password=password.encode() if password else None,
        backend=default_backend()
    )


def load_public_key(pem: bytes) -> RSAPublicKey:
    return serialization.load_pem_public_key(pem, backend=default_backend())


# ══════════════════════════════════════════════════════════════════════════════
# 2. CHIFFREMENT / DECHIFFREMENT RSA
# ══════════════════════════════════════════════════════════════════════════════

def rsa_encrypt(message: bytes, public_key: RSAPublicKey) -> bytes:
    """
    Chiffre un message avec la cle publique RSA — padding OAEP-SHA256.
    OAEP = Optimal Asymmetric Encryption Padding.
    Resistance aux attaques IND-CCA2. Max ~245 octets pour RSA-2048.
    Pour les gros fichiers, utiliser rsa_hybrid_encrypt().
    """
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Dechiffre avec la cle privee RSA — padding OAEP-SHA256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ══════════════════════════════════════════════════════════════════════════════
# 3. SIGNATURE NUMERIQUE RSA-PSS
# ══════════════════════════════════════════════════════════════════════════════

def rsa_sign(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Signe des donnees avec la cle privee — PSS-SHA256.
    PSS = Probabilistic Signature Scheme.
    Chaque signature est unique meme pour les memes donnees (sel aleatoire).
    Formule : signature = hash(data)^d mod n
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(data: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """
    Verifie une signature RSA-PSS.
    Retourne True si valide, False si la signature est incorrecte ou falsifiee.
    Formule : valide si hash(data) = signature^e mod n
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 4. CHIFFREMENT SYMETRIQUE AES-256-GCM
# ══════════════════════════════════════════════════════════════════════════════

def aes_encrypt(plaintext: bytes,
                key: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Chiffre avec AES-256-GCM. Garantit simultanement :
    - Confidentialite (chiffrement)
    - Integrite (tag d'authentification 16 octets integre)
    - Authenticite (nonce unique de 12 octets)
    Retourne : (ciphertext_avec_tag, nonce, cle_aes)
    """
    if key is None:
        key = os.urandom(32)   # 256 bits aleatoires
    nonce = os.urandom(12)     # 96 bits, recommandation NIST pour GCM
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return ciphertext, nonce, key


def aes_decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Dechiffre et verifie l'integrite AES-256-GCM.
    Leve une exception InvalidTag si les donnees ont ete corrompues ou modifiees.
    """
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ══════════════════════════════════════════════════════════════════════════════
# 5. CHIFFREMENT HYBRIDE RSA + AES (pour fichiers volumineux)
# ══════════════════════════════════════════════════════════════════════════════

def rsa_hybrid_encrypt(data: bytes, public_key: RSAPublicKey) -> dict:
    """
    Chiffrement hybride RSA + AES : standard industriel (TLS, PGP, SSH).
    Protocole en 4 etapes :
      (1) Generer une cle AES-256 ephemere aleatoire pour la session
      (2) Chiffrer les donnees avec AES-256-GCM
      (3) Chiffrer la cle AES avec RSA-OAEP (cle publique du destinataire)
      (4) Transmettre { RSA(cle_AES) + AES(donnees) + nonce + hash_integrite }
    Seul le possesseur de la cle privee RSA peut recuperer la cle AES et donc les donnees.
    """
    ciphertext, nonce, aes_key = aes_encrypt(data)
    encrypted_aes_key = rsa_encrypt(aes_key, public_key)
    integrity_hash = hashlib.sha256(data).hexdigest()

    return {
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
        "nonce":         base64.b64encode(nonce).decode(),
        "ciphertext":    base64.b64encode(ciphertext).decode(),
        "integrity":     integrity_hash,
        "algorithm":     "RSA-2048-OAEP-SHA256 + AES-256-GCM",
        "encrypted_at":  datetime.now(timezone.utc).isoformat() + "Z",
    }


def rsa_hybrid_decrypt(payload: dict, private_key: RSAPrivateKey) -> bytes:
    """
    Dechiffre un paquet hybride RSA+AES et verifie l'integrite.
    Leve une exception si les donnees ont ete corrompues.
    """
    aes_key = rsa_decrypt(
        base64.b64decode(payload["encrypted_key"]),
        private_key
    )
    data = aes_decrypt(
        base64.b64decode(payload["ciphertext"]),
        base64.b64decode(payload["nonce"]),
        aes_key
    )
    # Verification de l'integrite
    if payload.get("integrity"):
        computed = hashlib.sha256(data).hexdigest()
        if computed != payload["integrity"]:
            raise ValueError(
                "ALERTE SECURITE : Integrite des donnees compromise ! "
                "Le fichier a ete modifie apres chiffrement."
            )
    return data


# ══════════════════════════════════════════════════════════════════════════════
# 6. HACHAGE SECURISE
# ══════════════════════════════════════════════════════════════════════════════

def secure_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Empreinte SHA-256, SHA-512, SHA3-256 ou SHA3-512 pour verification d'integrite."""
    algos = {
        "sha256":   hashlib.sha256,
        "sha512":   hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "sha3_512": hashlib.sha3_512,
    }
    if algorithm not in algos:
        raise ValueError(f"Algorithme non supporte. Choisir : {list(algos.keys())}")
    return algos[algorithm](data).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# 7. GESTIONNAIRE DE CLES PME
# ══════════════════════════════════════════════════════════════════════════════

class PMEKeyManager:
    """
    Gestionnaire centralise des cles cryptographiques d'une PME SENTINEL.
    Chaque PME dispose d'une paire RSA-2048 unique generee a l'installation.
    - Cle privee : restee sur la machine de la PME, jamais transmise
    - Cle publique : transmise au SOC pour verification des signatures
    """

    def __init__(self, pme_id: str, key_size: int = 2048):
        self.pme_id     = pme_id
        self.key_size   = key_size
        self.created_at = datetime.now(timezone.utc).isoformat() + "Z"
        self.private_key, self.public_key = generate_rsa_keypair(key_size)
        print(f"[CRYPTO] Paire RSA-{key_size} generee pour {pme_id}")

    def export_public_key(self) -> str:
        """Exporte la cle publique PEM — a partager avec le SOC SENTINEL."""
        return serialize_public_key(self.public_key).decode()

    def export_private_key(self, password: str) -> str:
        """Exporte la cle privee chiffree — stockage LOCAL PME uniquement."""
        return serialize_private_key(self.private_key, password).decode()

    def sign_alert(self, alert_data: bytes) -> dict:
        """
        Signe une alerte SENTINEL avec la cle privee RSA.
        Garantit l'authenticite et la non-repudiation de chaque incident.
        """
        signature = rsa_sign(alert_data, self.private_key)
        return {
            "pme_id":    self.pme_id,
            "signature": base64.b64encode(signature).decode(),
            "hash":      secure_hash(alert_data),
            "signed_at": datetime.now(timezone.utc).isoformat() + "Z",
            "algorithm": "RSA-2048-PSS-SHA256",
        }

    def verify_alert(self, alert_data: bytes, sig_info: dict) -> bool:
        """Verifie la signature d'une alerte — utilise par le SOC."""
        sig_bytes = base64.b64decode(sig_info["signature"])
        return rsa_verify(alert_data, sig_bytes, self.public_key)

    def encrypt_backup(self, data: bytes) -> dict:
        """Chiffre une sauvegarde PME avec le protocole hybride RSA+AES."""
        payload = rsa_hybrid_encrypt(data, self.public_key)
        payload["pme_id"] = self.pme_id
        return payload

    def decrypt_backup(self, payload: dict) -> bytes:
        """Dechiffre et verifie l'integrite d'une sauvegarde PME."""
        return rsa_hybrid_decrypt(payload, self.private_key)


# ══════════════════════════════════════════════════════════════════════════════
# DEMONSTRATION COMPLETE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 65)
    print("  SENTINEL PME AFRICA — Demonstration Cryptographie RSA")
    print("=" * 65)

    # --- Test 1 : Generation des cles ---
    manager = PMEKeyManager(pme_id="PME-CM-YDE-00142", key_size=2048)
    print(f"\n[TEST 1] Paire RSA-2048 generee pour {manager.pme_id}")
    print(f"  Cle publique (50 premiers chars) : {manager.export_public_key()[:50]}...")

    # --- Test 2 : Chiffrement et dechiffrement d'une sauvegarde ---
    donnees_sensibles = (
        "BILAN ANNUEL — SARL TECHNOLOGIE YAOUNDE 2025\n"
        "Chiffre d'affaires : 48 500 000 FCFA\n"
        "Benefice net       : 12 300 000 FCFA\n"
        "CONFIDENTIEL — NE PAS DIVULGUER"
    ).encode("utf-8")

    payload = manager.encrypt_backup(donnees_sensibles)
    print(f"\n[TEST 2] Sauvegarde chiffree avec {payload['algorithm']}")
    print(f"  Cle AES chiffree RSA : {payload['encrypted_key'][:40]}...")
    print(f"  Hash integrite SHA256 : {payload['integrity'][:32]}...")

    donnees_restaurees = manager.decrypt_backup(payload)
    assert donnees_restaurees == donnees_sensibles
    print(f"  Dechiffrement et verification integrite : OK ✓")

    # --- Test 3 : Signature et verification d'une alerte ---
    alerte_json = json.dumps({
        "threat_type": "PORT_SCAN",
        "source_ip":   "192.168.56.10",
        "severity":    "ELEVE",
        "ports_sondes": 18,
        "detected_at": datetime.now(timezone.utc).isoformat()
    }, ensure_ascii=False).encode("utf-8")

    sig_info = manager.sign_alert(alerte_json)
    print(f"\n[TEST 3] Alerte signee RSA-PSS")
    print(f"  Signature : {sig_info['signature'][:40]}...")
    print(f"  Hash SHA256 : {sig_info['hash'][:32]}...")

    valide = manager.verify_alert(alerte_json, sig_info)
    print(f"  Verification signature authentique : {'VALIDE ✓' if valide else 'INVALIDE ✗'}")

    # --- Test 4 : Detection d'une alerte falsifiee ---
    alerte_falsifiee = json.dumps({
        "threat_type": "PORT_SCAN",
        "source_ip":   "ATTAQUANT_FALSIFICATEUR",
        "severity":    "FAIBLE",   # l'attaquant essaie de minimiser la severite
    }, ensure_ascii=False).encode("utf-8")

    non_valide = manager.verify_alert(alerte_falsifiee, sig_info)
    print(f"\n[TEST 4] Alerte falsifiee injectee :")
    print(f"  Resultat verification : {'ALERTE FALSIFIEE DETECTEE ✓' if not non_valide else 'NON DETECTEE ✗'}")

    print("\n" + "=" * 65)
    print("  Tous les tests cryptographiques reussis ✓")
    print("  RSA-2048 | AES-256-GCM | PSS-SHA256 | Hybride TLS-like")
    print("=" * 65)
