import os
from cryptography.fernet import Fernet, InvalidToken


def get_fernet() -> Fernet:
    key = os.environ.get("VAULT_KEY")
    if not key:
        raise RuntimeError("VAULT_KEY no configurada en .env")
    return Fernet(key.encode())


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise ValueError("Error al descifrar: clave inválida o dato corrupto")
