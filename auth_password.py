from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


def init():
    password = input("Enter a password: ")

    # TODO: Don't use RSA
    key = RSA.generate(2048)

    encrypted_key = key.export_key(
        passphrase=password, pkcs=8, protection="scryptAndAES128-CBC"
    )

    return {
        "enc_private_key": key.export_key(
            passphrase=password, pkcs=8, protection="scryptAndAES128-CBC"
        ),
        "public_key": key.publickey().export_key(),
        "key_type": "rsa:2048",
    }


def lock_key_slot(data, nonce):
    public_key = RSA.import_key(data["public_key"])

    cipher_rsa = PKCS1_OAEP.new(public_key)

    return cipher_rsa.encrypt(nonce)


def unlock_key_slot(data, enc_nonce):
    password = input("What is your password: ")

    private_key = RSA.import_key(data["enc_private_key"], passphrase=password)

    cipher_rsa = PKCS1_OAEP.new(private_key)

    return cipher_rsa.decrypt(enc_nonce)
