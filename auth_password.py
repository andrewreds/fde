from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def init_auth(data):
    # TODO: Don't use RSA

    if "key_size" not in data:
        data["key_size"] = 4096

    key = RSA.generate(data["key_size"])

    data["enc_private_key"] = key.export_key(
        passphrase=data["_password"], pkcs=8, protection="scryptAndAES128-CBC"
    )

    data["public_key"] = key.publickey().export_key()


def lock_key_slot(data, nonce):
    public_key = RSA.import_key(data["public_key"])

    cipher_rsa = PKCS1_OAEP.new(public_key)

    data["enc_nonce"] = cipher_rsa.encrypt(nonce)


def unlock_key_slot(data, unlock_data):
    private_key = RSA.import_key(data["enc_private_key"], passphrase=unlock_data)
    
    cipher_rsa = PKCS1_OAEP.new(private_key)

    return cipher_rsa.decrypt(data["enc_nonce"])
