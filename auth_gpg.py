from sh import gpg


def init():

    key_fingerprint = input("enter your key fingerprint")

    pub_key = gpg("--export", "--armor", key_fingerprint).stdout

    return {"public_key": pub_key, "key_fingerprint": key_fingerprint}


def lock_key_slot(data, nonce):

    """encode the nonce with the public key"""

    return gpg(
        "--encrypt", "--armor", "--recipient", data["key_fingerprint"], _in=nonce
    ).stdout


def unlock_key_slot(data, enc_nonce):

    return gpg("--decrypt", _in=enc_nonce).stdout
