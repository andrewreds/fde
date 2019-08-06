from sh import gpg


def init_auth(data):
    pub_key = gpg("--export", "--armor", data["key_fingerprint"]).stdout

    data["public_key"] = pub_key


def lock_key_slot(data, nonce):
    """encode the nonce with the public key"""

    data["enc_nonce"] = gpg(
        "--encrypt", "--armor", "--recipient", data["key_fingerprint"], _in=nonce
    ).stdout


def unlock_key_slot(data, unlock_data):
    return gpg("--decrypt", _in=data["enc_nonce"]).stdout
