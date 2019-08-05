from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

AUTH_TYPE_MAP = {}
for auth_type in ["password", "gpg"]:
    try:
        AUTH_TYPE_MAP[auth_type] = __import__("auth_" + auth_type)
    except:
        # TODO: better error message required
        print("Could not load auth type: %s" % auth_type)


class Auth(object):
    nonce = None

    def __init__(self, data):
        self.data = data

        self.auth_type = data["auth_type"]
        assert self.auth_type in AUTH_TYPE_MAP, "Unknown auth type: %s" % self.auth_type

        self.auth_module = AUTH_TYPE_MAP[self.auth_type]

        if "sub_auth" in self.data:
            self.sub_auth = Auth(self.data["sub_auth"])
        else:
            self.sub_auth = None

        if "auth_data" not in self.data:
            self.data["auth_data"] = self.auth_module.init()

    def dump(self):
        # TODO: this is being a little abusive of recursive data being the same object
        return self.data

    def re_key(self):
        nonce = get_random_bytes(32)

        self._re_key(nonce)

        return nonce

    def _re_key(self, nonce):
        if self.sub_auth is not None:
            # recurivly encrypt nonce
            nonce = self.sub_auth._re_key(nonce)

        self.data["enc_nonce"] = self.auth_module.lock_key_slot(
            self.data["auth_data"], nonce
        )

        return self.data["enc_nonce"]

    def unlock(self):
        return self._unlock(self.data["enc_nonce"])

    def _unlock(self, enc_nonce):
        nonce = self.auth_module.unlock_key_slot(self.data["auth_data"], enc_nonce)

        if self.sub_auth is not None:
            # the nonce is still encrypted by the sub auth
            return self.sub_auth._unlock(nonce)

        return nonce

    def __repr__(self):
        return "Auth(%s)" % repr(self.data)
