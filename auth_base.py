from Crypto.Random import get_random_bytes

# TODO: remove secretsharing and replace with something else (it currently requires hacking to work with python3)
from secretsharing import SecretSharer

SecretSharer.secret_charset = bytes(range(256))
SecretSharer.share_charset = SecretSharer.share_charset.encode()

AUTH_TYPE_MAP = {}
for auth_type in ["password", "gpg"]:
    try:
        AUTH_TYPE_MAP[auth_type] = __import__("auth_" + auth_type)
    except:
        # TODO: better error message required
        print("Could not load auth type: %s" % auth_type)


class Auth(object):
    def __init__(self, data):
        self.data = data

        for key_slot in data["key_slots"]:
            auth_type = key_slot["auth_type"]

            assert auth_type in AUTH_TYPE_MAP, "Unknown auth type: %s" % auth_type

            auth_module = AUTH_TYPE_MAP[auth_type]

            auth_module.init_auth(key_slot)

        # delete all keys starting with '_' as they are for init only
        def rm_underscore(d):
            for key in list(d.keys()):
                print((key, d[key]))
                if key.startswith("_"):
                    del d[key]
                    print("del")
                    continue

                value = d[key]

                if isinstance(value, dict):
                    print("recurse")
                    rm_underscore(value)

                if isinstance(value, list):
                    for subv in value:
                        print("rec2")
                        rm_underscore(subv)

        rm_underscore(self.data)

    def dump(self):
        # TODO: this is being a little abusive of recursive data being the same object
        return self.data

    def re_key(self):
        nonce = get_random_bytes(32)

        self._re_key(nonce, self.data["sss_tree"])

        return nonce

    def _re_key(self, target_nonce, current_sss_tree):
        if "key_slot_id" in current_sss_tree:
            key_slot = self.data["key_slots"][current_sss_tree["key_slot_id"]]
            auth_module = AUTH_TYPE_MAP[key_slot["auth_type"]]

            auth_module.lock_key_slot(key_slot, target_nonce)

        else:
            sss_keys = SecretSharer.split_secret(
                target_nonce,
                current_sss_tree["required_auth_count"],
                len(current_sss_tree["children"]),
            )

            for new_target, child in zip(sss_keys, current_sss_tree["children"]):
                self._re_key(new_target, child)

    def unlock(self, key_slot_unlock_data):
        return self._unlock(self.data["sss_tree"], key_slot_unlock_data)

    def _unlock(self, current_sss_tree, key_slot_unlock_data):
        if "key_slot_id" in current_sss_tree:
            key_slot_id = current_sss_tree["key_slot_id"]
            key_slot = self.data["key_slots"][key_slot_id]
            auth_module = AUTH_TYPE_MAP[key_slot["auth_type"]]
            cur_key_slot_unlock_data = key_slot_unlock_data[key_slot_id]

            if cur_key_slot_unlock_data is None:
                return None

            return auth_module.unlock_key_slot(key_slot, cur_key_slot_unlock_data)

        unlocked_nonces = []
        for child in current_sss_tree["children"]:
            child_nonce = self._unlock(child, key_slot_unlock_data)
            if child_nonce is not None:
                unlocked_nonces.append(child_nonce)

                if len(unlocked_nonces) == current_sss_tree["required_auth_count"]:
                    break

        else:
            # We don't have enough info to unlock this tree :(
            return None

        return SecretSharer.recover_secret(unlocked_nonces)

    def __repr__(self):
        return "Auth(%s)" % repr(self.data)


if __name__ == "__main__":
    a = Auth(
        {
            "key_slots": [
                {"auth_type": "password", "_password": "1111", "key_size": 1024},
                {
                    "auth_type": "gpg",
                    "key_fingerprint": "D9386D384AC7A7FBE27117E5B3BDC2E65D11A648",
                },
                {"auth_type": "password", "_password": "2222", "key_size": 1024},
                {"auth_type": "password", "_password": "3333", "key_size": 1024},
            ],
            "sss_tree": {
                "required_auth_count": 2,
                "children": [{"key_slot_id": 0}, {"key_slot_id": 1}, {"key_slot_id": 2}],
            },
        }
    )
    print("got auth: %s" % a)

    print("Rekey to: %s" % a.re_key())

    print("Unlocked: %s" % a.unlock(["1111", None, "3333"]))
