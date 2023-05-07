from PrivateKey import PrivateKey


class PrivateKeyRing:

    def __init__(self):
        self.keys = []

    def save_key(self, public_key, private_key, email, passphrase, algo):
        pk = PrivateKey(public_key, private_key, email, passphrase, algo)
        self.keys.append(pk)

    def save_key_exisiting(self, private_key: PrivateKey):
        self.keys.append(private_key)

    def get_key_by_key_id(self, key_id):
        if key_id == 0 and len(self.keys) > 0:
            return self.keys[0]

        for key in self.keys:
            if key.key_id == key_id:
                return key

        return None

    def get_keys_by_user_id(self, user_id):
        user_id_keys = []
        for key in self.keys:
            if key.user_id == user_id:
                user_id_keys.append(key)

        return user_id_keys

    def get_all_keys(self):
        return self.keys

    def delete_key_pair(self, key_id):
        temp = None
        for key in self.keys:
            if key.key_id == key_id:
                temp = key
                break

        if temp != None:
            self.keys.remove(temp)

privateKeyRing = PrivateKeyRing()