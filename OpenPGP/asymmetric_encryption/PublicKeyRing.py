from asymmetric_encryption.PublicKey import PublicKey


class PublicKeyRing:

    def __init__(self):
        self.keys = []

    def save_key(self, public_key, username, email, algo):
        pk = PublicKey(public_key, username, email, algo)
        self.keys.append(pk)

    def add_key(self, public_key):
        self.keys.append(public_key)

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

    def delete_key(self, key_id):
        temp = None
        for key in self.keys:
            if key.key_id == key_id:
                temp = key
                break

        if temp != None:
            self.keys.remove(temp)

publicKeyRing = PublicKeyRing()
