class GlobalVariables:
    AES128 = 0
    TripleDES = 1
    RSA = 2
    ElGamal = 3
    DSA = 4

    codes = {AES128: 'AES128', TripleDES: 'TripleDES', RSA: 'RSA', ElGamal: 'ElGamal', DSA: 'DSA'}

    PRIVATE_KEYRING_PAIRS = './key_pairs/private_keyring'
    PUBLIC_KEYRING_PAIRS = './key_pairs/public_keyring'

    def __init__(self):
        self.asymmetric_algorithm = -1
        self.symmetric_algorithm = -1
        self.name = self.email = self.algoChecked = self.keySizeChecked = None
        self.passphrase = None

    def set_algoChecked(self, algoChecked):
        if not algoChecked:
            return
        if algoChecked == 'RSA':
            self.algoChecked = 2
        elif algoChecked == 'ElGamal':
            self.algoChecked = 3
        elif algoChecked == 'DSA':
            self.algoChecked = 4

    def set_keySizeChecked(self, keySizeChecked):
        if not keySizeChecked:
            return
        self.keySizeChecked = int(keySizeChecked)

    @classmethod
    def decode_algorithm_code(cls, code):
        return cls.codes[code]


globalVariables = GlobalVariables()
