class UnsupportedSymmetricAlgorithm(Exception):

    def __init__(self):
        super(UnsupportedSymmetricAlgorithm, self).__init__('Symmetric algorithm is not supported!')