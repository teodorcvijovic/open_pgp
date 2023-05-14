class InvalidSignature(Exception):

    def __init__(self):
        super(InvalidSignature, self).__init__('Signature is not valid!')