from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

import base64

import os

class Node:
    def __init__(self, data):
        self.left = None
        self.right = None
        self.data = data
    
    def __repr__(self) -> str:
        data_repr = self.data.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        left_pkey = self.left.public_key() if isinstance(self.left, ec.EllipticCurvePrivateKey) else self.left
        left_repr = left_pkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        right_pkey = self.right.public_key() if isinstance(self.right, ec.EllipticCurvePrivateKey) else self.right
        right_repr = right_pkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        return f"Node: [{data_repr}]\nLeft: [{left_repr}]\nRight: [{right_repr}]"


def sha256(*keys) -> bytes:
    digest = hashes.Hash(hashes.SHA256())

    for key in keys:
        digest.update(key)

    return digest.finalize()


def exchange(sk, target):
    msg = handshake(sk, target.public_key())
    out = read_handshake(msg, target)

    derived_key = derive_ec_from_secret(out)

    node = Node(derived_key)
    node.left = sk
    node.right = target

    return node


def compute_root(tree):
    assert(tree.left is ec.EllipticCurvePrivateKey)


def get_aes_params(secret: bytes):
    nonce = HKDF(
        algorithm=hashes.SHA256(),
        length=12,
        salt=None,
        info=b'EDHE Nonce',
    ).derive(secret)
    
    transmission_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'EDHE Key',
    ).derive(secret)

    return (nonce, transmission_key)


# This would be an invite stored on the blockchain (Maybe post members expected public key on there too? Add the node on their behalf ready to go)
def handshake(sk: ec.EllipticCurvePrivateKey, target_pk: ec.EllipticCurvePublicKey):
    secret = sk.exchange(ec.ECDH(), target_pk)

    aes_params = get_aes_params(secret)

    aes = aead.AESGCM(aes_params[1])
    message = aes.encrypt(
        aes_params[0],
        secret,
        None
    )

    return (sk.public_key(), message)


def read_handshake(message, sk: ec.EllipticCurvePrivateKey):
    secret = sk.exchange(ec.ECDH(), message[0])

    aes_params = get_aes_params(secret)
    aes = aead.AESGCM(aes_params[1])

    out = aes.decrypt(
        aes_params[0],
        message[1],
        None
    )

    return out


def derive_ec_from_secret(secret: bytes):
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'DHE Key',
    ).derive(secret)

    return ec.derive_private_key(int.from_bytes(key, byteorder="big"), ec.SECP384R1())


def main():
    # TODO: Maybe make the exchange use an Ephemeral key again and sign the message with the senders public id key
    # Although perhaps message integrity is already provided by virtue of the blockchain...
    a = ec.generate_private_key(ec.SECP384R1())
    b = ec.generate_private_key(ec.SECP384R1())
    c = ec.generate_private_key(ec.SECP384R1())
    d = ec.generate_private_key(ec.SECP384R1())

    '''
        TODO: Figure out graceful way to rebalance Perhaps when new 'trusted' administrative users are added,
        a rebalance can occur in which the groups are further split and delegated to the new admin account.
        This is important to consider because the tree essentially forms a chain of trust in which the top most group
        members are responsible for the nodes under them.

        Construct a tree where the root node can be reconstructed. Tree layout:
                            [DH(D, DH(DH(DH(A, B), C)))]
                    [DH(DH(A, B), C)]                    [D]
                [DH(A, B)]            [C]
            [A]            [B]
    '''

    # A Constructs the DH Tree
    # DH(A, B)
    ab = exchange(a, b)
    # DH(DH(A, B), C)
    abc = exchange(ab.data, c)
    # DH(DH(DH(A, B), C), D)
    abcd = exchange(abc.data, d)

    # Theoretical exchange where D computes DH(D, DH(DH(DH(A, B), C)))
    dabc = exchange(d, abc.data)

    abcd_pem = abcd.data.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    dabc_pem = dabc.data.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    print(abcd_pem)
    print(dabc_pem)
    print(abcd_pem == dabc_pem)


if __name__ == "__main__":
    main()