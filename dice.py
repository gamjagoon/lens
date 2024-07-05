from hashlib import sha512
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from util import print_input_output
from util import print_4bytes_little_endian
from util import print_bytes_big_endian

# Constants
DICE_CDI_SIZE = 32
DICE_HASH_SIZE = 64
DICE_HIDDEN_SIZE = 64
DICE_INLINE_CONFIG_SIZE = 64
DICE_PRIVATE_KEY_SEED_SIZE = 32
DICE_ID_SIZE = 20
DICE_PUBLIC_KEY_SIZE = 32
DICE_PRIVATE_KEY_SIZE = 32
DICE_SIGNATURE_SIZE = 64
DICE_MAX_PUBLIC_KEY_SIZE = DICE_PUBLIC_KEY_SIZE + 32
DICE_MAX_PROTECTED_ATTRIBUTES_SIZE = 16
DICE_COSE_KEY_ALG_VALUE = -8
DICE_PROFILE_NAME = None


class CDI:
    root_pub_key: bytes = b"\x00" * 32
    hash_function = hashes.SHA512()
    asym_salt = bytes(
        [
            0x63,
            0xB6,
            0xA0,
            0x4D,
            0x2C,
            0x07,
            0x7F,
            0xC1,
            0x0F,
            0x63,
            0x9F,
            0x21,
            0xDA,
            0x79,
            0x38,
            0x44,
            0x35,
            0x6C,
            0xC2,
            0xB0,
            0xB4,
            0x41,
            0xB3,
            0xA7,
            0x71,
            0x24,
            0x03,
            0x5C,
            0x03,
            0xF8,
            0xE1,
            0xBE,
            0x60,
            0x35,
            0xD3,
            0x1F,
            0x28,
            0x28,
            0x21,
            0xA7,
            0x45,
            0x0A,
            0x02,
            0x22,
            0x2A,
            0xB1,
            0xB3,
            0xCF,
            0xF1,
            0x67,
            0x9B,
            0x05,
            0xAB,
            0x1C,
            0xA5,
            0xD1,
            0xAF,
            0xFB,
            0x78,
            0x9C,
            0xCD,
            0x2B,
            0x0B,
            0x3B,
        ]
    )
    id_salt = bytes(
        [
            0xDB,
            0xDB,
            0xAE,
            0xBC,
            0x80,
            0x20,
            0xDA,
            0x9F,
            0xF0,
            0xDD,
            0x5A,
            0x24,
            0xC8,
            0x3A,
            0xA5,
            0xA5,
            0x42,
            0x86,
            0xDF,
            0xC2,
            0x63,
            0x03,
            0x1E,
            0x32,
            0x9B,
            0x4D,
            0xA1,
            0x48,
            0x43,
            0x06,
            0x59,
            0xFE,
            0x62,
            0xCD,
            0xB5,
            0xB7,
            0xE1,
            0xE0,
            0x0F,
            0xC6,
            0x80,
            0x30,
            0x67,
            0x11,
            0xEB,
            0x44,
            0x4A,
            0xF7,
            0x72,
            0x09,
            0x35,
            0x94,
            0x96,
            0xFC,
            0xFF,
            0x1D,
            0xB9,
            0x52,
            0x0B,
            0xA5,
            0x1C,
            0x7B,
            0x29,
            0xEA,
        ]
    )

    def __init__(self):
        self.UDS = b"\x00" * 32
        self.cdi_attest: bytes = self.UDS
        self.cdi_seal: bytes = self.UDS
        self.prev_cdi_attest: bytes = b"\x00" * 32
        self.prev_cdi_seal: bytes = b"\x00" * 32
        # Calculate Root Pub Key
        _, self.root_pub_key = self.asyn_kdf(self.UDS)

    @staticmethod
    def SHA2_512(input: bytes):
        ret = sha512(input).digest()
        return ret

    @classmethod
    def gen_cdi_attest(
        cls,
        prev_attest: bytes,
        code: bytes,
        config: bytes = b"\x00" * 64,
        authority: bytes = b"\x00" * 64,
        mode: bytes = b"\x00" * 1,
        hidden: bytes = b"\x00" * 64,
    ):
        """
        code (64 bytes)
        Configuration Data (64 bytes)
        Authority Data (64 bytes)
        Mode Decision (1 byte)
        Hidden Inputs (64 bytes)
        """
        cdi_hkdf = HKDF(
            cls.hash_function,
            DICE_CDI_SIZE,
            cls.SHA2_512(code + config + authority + mode + hidden),
            "CDI_Attest".encode("utf-8"),
        )
        ret = cdi_hkdf.derive(prev_attest)
        return ret

    @classmethod
    def gen_cdi_seal(
        cls,
        prev_seal: bytes,
        authority: bytes = b"\x00" * 64,
        mode: bytes = b"\x00" * 1,
        hidden: bytes = b"\x00" * 64,
    ):
        cdi_hkdf = HKDF(
            cls.hash_function,
            DICE_CDI_SIZE,
            cls.SHA2_512(authority + mode + hidden),
            "CDI_Seal".encode("utf-8"),
        )
        ret = cdi_hkdf.derive(prev_seal)
        return ret

    @classmethod
    @print_input_output
    def gen_id(cls, input: bytes):
        """
        UDS_ID = KDF(20, UDS_Public, ID_SALT, "ID")
        CDI_ID = KDF(20, CDI_Public, ID_SALT, "ID")
        """
        id_hkdf = HKDF(
            cls.hash_function,
            DICE_ID_SIZE,
            cls.id_salt,
            "ID".encode("utf-8"),
        )
        ret = id_hkdf.derive(input)
        return ret

    @staticmethod
    def ed25519_sign(private_key_value: bytes, msg: bytes) -> bytes:
        """
        signing msg using private_key_value
        """
        ed25519_obj_with_pk = ed25519.Ed25519PrivateKey.from_private_bytes(
            private_key_value
        )
        return ed25519_obj_with_pk.sign(msg)

    @staticmethod
    def ed25519_public_key_generation(private_key_value: bytes) -> bytes:
        return (
            ed25519.Ed25519PrivateKey.from_private_bytes(private_key_value)
            .public_key()
            .public_bytes_raw()
        )

    @classmethod
    def asyn_kdf(cls, input: bytes):
        """
        1. Generate private_key from input value
        2. Generate public key-fair using ed25519 key generation
        return (private_key, public_key)
        """
        asyn_hkdf = HKDF(
            cls.hash_function,
            32,
            cls.asym_salt,
            "Key Pair".encode("utf-8"),
        )
        print("[input]")
        print_bytes_big_endian(input)
        private_key = asyn_hkdf.derive(input)
        public_key = cls.ed25519_public_key_generation(private_key)
        print("[private key]")
        print_bytes_big_endian(private_key)
        print("[public key]")
        print_bytes_big_endian(public_key)
        return (private_key, public_key)

    def gen_next_cdi_attest_seal(
        self,
        code: bytes = b"\x00" * 64,
        config: bytes = b"\x00" * 64,
        authority: bytes = b"\x00" * 64,
        mode: bytes = b"\x00" * 1,
        hidden: bytes = b"\x00" * 64,
    ):
        self.prev_cdi_attest = self.cdi_attest
        self.prev_cdi_seal = self.cdi_seal
        self.cdi_attest = self.gen_cdi_attest(
            self.prev_cdi_attest, code, config, authority, mode, hidden
        )
        self.cdi_seal = self.gen_cdi_seal(self.prev_cdi_seal, authority, mode, hidden)

    def view_cdi(self, cdi: int):
        print("[CDI{} Attest]".format(cdi))
        print_bytes_big_endian(self.cdi_attest)
        print("[CDI{} Seal]".format(cdi))
        print_bytes_big_endian(self.cdi_seal)
        print()
