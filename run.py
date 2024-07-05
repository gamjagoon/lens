import dice
import os
import hashlib

from util import (
    get_bin_hash,
    print_4bytes_little_endian,
    print_bytes_big_endian,
    read_config,
)

#
TEST_MODE = True
# Window에서는 \\로 구분해야 한다.
WorkDirectory = "C:\\Users\\mingjae.kim\\Solomon"
## Read Config
bin_path = os.path.abspath("C:\\Users\\mingjae.kim\\Solomon")
config_path = os.path.join(os.getcwd(), "config")
configs = read_config(config_path)

## Check Config

## get binary hashes
BIN_HASHS = dict()
for bin_path_name, bin_name, hash_type in configs:
    print(bin_name)
    hash_bytes = get_bin_hash(bin_path, bin_path_name, hash_type)
    BIN_HASHS.update({bin_name: hash_bytes})

## generate CDI CustOS BL1

# init cdi class

dice_chain_bin_list = [
    "psp_bl1",
    "debug_core",
    "hostbl1",
    "custos_bl1",
    "epbl",
    "bl2",
    "dpm",
    "bootloader",
    "custos",
    "el3_mon",
    "keystorage",
    "svm",
    "ldfw",
    "tzsw",
]

for bin_name in dice_chain_bin_list:
    if bin_name not in BIN_HASHS.keys():
        print("{} bin error", bin_name)
        raise Exception("bin = {} is not contained", bin_name)

########################
# Cust OS BL1 Sequence #
########################

if TEST_MODE is False:
    # Hash(H_hostbl1 | H_custos_bl1 | H_epbl)
    code_hash_custos_bl1 = hashlib.sha512(
        BIN_HASHS["psp_bl1"]
        + BIN_HASHS["debug_core"]
        + BIN_HASHS["hostbl1"]
        + BIN_HASHS["epbl"]
        + BIN_HASHS["custos_bl1"]
        + BIN_HASHS["bl2"]
        + BIN_HASHS["dpm"]
        + BIN_HASHS["bootloader"]
        + BIN_HASHS["custos"]
    ).digest()
    print("[code_hash CustOS BL1]")
    print_bytes_big_endian(code_hash_custos_bl1)
    print()
else:
    print("[Test Mode = Ture]")
    code_hash_custos_bl1 = b"\x00" * 64
    print("[code_hash CustOS BL1]")
    print_bytes_big_endian(code_hash_custos_bl1)
    print()

custos_CDI = dice.CDI()

# generate CDI0
custos_CDI.gen_next_cdi_attest_seal(code_hash_custos_bl1)
custos_CDI.view_cdi(1)

CDI_ATTEST_0 = custos_CDI.cdi_attest
CDI_SEAL_0 = custos_CDI.cdi_seal

####################
# Cust OS Sequence #
####################
# generate CDI1
custos_CDI.gen_next_cdi_attest_seal(BIN_HASHS["el3_mon"])
custos_CDI.view_cdi(2)

CDI_ATTEST_1 = custos_CDI.cdi_attest
CDI_SEAL_1 = custos_CDI.cdi_seal

# # generate CDI2
custos_CDI.gen_next_cdi_attest_seal(BIN_HASHS["keystorage"])
custos_CDI.view_cdi(3)

CDI_ATTEST_2 = custos_CDI.cdi_attest
CDI_SEAL_2 = custos_CDI.cdi_seal

# # generate CDI3
custos_CDI.gen_next_cdi_attest_seal(BIN_HASHS["svm"])
custos_CDI.view_cdi(4)

CDI_ATTEST_3 = custos_CDI.cdi_attest
CDI_SEAL_3 = custos_CDI.cdi_seal

# # generate CDI4
custos_CDI.gen_next_cdi_attest_seal(BIN_HASHS["ldfw"])
custos_CDI.view_cdi(5)

CDI_ATTEST_4 = custos_CDI.cdi_attest
CDI_SEAL_4 = custos_CDI.cdi_seal

# # generate BCC4
# input_value = {}  # TODO! : change dictionary values
# BCC4 = custos_BCC.DiceGenerateCertificate(CDI_ATTEST_3, CDI_ATTEST_4, input_value)

# # generate CDI5
# custos_CDI.gen_next_cdi_attest_seal(BIN_HASHS["tzsw"])
# custos_CDI.view_cdi(6)

# CDI_ATTEST_5 = custos_CDI.cdi_attest
# CDI_SEAL_5 = custos_CDI.cdi_seal

# # generate BCC5
# input_value = {}  # TODO! : change dictionary values
# BCC5 = custos_BCC.DiceGenerateCertificate(CDI_ATTEST_4, CDI_ATTEST_5, input_value)
