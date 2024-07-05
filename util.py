import os
import hashlib


def print_4bytes_little_endian(bytes, depth: int = 0):
    # bytes를 4bytes 단위로 자르기
    chunks = [bytes[i : i + 4] for i in range(0, len(bytes), 4)]

    # 각 4bytes를 little endian으로 변환하여 16진수로 출력
    for i, chunk in enumerate(chunks, 1):
        string = hex(int.from_bytes(chunk, byteorder="little"))[2:].upper().zfill(8)
        depth_str = " " * depth
        if i % 4 == 1:
            print(depth_str, end="")
        print("{}".format(string), end=" ")
        if i % 4 == 0:
            print()
    print()


def print_bytes_big_endian(bytes):
    # bytes를 1bytes 단위로 자르기
    chunks = [bytes[i : i + 1] for i in range(0, len(bytes), 1)]

    print("[", end="")
    # 각 1bytes를 little endian으로 변환하여 16진수로 출력
    for i, chunk in enumerate(chunks, 1):
        string = hex(int.from_bytes(chunk, byteorder="little"))[2:].upper().zfill(2)
        if i != len(chunks):
            print("0x{},".format(string), end=" ")
        else:
            print("0x{}".format(string), end="")
    print("]", end="")
    print()


def print_bytes_big_online(bytes):
    # bytes를 1bytes 단위로 자르기
    chunks = [bytes[i : i + 1] for i in range(0, len(bytes), 1)]

    print("[", end="")
    # 각 1bytes를 little endian으로 변환하여 16진수로 출력
    for i, chunk in enumerate(chunks, 1):
        string = hex(int.from_bytes(chunk, byteorder="little"))[2:].upper().zfill(2)
        if i != len(chunks):
            print("{}".format(string), end="")
        else:
            print("{}".format(string), end="")
    print("]", end="")
    print()


def print_input_output(func):
    def wrapper(*args, **kwargs):
        print("\n함수명:", func.__name__)
        # print("[입력]")
        # print(args, kwargs)
        result = func(*args, **kwargs)
        print("[출력]")
        print_bytes_big_endian(result)
        print()
        return result

    return wrapper


def read_config(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()

    parsed_lines = []
    for line in lines:
        parsed_line = line.split()
        parsed_lines.append(parsed_line)

    return parsed_lines


@print_input_output  ## 바이너리 해쉬 인풋 아웃풋 디버깅용
def get_bin_hash(file_path, file_name: str, hash_type: str):
    bin_path = os.path.join(file_path, file_name)
    with open(bin_path, "rb") as file:
        binary_bytes = file.read()
    if hash_type == "0":  # psp_bl1, custos_bl1, epbl
        data_bytes = binary_bytes[16:]
        hash_object = hashlib.sha512(data_bytes)
    elif hash_type == "1":  # host bl1, dbgc
        sign_header_len = 20
        sign_len = 512
        data_bytes = binary_bytes[: -(sign_header_len + sign_len)]
        hash_object = hashlib.sha512(data_bytes)
    elif hash_type == "2":
        sign_header_len = 0
        sign_len = 512
        data_bytes = binary_bytes[: -(sign_header_len + sign_len)]
        hash_object = hashlib.sha512(data_bytes)
    elif hash_type == "3":
        # CustOS 빌드마다 달라짐 Binary에서 제일 앞에서 부터파싱해서
        # Cust \x43\75\73\74 로시작하는 구간에서 + 0x10 한 부분 찾아야함
        offset = 0
        for i in range(len(binary_bytes) - 4):
            if binary_bytes[i : i + 4] == "Cust".encode("utf-8"):
                offset = i + 0x10
                break
        data_bytes = binary_bytes[:offset]
        hash_object = hashlib.sha512(data_bytes)
    return hash_object.digest()
