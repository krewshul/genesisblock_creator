import hashlib, struct, os, time, sys, argparse
import scrypt
from construct import *
from ecdsa import SigningKey, SECP256k1


def main():
    options = get_args()

    algorithm = get_algorithm(options)

    input_script = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)

    tx = create_transaction(input_script, output_script, options)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    print_block_info(options, hash_merkle_root)

    block_header = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)
    genesis_hash, nonce = generate_hash(block_header, algorithm, options.nonce, options.bits)
    announce_found_genesis(genesis_hash, nonce)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--time", dest="time", default=None, type=int, help="Block time (default: current time)")
    parser.add_argument("-z", "--timestamp", dest="timestamp",
                        default="04/24/2025 - OurCoin - SF is not what it was",
                        type=str)
    parser.add_argument("-n", "--nonce", dest="nonce", default=0, type=int)
    parser.add_argument("-a", "--algorithm", dest="algorithm", default="SHA256")
    parser.add_argument("-p", "--pubkey", dest="pubkey", type=str)
    parser.add_argument("-v", "--value", dest="value", default=5000000000, type=int)
    parser.add_argument("-b", "--bits", dest="bits", type=lambda x: int(x, 0))

    options = parser.parse_args()

    if options.time is None:
        options.time = int(time.time())

    if not options.pubkey:
        print("[+] No pubkey provided, generating random public key...")
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        options.pubkey = '04' + vk.to_string().hex()
        print("[+] Generated pubkey:", options.pubkey)

    if not options.bits:
        options.bits = 0x1e0ffff0 if options.algorithm in ["scrypt", "X11", "X13", "X15"] else 0x1d00ffff

    return options


def get_algorithm(options):
    supported_algorithms = ["SHA256", "scrypt", "X11", "X13", "X15"]
    if options.algorithm not in supported_algorithms:
        sys.exit("Error: Given algorithm must be one of: " + str(supported_algorithms))
    return options.algorithm


def create_input_script(psz_timestamp):
    psz_prefix = "4c" if len(psz_timestamp) > 76 else ""
    script_prefix = '04ffff001d0104' + psz_prefix + format(len(psz_timestamp), '02x')
    full_script = script_prefix + psz_timestamp.encode().hex()
    print(full_script)
    return bytes.fromhex(full_script)


def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return bytes.fromhex(script_len + pubkey + OP_CHECKSIG)


def create_transaction(input_script, output_script, options):
    transaction = Struct(
        "version" / Int32ul,
        "num_inputs" / Byte,
        "prev_output" / Bytes(32),
        "prev_out_idx" / Int32ul,
        "input_script_len" / Byte,
        "input_script" / Bytes(len(input_script)),
        "sequence" / Int32ul,
        "num_outputs" / Byte,
        "out_value" / Bytes(8),
        "output_script_len" / Byte,
        "output_script" / Bytes(0x43),
        "locktime" / Int32ul
    )

    tx = dict(
        version=1,
        num_inputs=1,
        prev_output=bytes(32),
        prev_out_idx=0xFFFFFFFF,
        input_script_len=len(input_script),
        input_script=input_script,
        sequence=0xFFFFFFFF,
        num_outputs=1,
        out_value=struct.pack('<Q', options.value),
        output_script_len=0x43,
        output_script=output_script,
        locktime=0
    )
    return transaction.build(tx)


def create_block_header(hash_merkle_root, time_val, bits, nonce):
    block_header = Struct(
        "version" / Int32ul,
        "hash_prev_block" / Bytes(32),
        "hash_merkle_root" / Bytes(32),
        "time" / Int32ul,
        "bits" / Int32ul,
        "nonce" / Int32ul
    )

    header = dict(
        version=1,
        hash_prev_block=bytes(32),
        hash_merkle_root=hash_merkle_root,
        time=time_val,
        bits=bits,
        nonce=nonce
    )
    return block_header.build(header)


def generate_hash(data_block, algorithm, start_nonce, bits):
    print("Searching for genesis hash...")
    nonce = start_nonce
    last_updated = time.time()
    target = (bits & 0xffffff) * 2 ** (8 * ((bits >> 24) - 3))

    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block, algorithm)
        last_updated = calculate_hashrate(nonce, last_updated)
        if is_genesis_hash(header_hash, target):
            return (sha256_hash if algorithm in ["SHA256", "scrypt"] else header_hash, nonce)
        nonce += 1
        data_block = data_block[:-4] + struct.pack('<I', nonce)


def generate_hashes_from_block(data_block, algorithm):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    header_hash = b""
    if algorithm == 'scrypt':
        header_hash = scrypt.hash(data_block, data_block, 1024, 1, 1, 32)[::-1]
    elif algorithm == 'SHA256':
        header_hash = sha256_hash
    elif algorithm == 'X11':
        import xcoin_hash
        header_hash = xcoin_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X13':
        import x13_hash
        header_hash = x13_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X15':
        import x15_hash
        header_hash = x15_hash.getPoWHash(data_block)[::-1]
    return sha256_hash, header_hash


def is_genesis_hash(header_hash, target):
    return int.from_bytes(header_hash, 'big') < target


def calculate_hashrate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hashrate = round(1000000 / (now - last_updated))
        generation_time = round(pow(2, 32) / hashrate / 3600, 1)
        sys.stdout.write(f"\r{hashrate} hash/s, estimate: {generation_time} h")
        sys.stdout.flush()
        return now
    return last_updated


def print_block_info(options, hash_merkle_root):
    print("algorithm:", options.algorithm)
    print("merkle hash:", hash_merkle_root[::-1].hex())
    print("pszTimestamp:", options.timestamp)
    print("pubkey:", options.pubkey)
    print("time:", options.time)
    print("bits:", hex(options.bits))


def announce_found_genesis(genesis_hash, nonce):
    print("genesis hash found!")
    print("nonce:", nonce)
    print("genesis hash:", genesis_hash.hex())


if __name__ == '__main__':
    main()
