import os
from coincurve import PrivateKey
import base58
import jinja2
import hashlib

PAGE_RANGES = {
    1: ('0x4000000000000000000000000000000000', '0x4fffffffffffffffffffffffffffffffff'),
    2: ('0x5000000000000000000000000000000000', '0x5fffffffffffffffffffffffffffffffff'),
    3: ('0x6000000000000000000000000000000000', '0x6fffffffffffffffffffffffffffffffff'),
    4: ('0x7000000000000000000000000000000000', '0x7fffffffffffffffffffffffffffffffff'),
}

KEYS_PER_PAGE = 1000

def hash160(b):
    ripemd = hashlib.new('ripemd160')
    ripemd.update(hashlib.sha256(b).digest())
    return ripemd.digest()

def pubkey_to_address(pubkey_bytes):
    prefix = b'\x00' + hash160(pubkey_bytes)
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58.b58encode(prefix + checksum).decode()

def generate_keys(start_hex, end_hex, count):
    start = int(start_hex, 16)
    step = (int(end_hex, 16) - start) // count
    for i in range(count):
        key_int = start + i * step
        priv_hex = f"{key_int:064x}"
        priv = PrivateKey.from_int(key_int)
        pub_bytes = priv.public_key.format(compressed=True)
        pub_hex = pub_bytes.hex()
        address = pubkey_to_address(pub_bytes)
        yield {'priv': priv_hex, 'pub': pub_hex, 'addr': address}

def generate_html(page_num, keys):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader("."))
    template = env.get_template("template.html")
    html = template.render(keys=keys, page=page_num)

    os.makedirs("pages", exist_ok=True)
    with open(f"pages/page_{page_num}.html", "w") as f:
        f.write(html)

if __name__ == "__main__":
    for page_num, (start_hex, end_hex) in PAGE_RANGES.items():
        print(f"Generating Page {page_num}...")
        keys = list(generate_keys(start_hex, end_hex, KEYS_PER_PAGE))
        generate_html(page_num, keys)
    print("✅ All pages generated.")
