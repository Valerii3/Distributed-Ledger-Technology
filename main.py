import argparse
import sys
from rsa import (
    generate_rsa_keys,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify
)


def bytes_to_long(b: bytes) -> int:
    """
    Converts a byte sequence to a long integer.
    """
    return int.from_bytes(b, byteorder='big')


def long_to_bytes(n: int) -> bytes:
    """
    Converts a long integer back to bytes.
    """
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, byteorder='big')


def read_key_file(path: str, key_type: str) -> tuple[int, int]:
    """
    Reads a public or private RSA key from a file.

    Args:
        path: Path to the key file.
        key_type: A string indicating "public" or "private" (used for error messages).

    Returns:
        Tuple containing the key values (e or d, n).
    """
    try:
        with open(path, "r") as f:
            lines = f.read().split()
            key1 = int(lines[0])
            key2 = int(lines[1])
        return key1, key2
    except Exception as ex:
        print(f"Error reading {key_type} key file '{path}': {ex}")
        sys.exit(1)


def generate_keys(args: argparse.Namespace) -> None:
    """
    Generates RSA keys and saves them to files.
    """
    e, d, n = generate_rsa_keys(args.bits)
    with open(args.public_key, "w") as pubf:
        pubf.write(f"{e}\n{n}\n")
    with open(args.private_key, "w") as prvf:
        prvf.write(f"{d}\n{n}\n")
    print(f"Generated RSA keys ({args.bits} bits) and saved to:")
    print(f"  - {args.public_key}")
    print(f"  - {args.private_key}")


def encrypt_file(args: argparse.Namespace) -> None:
    """
    Encrypts the content of a file using RSA and writes the ciphertext to a file.
    """
    if not args.input_file:
        print("Error: Must specify --input_file for encryption.")
        sys.exit(1)

    e, n = read_key_file(args.public_key, "public")

    with open(args.input_file, "rb") as f:
        plaintext_bytes = f.read()

    m_int = bytes_to_long(plaintext_bytes)
    c_int = rsa_encrypt(m_int, e, n)
    c_hex = hex(c_int)[2:]

    with open(args.output_ciphertext, "w") as f:
        f.write(c_hex)

    print(f"Encrypted data saved to {args.output_ciphertext}")


def decrypt_file(args: argparse.Namespace) -> None:
    """
    Decrypts an RSA-encrypted file and writes the plaintext bytes to a file.
    """
    if not args.ciphertext_file:
        print("Error: Must specify --ciphertext_file for decryption.")
        sys.exit(1)

    d, n = read_key_file(args.private_key, "private")

    try:
        with open(args.ciphertext_file, "r") as f:
            cipher_hex = f.read().strip()
        cipher_int = int(cipher_hex, 16)
    except Exception as ex:
        print(f"Failed to read ciphertext file: {ex}")
        sys.exit(1)

    decrypted_int = rsa_decrypt(cipher_int, d, n)
    decrypted_bytes = long_to_bytes(decrypted_int)

    with open(args.output_decrypted, "wb") as f:
        f.write(decrypted_bytes)

    print(f"Decrypted data saved to {args.output_decrypted}")


def sign_file(args: argparse.Namespace) -> None:
    """
    Signs a file using the RSA private key and saves the signature to a file.
    """
    if not args.input_file:
        print("Error: Must specify --input_file for signing.")
        sys.exit(1)

    d, n = read_key_file(args.private_key, "private")

    with open(args.input_file, "rb") as f:
        data_bytes = f.read()

    sig_int = rsa_sign(bytes_to_long(data_bytes), d, n)
    sig_hex = hex(sig_int)[2:]

    with open(args.output_signature, "w") as f:
        f.write(sig_hex)

    print(f"Signature saved to {args.output_signature}")


def verify_signature(args: argparse.Namespace) -> None:
    """
    Verifies a digital signature using the RSA public key.
    """
    if not args.input_file or not args.signature_file:
        print("Error: Must specify both --input_file and --signature_file for verification.")
        sys.exit(1)

    e, n = read_key_file(args.public_key, "public")

    with open(args.input_file, "rb") as f:
        data_bytes = f.read()
    m_int = bytes_to_long(data_bytes)

    try:
        with open(args.signature_file, "r") as f:
            sig_hex = f.read().strip()
        sig_int = int(sig_hex, 16)
    except Exception as ex:
        print(f"Failed to read signature file: {ex}")
        sys.exit(1)

    is_ok = rsa_verify(sig_int, m_int, e, n)
    print("Signature valid!" if is_ok else "Signature invalid!")


def parse_arguments() -> argparse.Namespace:
    """
    Parses and returns command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="A simple RSA demonstration using file-based input/output."
    )
    parser.add_argument("--bits", type=int, default=512,
                        help="Key size in bits (default: 512). Use >=2048 for real use.")

    parser.add_argument("--mode", choices=[
        "generate_keys", "encrypt", "decrypt", "sign", "verify"
    ], required=True, help="Action to perform.")

    parser.add_argument("--public_key", default="public.key", help="Path to public key file.")
    parser.add_argument("--private_key", default="private.key", help="Path to private key file.")
    parser.add_argument("--input_file", help="File to encrypt, sign, or verify.")
    parser.add_argument("--ciphertext_file", help="Ciphertext file to decrypt.")
    parser.add_argument("--signature_file", help="Signature file to verify.")
    parser.add_argument("--output_ciphertext", default="ciphertext.txt", help="Output path for ciphertext.")
    parser.add_argument("--output_decrypted", default="decrypted.bin", help="Output path for decrypted data.")
    parser.add_argument("--output_signature", default="signature.txt", help="Output path for signature.")

    return parser.parse_args()


def main():
    args = parse_arguments()

    mode_functions = {
        "generate_keys": generate_keys,
        "encrypt": encrypt_file,
        "decrypt": decrypt_file,
        "sign": sign_file,
        "verify": verify_signature,
    }

    mode_func = mode_functions.get(args.mode)
    if mode_func:
        mode_func(args)
    else:
        print("Invalid mode selected.")

if __name__ == "__main__":
    main()
