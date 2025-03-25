import argparse
import random
import sys

def bytes_to_long(b):
    return int.from_bytes(b, byteorder='big')

def long_to_bytes(n):
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, byteorder='big')

from rsa import (
    generate_rsa_keys,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify
)

def main():
    parser = argparse.ArgumentParser(
        description="A simple RSA demonstration with dynamic arguments."
    )
    parser.add_argument("--bits", type=int, default=512,
                        help="Key size (in bits). Default is 512 (for demo). Use >=2048 in real usage.")
    parser.add_argument("--mode", choices=["encrypt", "decrypt", "sign", "verify"],
                        help="Action to perform.")
    parser.add_argument("--message", type=str, default="Hello RSA!",
                        help="Message to encrypt/sign.")
    parser.add_argument("--ciphertext", type=str,
                        help="Ciphertext (hex) for decryption.")
    parser.add_argument("--signature", type=str,
                        help="Signature (hex) for verification.")
    args = parser.parse_args()

    # Generate ephemeral keys (public: (e,n), private: (d,n))
    e, d, n = generate_rsa_keys(args.bits)

    # Show the user the keys
    print(f"Generated RSA keys ({args.bits} bits):")
    print(f"  Public key (e,n): e={e}, n={n}")
    print(f"  Private key (d,n): d={d}, n={n}\n")

    # Convert message to integer if needed
    m_bytes = args.message.encode("utf-8")
    m_int = bytes_to_long(m_bytes)

    if args.mode == "encrypt":
        # Encrypt
        c_int = rsa_encrypt(m_int, e, n)
        c_hex = hex(c_int)[2:]  # remove '0x'
        
        with open("ciphertext.txt", "w") as f:
            f.write(c_hex)
        print(f"Encrypted ciphertext saved!")

    elif args.mode == "decrypt":
        if not args.ciphertext:
            print("Error: Must provide --ciphertext <file path> for decryption.")
            sys.exit(1)

        try:
            with open(args.ciphertext, "r") as f:
                cipher_hex = f.read().strip()
            cipher_int = int(cipher_hex, 16)
        except Exception as e:
            print(f"Failed to read ciphertext file: {e}")
            sys.exit(1)

        decrypted_int = rsa_decrypt(cipher_int, d, n)
        decrypted_bytes = long_to_bytes(decrypted_int)

        # save the decrypted message to a file
        with open("decrypted_message.txt", "w") as f:
            f.write(decrypted_bytes.decode('utf-8', errors='replace'))
        print(f"🔓 Decrypted message saved!")

    elif args.mode == "sign":
        sig_int = rsa_sign(m_int, d, n)
        sig_hex = hex(sig_int)[2:]  # remove '0x'
        print(f"Signature (hex): {sig_hex}")

    elif args.mode == "verify":
        # Need signature in hex from user
        if not args.signature:
            print("Error: must specify --signature (hex) for verification.")
            sys.exit(1)
        try:
            sig_int = int(args.signature, 16)
        except ValueError:
            print("Error: signature must be a valid hex string.")
            sys.exit(1)
        is_ok = rsa_verify(sig_int, m_int, e, n)
        print("Signature valid?" if is_ok else "Signature invalid!")

    else:
        print("No action selected. Use --mode with encrypt|decrypt|sign|verify.")

if __name__ == "__main__":
    main()