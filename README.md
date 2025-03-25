# RSA 

This is a simple demonstration of RSA key generation, encryption, decryption, signing, and verification using Python. It uses a custom RSA implementation with Miller-Rabin primality checks and the Extended Euclidean Algorithm.

## Features

- **Generate RSA keys** (public key and private key)  
- **Encrypt** and **Decrypt** text messages  
- **Sign** messages and **Verify** signatures  


## Usage

1. **Generate RSA Keys**

   ```bash
   python script.py --mode generate_keys --bits 512
   ```
`--bits 512`: Specifies the key size. For demonstration, 512 bits is enough; in real usage, 2048 or more is recommended.

This command generates:
* A public key file public.key (containing e and n)
* A private key file private.key (containing d and n)

2. **Encrypt a Message**
```
python script.py --mode encrypt --message "Hello RSA!" --public_key public.key
```
* `--public_key public.key`: Specify the public key file to load
* The ciphertext is saved in a file called ciphertext.txt

3. **Decrypt a Message**
```
python script.py --mode decrypt --ciphertext ciphertext.txt --private_key private.key
```
* `--ciphertext ciphertext.txt`: The hex-encoded ciphertext that was output in the previous step.

* `--private_key private.key`: Specify the private key file to load.

4. **Sign a Message**

```
python script.py --mode sign --message "Important document" --private_key private.key

Prints out the signature (hex-encoded) on the console. You can copy it for verification.

5. **Verify a Signature**

```
python script.py --mode verify --message "Important document" --signature <paste-the-hex-signature-here> --public_key public.key
```
* Verifies that <signature> (hex-encoded) is valid for the message "Important document" under the provided public key public.key.
* Prints "Signature valid!" or "Signature invalid!" depending on the outcome.

