# RSA 

This is a simple demonstration of RSA key generation, encryption, decryption, signing, and verification using Python. It uses a custom RSA implementation with Miller-Rabin primality checks and the Extended Euclidean Algorithm.

## Features

- **Generate RSA keys** (public key and private key)  
- **Encrypt** and **Decrypt** text messages  
- **Sign** messages and **Verify** signatures  


## Usage

1. **Generate RSA Keys**

   ```bash
   python main.py --mode generate_keys --bits 512
   ```
`--bits 512`: Specifies the key size. For demonstration, 512 bits is enough; in real usage, 2048 or more is recommended.

This command generates:
* A public key file public.key (containing e and n)
* A private key file private.key (containing d and n)

2. **Encrypt a Message**
```
python main.py --mode encrypt --input_file message.txt        
```
* it takes public key generated above
* The ciphertext is saved in a file called ciphertext.txt

3. **Decrypt a Message**
```
python main.py --mode decrypt --ciphertext_file ciphertext.txt
```
* `--ciphertext ciphertext.txt`: The hex-encoded ciphertext that was output in the previous step.

* it takes private key generated above

4. **Sign a Message**

```
python main.py --mode sign --input_file message.txt 
```
* Saves the signature (hex-encoded) to the file.

5. **Verify a Signature**

```
python main.py --mode verify --input_file message.txt --signature_file signature.txt
```
* Verifies that <signature> (hex-encoded) is valid for the message file under with the public key generated on step 1.
* Prints "Signature valid!" or "Signature invalid!" depending on the outcome.

