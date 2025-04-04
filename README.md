# electronic-signature

created by: [Michella Miłecka](https://github.com/michellamilecka), [Alicja Lendzioszek](https://github.com/alicjalendzioszek)

## Project description
The project undertaken as part of the "Computer Systems Security" course aims to develop software for emulating a qualified electronic signature, enabling the signing of documents in compliance with current security standards.

## Features

1. **RSA Key Pair Generation**  
   - Generates a 4096-bit RSA key pair (public and private keys).

2. **Private Key Encryption**  
   - Encrypts the private RSA key using AES-256, with the encryption key derived from the SHA-256 hash of the user's PIN.

3. **Key Storage**  
   - Saves the encrypted private key to a USB drive, while the public key is stored locally.

4. **PIN-Based Key Decryption**  
   - Prompts the user to enter a 4-digit PIN to decrypt the private key stored on the USB drive.

5. **PDF Signing**  
   - Uses the decrypted private key to digitally sign a PDF document.

6. **File Saving**  
   - Saves the signed PDF file with a new name.

7. **PDF Signature Verification**  
   - Allows the verification of the PDF signature using the public RSA key.


