import psutil
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Signature import pkcs1_15

privateFileName = "private_key_encrypted.pem"
signatureLength = 512

# szukanie pendrive'a podlaczonego do komputera
def find_usb_drive():
    
    for partition in psutil.disk_partitions():
        
        if 'removable' in partition.opts:
            return partition.device  
        
    return None

# szukanie pelnej sciezki do klucza prywatnego znajdujacego sie na pendrive
def find_private_key_path(usb_drive):

    if usb_drive:
     
        private_key_path = os.path.join(usb_drive, privateFileName)

        if os.path.exists(private_key_path):
            return private_key_path
        else:
            return None
    else:
        return None

# odszyfrowywanie klucza prywatnego znalezionego na pendrive
def decrypt_private_key(private_key_path, pin):
    try:
        with open(private_key_path, "rb") as f:
            encrypted_data = f.read()
    
        initialization_vector = encrypted_data[:16]
        encrypted_private_key = encrypted_data[16:]
    
        pin_encoded = pin.encode('utf-8')
        key_aes = SHA256.new(pin_encoded).digest()#[:32]
    
        cipher = AES.new(key_aes, AES.MODE_CBC, iv=initialization_vector)
        decrypted_private_key = unpad(cipher.decrypt(encrypted_private_key), AES.block_size)
    
        private_key = RSA.import_key(decrypted_private_key)
        
        return private_key
    except (ValueError, KeyError):
        print("nieprawidłowy pin")
        return None

# podpisanie wybranego pdfa
def sign_file(file_path, decrypted_private_key):
    
    with open(file_path, "rb") as f:
        document_data = f.read()

    file_hash = SHA256.new(document_data)
    signature = pkcs1_15.new(decrypted_private_key).sign(file_hash)

    with open(file_path, "ab") as f:
        f.write(signature)
    
    new_file_path = file_path.replace(".pdf", "_signed.pdf")
    os.rename(file_path, new_file_path)
    print("podpisane")

# weryfikacja podpisanego pdfa
def verify_signature(file_path, public_key_path):

    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    with open(file_path, "rb") as f:
        document_data = f.read()

    signature = document_data[-signatureLength:]
    document_data_without_signature = document_data[:-signatureLength]

    file_hash = SHA256.new(document_data_without_signature)

    try:
        pkcs1_15.new(public_key).verify(file_hash, signature)
        print("jest git")
        return True
    except (ValueError, TypeError):
        print("nie jest git")
        return False
    

#usb_drive = find_usb_drive()
#private_path = find_private_key_path(usb_drive)
#decrypted_key = decrypt_private_key(private_path,"1234")
#sign_file(file_path="C:\\Users\\alicj\\Downloads\\zwolnienie1.pdf", decrypted_private_key=decrypted_key)
verify_signature(file_path="C:\\Users\\alicj\\Downloads\\zwolnienie1_signed.pdf",public_key_path="C:\\Users\\alicj\\Downloads\\public_key.pem")