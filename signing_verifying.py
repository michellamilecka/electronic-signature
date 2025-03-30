import psutil
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

privateFileName = "private_key_encrypted.pem"

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

    with open(private_key_path, "rb") as f:
        encrypted_data = f.read()

    initialization_vector = encrypted_data[:16]
    encrypted_private_key = encrypted_data[16:]

    pin_encoded = pin.encode('utf-8')
    key_aes = SHA256.new(pin_encoded).digest()[:32]

    cipher = AES.new(key_aes, AES.MODE_CBC, iv=initialization_vector)
    decrypted_private_key = unpad(cipher.decrypt(encrypted_private_key), AES.block_size)

    private_key = RSA.import_key(decrypted_private_key)
    
    return private_key

