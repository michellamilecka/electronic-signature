import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

##sprawdzanie czy na pendrive istnieje juz zaszyforwany klucz prywatny, jesli tak to komunikat

def random_bytes(n):
    return get_random_bytes(n)


def generate_public_private_RSA_keys():
    key = RSA.generate(4096, randfunc=random_bytes)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key)
    return private_key, public_key


def private_key_encryption(private_key, pin):
    pin_encoded = pin.encode('utf-8')
    key_aes = SHA256.new(pin_encoded).digest()[:32]
    aes_encoding = AES.new(key_aes, AES.MODE_CBC)
    initialization_vector = aes_encoding.iv
    encrypted_private_key = aes_encoding.encrypt(pad(private_key, AES.block_size))
    with open("private_key_encrypted.pem", "wb") as private_key_encrypted_file:
        private_key_encrypted_file.write(initialization_vector + encrypted_private_key)


def on_generate_keys():
    pin = pin_box.get()

    if len(pin) != 4 or not pin.isdigit():
        messagebox.showerror("Error", "PIN musi składać się z dokładnie 4 cyfr.")
        return
    private_key, public_key = generate_public_private_RSA_keys()
    private_key_encryption(private_key, pin)
    messagebox.showinfo("Sukces", "Klucz prywatny został zaszyfrowany.")


root = tk.Tk()
root.title("Generator kluczy RSA")
root.geometry("400x300")


root.configure(bg='#9264d1')
pin_text = tk.Label(root, text="Wprowadź PIN (4 cyfry):",bg='#c5afe3',font=('Verdana', 10))
pin_text.pack(pady=50)

pin_box = tk.Entry(root, show="*")
pin_box.pack(pady=5)

button_to_generate_keys = tk.Button(root, text="Wygeneruj klucze", command=on_generate_keys,bg='#c5afe3',  font=('Verdana', 10))
button_to_generate_keys.pack(pady=20)

root.mainloop()
