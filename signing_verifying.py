import psutil
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Signature import pkcs1_15
import tkinter as tk
from tkinter import filedialog, messagebox

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

# GUI

root = tk.Tk()
root.title("Podpisywanie i Weryfikacja plików PDF")
root.geometry("400x300")
root.configure(bg="#9264d1")


def clear_window():
    for widget in root.winfo_children():
        widget.destroy()


def show_main_menu():
    clear_window()
    tk.Label(root, text="Wybierz opcję:", bg="#c5afe3", font=("Verdana", 12)).pack(pady=40)

    tk.Button(root, text="Podpisz PDF", command=show_sign_screen, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)
    tk.Button(root, text="Zweryfikuj PDF", command=verify_pdf_screen, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)


def show_sign_screen():
    clear_window()
    tk.Label(root, text="Wprowadź PIN (4 cyfry):", bg="#c5afe3", font=("Verdana", 10)).pack(pady=30)

    pin_entry = tk.Entry(root, show="*", font=("Verdana", 10))
    pin_entry.pack(pady=5)

    def handle_sign():

        pin = pin_entry.get()

        if not pin.isdigit() or len(pin) != 4:
            messagebox.showerror("Błąd", "PIN musi mieć dokładnie 4 cyfry.")
            return

        file_path = filedialog.askopenfilename(title="Wybierz plik PDF", filetypes=[("PDF files", "*.pdf")])

        if not file_path:
            return
        
        usb_drive = find_usb_drive()

        if not usb_drive:
            messagebox.showerror("Błąd", "Nie wykryto zewnętrznego nośnika danych - pendrive.")
            return
        
        private_key_path = find_private_key_path(usb_drive)

        if not private_key_path:
            messagebox.showerror("Błąd", "Nie znaleziono klucza prywatnego na pendrive.")
            return

        private_key = decrypt_private_key(private_key_path, pin)

        if not private_key:
            messagebox.showerror("Błąd", "Wprowadzony PIN jest nieprawidłowy, spróbuj jeszcze raz.")
            return

        sign_file(file_path, private_key)
        show_main_menu()

    tk.Button(root, text="Podpisz", command=handle_sign, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)
    tk.Button(root, text="Wróć", command=show_main_menu, bg="#c5afe3", font=("Verdana", 10)).pack(pady=5)


def verify_pdf_screen():
    clear_window()

    selected_pdf_path = tk.StringVar()
    selected_public_key_path = tk.StringVar()

    def pick_pdf():

        path = filedialog.askopenfilename(title="Wybierz plik PDF", filetypes=[("PDF files", "*.pdf")])

        if path:
            selected_pdf_path.set(path)
            pdf_label.config(text=os.path.basename(path))

    def pick_public_key():

        path = filedialog.askopenfilename(title="Wybierz klucz publiczny", filetypes=[("PEM files", "*.pem")])

        if path:
            selected_public_key_path.set(path)

    def conduct_verification():

        pdf = selected_pdf_path.get()
        public_key = selected_public_key_path.get()

        if not pdf or not public_key:
            messagebox.showerror("Błąd", "Najpierw wybierz plik PDF oraz klucz publiczny.")
            return
        
        is_verified = verify_signature(pdf, public_key)

        if is_verified:
            messagebox.showinfo("Weryfikacja", "Weryfkiacja pomyślna - Podpis jest prawidłowy.")
        else:
            messagebox.showerror("Weryfikacja", "Weryfikacja niepomyślna - Podpis jest nieprawidłowy.")

        show_main_menu()

    tk.Label(root, text="Weryfikacja podpisu PDF", bg="#c5afe3", font=("Verdana", 12)).pack(pady=20)

    pdf_label = tk.Label(root, text="", bg="#9264d1", fg="white", font=("Verdana", 9))
    pdf_label.pack()

    tk.Button(root, text="Wybierz PDF", command=pick_pdf, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)
    tk.Button(root, text="Wybierz klucz publiczny", command=pick_public_key, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)
    tk.Button(root, text="Weryfikuj", command=conduct_verification, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)
    tk.Button(root, text="Wróć", command=show_main_menu, bg="#c5afe3", font=("Verdana", 10)).pack()


show_main_menu()
root.mainloop()