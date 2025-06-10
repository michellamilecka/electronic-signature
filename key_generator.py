import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import psutil
import os

## \brief Generuje losowe bajty z biblioteki Crypto.Random.
#  \param n Liczba bajtów do wygenerowania.
#  \return Wygenerowane losowe bajty.
def random_bytes(n):
    return get_random_bytes(n)


## \brief Wyszukuje podłączone do komputera pendrive'y na podstawie dostępnych partycji.
#
# Funkcja przeszukuje wszystkie zamontowane partycje w systemie i identyfikuje te,
# które są oznaczone jako „removable” (czyli urządzenia wymienne - np. pendrive'y).

# \return Ścieżka urządzenia do jedynego wykrytego pendrive'a (np. '/dev/disk2' lub 'E:\\'),
# liczba 2 w przypadku wykrycia wielu urządzeń, lub None jeśli nie znaleziono żadnego.
def find_usb_drive():
    usb_drives = []

    for partition in psutil.disk_partitions():
        
        if 'removable' in partition.opts:
            usb_drives.append(partition.device) 
        
    if len(usb_drives) == 1:
        return usb_drives[0]
    elif len(usb_drives) > 1:
        #print("Wykryto więcej niż jeden pendrive. Proszę pozostawić pendrive posiadający klucz prywatny i odłączyć pozostałe.")
        return 2
    
    return None

## \brief Generuje parę kluczy RSA (publiczny i prywatny) o długości 4096 bitów.
#  Generujemy klucze RSA prywatny i publiczny o długości 4096 bitów z użyciem funkcji random_bytes, która zapewnia, że klucze są losowe.
#  Eksportuje klucz publiczny i prywatny.
#  Zapisuje klucz publiczny do pliku 'public_key.pem'.
#  \return Wygenerowane klucze: publiczny i prywatny.
def generate_public_private_RSA_keys():
    key = RSA.generate(4096, randfunc=random_bytes)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key)
    return private_key, public_key

## \brief Szyfruje klucz prywatny za pomocą podanego PIN-u przez użytkownika oraz algorytmu AES.
#   Kod PIN podany przez użytkownika jest zamieniony na bajty.
#   Tworzy klucz AES poprzez hashowanie tego PIN-u za pomocą SHA-256, zwraca 256 bitów.
#   Tworzy obiekt do szyfrowania AES w trybie Cipher Block Chaining.
#   Tworzy wektor inicjujący, który jest potrzebnt do szyfrowania.
#   Szyfruje klucz prywatny, dbając o to, żeby dane miały długość wielokrotności rozmiaru bloku AES.
#   Sprawdza czy jest podlaczony pendrive.
#   Zapisuje zaszyfrowany klucz prywatny do pliku 'private_key_encrypted.pem' na pendrive.
#  \param private_key    Klucz prywatny do zaszyfrowania.
#  \param pin Podany przez użytkownika 4-cyfrowy kod PIN.
def private_key_encryption(private_key, pin):
    usb_path = find_usb_drive()
    
    if usb_path == 2:
        messagebox.showerror("Błąd", "Wykryto więcej niż jeden pendrive. Podłącz tylko ten, na którym chcesz zapisać klucz prywatny.")
        return False
    elif usb_path is None:
        messagebox.showerror("Błąd", "Nie znaleziono pendrive'a. Podłącz urządzenie i spróbuj ponownie.")
        return False
    pin_encoded = pin.encode('utf-8')
    key_aes = SHA256.new(pin_encoded).digest()[:32]
    aes_encoding = AES.new(key_aes, AES.MODE_CBC)
    initialization_vector = aes_encoding.iv
    encrypted_private_key = aes_encoding.encrypt(pad(private_key, AES.block_size))
    

    file_path = os.path.join(usb_path, "private_key_encrypted.pem")
    with open(file_path, "wb") as private_key_encrypted_file:
        private_key_encrypted_file.write(initialization_vector + encrypted_private_key)

    return True

## \brief Reaguje na kliknięcie przycisku generowania kluczy.
#  Zapewnia, że PIN jest 4 cyforwy, generuje klucze RSA oraz szyfruje klucz prywatny za pomocą wprowadzonego PIN-u.
#  Informuje użytkownika o aktualnym stanie pracy (szyforwanie kluczy, sukces, błąd).
def on_generate_keys():
    pin = pin_box.get()
    if len(pin) != 4 or not pin.isdigit():
        messagebox.showerror("Error", "PIN musi składać się z dokładnie 4 cyfr.")
        return
    status_label.config(text="Trwa szyfrowanie klucza prywatnego...")
    root.update_idletasks()
    private_key, public_key = generate_public_private_RSA_keys()
    success=private_key_encryption(private_key, pin)
    if success:
        messagebox.showinfo("Sukces", "Klucz prywatny został zaszyfrowany i zapisany na pendrive.")
        status_label.config(text="")
        pin_box.delete(0, tk.END)
    else:
        status_label.config(text="")

## \brief Tworzy główne okno aplikacji.

root = tk.Tk()
root.title("Generator kluczy RSA")
root.geometry("400x300")
root.configure(bg='#9264d1')

## \brief Tekst informujący użytkownika jak ma wyglądać PIN.
pin_text = tk.Label(root, text="Wprowadź PIN (4 cyfry):", bg='#c5afe3', font=('Verdana', 10))
pin_text.pack(pady=50)

## \brief Pole do wprowadzenia PIN-u z ukrywaniem znaków.
pin_box = tk.Entry(root, show="*")
pin_box.pack(pady=5)

## \brief Przycisk do generowania kluczy RSA.
button_to_generate_keys = tk.Button(root, text="Wygeneruj klucze", command=on_generate_keys, bg='#c5afe3', font=('Verdana', 10))
button_to_generate_keys.pack(pady=20)
## \brief Etykieta informacyjna wyświetlająca tymczasowe komunikaty dla użytkownika (informowanie o trwającym szyfrowaniu klucza prywatnego).
status_label = tk.Label(root, text="", bg='#9264d1', fg='white', font=('Verdana', 9))
status_label.pack(pady=5)

root.mainloop()
