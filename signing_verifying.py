import psutil
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Signature import pkcs1_15
import tkinter as tk
from tkinter import filedialog, messagebox
## \brief Nazwa pliku z zaszyfrowanym kluczem prywatnym RSA.
privateFileName = "private_key_encrypted.pem"
## \brief Długość podpisu cyfrowego (w bajtach).
signatureLength = 512


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

# szukanie pelnej sciezki do klucza prywatnego znajdujacego sie na pendrive

## \brief Wyszukuje pełną ścieżkę do pliku z kluczem prywatnym znajdującego się na pendrive.
#
# Funkcja buduje ścieżkę do pliku na podstawie ścieżki do podłączonego pendrive'a
# oraz nazwy pliku klucza prywatnego, którego nazwa wynika z założenia programu i 
# jest przechowywana w zmiennej globalnej wykorzystywanej w funkcji.
#
# \param usb_drive Ścieżka do zamontowanego pendrive'a (np. 'E:\\').
# \return Pełna ścieżka do pliku z kluczem prywatnym - jeśli istnieje, None jeśli nie znaleziono klucza prywatnego na pendrive.

def find_private_key_path(usb_drive):

    if usb_drive:
     
        private_key_path = os.path.join(usb_drive, privateFileName)

        if os.path.exists(private_key_path):
            return private_key_path
        else:
            return None
    else:
        return None
    

## \brief Odszyfrowuje wcześniej zaszyfrowany klucz prywatny RSA przy użyciu podanego PIN-u i algorytmu AES.
#
# Odczytuje dane z pliku z zaszyfrowanym kluczem prywatnym. Pierwsze 16 bajtów danych to wektor inicjujący (IV),
# pozostałe bajty to zaszyfrowany klucz RSA. PIN wprowadzony przez użytkownika jest konwertowany na bajty,
# a następnie hashowany algorytmem SHA-256, aby wygenerować klucz AES o długości 256 bitów.
# Funkcja tworzy obiekt AES w trybie CBC (Cipher Block Chaining) z użyciem odczytanego IV,
# następnie odszyfrowuje dane i usuwa padding, który został wcześniej dodany.
#
# \param private_key_path Ścieżka do pliku z zaszyfrowanym kluczem prywatnym.
# \param pin Czterocyfrowy kod PIN podany przez użytkownika.
# \return Odszyfrowany klucz prywatny RSA lub None, jeśli odszyfrowanie się nie powiodło.

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
        #print("nieprawidłowy pin")
        return None


## \brief Podpisuje cyfrowo wskazany plik PDF za pomocą klucza prywatnego.
#
# Funkcja odczytuje zawartość pliku PDF i oblicza jego skrót SHA-256. Następnie tworzy podpis cyfrowy
# przy użyciu klucza prywatnego RSA oraz algorytmu podpisu PKCS#1 v1.5. Podpis zostaje dołączony na końcu
# oryginalnego pliku. Po dołączeniu podpisu plik zostaje przemianowany — do nazwy pliku dodawany jest sufiks "_signed".
# Oryginalny plik zostaje zastąpiony podpisanym.
#
# \param file_path Ścieżka do pliku PDF, który ma zostać podpisany.
# \param decrypted_private_key Odszyfrowany klucz prywatny RSA wykorzystywany do generowania podpisu.

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


## \brief Weryfikuje podpis cyfrowy znajdujący się na końcu pliku PDF przy użyciu klucza publicznego RSA.
#
# Funkcja odczytuje zawartość pliku PDF: wydziela końcowe 512 bajtów jako podpis, a pozostałe dane traktuje jako treść dokumentu.
# Na podstawie treści tworzy skrót SHA-256, a następnie weryfikuje podpis przy użyciu klucza publicznego RSA i algorytmu PKCS#1 v1.5.
#
# \param file_path Ścieżka do podpisanego pliku PDF.
# \param public_key_path Ścieżka do pliku zawierającego klucz publiczny RSA w formacie PEM.
# \return True, jeśli podpis jest prawidłowy, False w przeciwnym razie.

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
        print("Weryfikacja pomyslna")
        return True
    except (ValueError, TypeError):
        print("Weryfikacja niepomyslna")
        return False


## \brief Tworzy główne okno aplikacji.
root = tk.Tk()
root.title("Podpisywanie i Weryfikacja plików PDF")
root.geometry("400x300")
root.configure(bg="#9264d1")


## \brief Czyści wszystkie elementy z głównego okna aplikacji.
#
# Funkcja usuwa wszystkie widżety potomne z głównego okna `root`, co umożliwia
# przeładowanie interfejsu użytkownika (np. przed załadowaniem innego ekranu).
def clear_window():
    for widget in root.winfo_children():
        widget.destroy()


## \brief Wyświetla główne menu aplikacji z opcjami podpisywania i weryfikacji PDF.
#
# Funkcja czyści aktualne okno i tworzy interfejs zawierający przyciski umożliwiające
# użytkownikowi wybór jednej z dostępnych opcji: podpisania pliku PDF lub weryfikacji podpisu.

def show_main_menu():
    clear_window()
    tk.Label(root, text="Wybierz opcję:", bg="#c5afe3", font=("Verdana", 12)).pack(pady=40)

    tk.Button(root, text="Podpisz PDF", command=show_sign_screen, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)
    tk.Button(root, text="Zweryfikuj PDF", command=verify_pdf_screen, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)


## \brief Wyświetla ekran umożliwiający podpisanie pliku PDF przy użyciu klucza prywatnego z pendrive'a.
#
# Funkcja tworzy graficzny interfejs, w którym użytkownik wprowadza PIN, a następnie wybiera plik PDF do podpisania.
# System sprawdza, czy podłączony jest dokładnie jeden pendrive z kluczem prywatnym, odszyfrowuje klucz przy użyciu PIN-u,
# a następnie podpisuje wskazany plik. W przypadku błędów (brak pendrive'a, więcej niż jeden pendrive podłączony do komputera,
# nieprawidłowy PIN, brak klucza prywatnego na pendrive) użytkownik otrzymuje odpowiedni komunikat.
#
# Po zakończeniu operacji podpisywania pliku, ekran główny zostaje przywrócony.

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
        elif usb_drive == 2:
            messagebox.showerror("Błąd", "Wykryto więcej niż jeden pendrive. Proszę pozostawić podłączony pendrive posiadający klucz prywatny i odłączyć pozostałe.")
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
        messagebox.showinfo("Sukces", "Plik został podpisany pomyślnie.")
        show_main_menu()

    tk.Button(root, text="Podpisz", command=handle_sign, bg="#c5afe3", font=("Verdana", 10)).pack(pady=10)
    tk.Button(root, text="Wróć", command=show_main_menu, bg="#c5afe3", font=("Verdana", 10)).pack(pady=5)


## \brief Wyświetla ekran umożliwiający weryfikację podpisu cyfrowego w pliku PDF.
#
# Funkcja generuje graficzny interfejs, w którym użytkownik może wybrać podpisany plik PDF
# oraz odpowiadający mu klucz publiczny w formacie PEM. Po zatwierdzeniu dane są przekazywane
# do funkcji weryfikującej podpis cyfrowy. Wynik operacji prezentowany jest użytkownikowi
# w formie komunikatu informacyjnego. Po zakończeniu operacji użytkownik wraca do głównego menu aplikacji.

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
            messagebox.showinfo("Weryfikacja", "Weryfikacja pomyślna - Podpis jest prawidłowy.")
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