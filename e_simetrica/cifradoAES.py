from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox

# Función para derivar la clave a partir de la contraseña
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Función para cifrar un archivo
def encrypt_file(input_file: str, output_file: str, password: str) -> None:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)

# Función para descifrar un archivo
def decrypt_file(input_file: str, output_file: str, password: str) -> None:
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Funciones para manejar los botones de la interfaz gráfica
def encrypt():
    input_file = filedialog.askopenfilename(title="Seleccionar archivo a cifrar")
    output_file = filedialog.asksaveasfilename(title="Guardar archivo cifrado")
    password = password_entry.get()
    
    try:
        encrypt_file(input_file, output_file, password)
        messagebox.showinfo("Éxito", "El archivo ha sido cifrado exitosamente.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar el archivo: {e}")

def decrypt():
    input_file = filedialog.askopenfilename(title="Seleccionar archivo a descifrar")
    output_file = filedialog.asksaveasfilename(title="Guardar archivo descifrado")
    password = password_entry.get()
    
    try:
        decrypt_file(input_file, output_file, password)
        messagebox.showinfo("Éxito", "El archivo ha sido descifrado exitosamente.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar el archivo: {e}")

# Configuración de la interfaz gráfica
app = tk.Tk()
app.title("Cifrado AES")

frame = tk.Frame(app)
frame.pack(padx=10, pady=10)

password_label = tk.Label(frame, text="Contraseña:")
password_label.grid(row=0, column=0, pady=5)

password_entry = tk.Entry(frame, show="*")
password_entry.grid(row=0, column=1, pady=5)

encrypt_button = tk.Button(frame, text="Cifrar archivo", command=encrypt)
encrypt_button.grid(row=1, column=0, pady=10)

decrypt_button = tk.Button(frame, text="Descifrar archivo", command=decrypt)
decrypt_button.grid(row=1, column=1, pady=10)

app.mainloop()

