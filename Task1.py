import customtkinter as ctk
from tkinter import messagebox

def caesar_cipher_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            ascii_offset = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - ascii_offset + shift_amount) % 26 + ascii_offset)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def caesar_cipher_decrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)

def encrypt_message():
    try:
        message = message_entry.get("1.0", "end").strip()
        shift = int(shift_entry.get())
        encrypted_message = caesar_cipher_encrypt(message, shift)
        result_entry.delete("1.0", "end")
        result_entry.insert("end", encrypted_message)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid integer for the shift value.")

def decrypt_message():
    try:
        message = message_entry.get("1.0", "end").strip()
        shift = int(shift_entry.get())
        decrypted_message = caesar_cipher_decrypt(message, shift)
        result_entry.delete("1.0", "end")
        result_entry.insert("end", decrypted_message)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid integer for the shift value.")

def create_gui():
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")

    global message_entry, shift_entry, result_entry

    root = ctk.CTk()
    root.title("Caesar Cipher")
    root.geometry("500x450")
    root.resizable(False, False)

    title_label = ctk.CTkLabel(root, text="Caesar Cipher", font=("Arial", 20))
    title_label.pack(pady=10)

    frame = ctk.CTkFrame(root)
    frame.pack(pady=10, padx=10, fill="both", expand=True)

    message_label = ctk.CTkLabel(frame, text="Message:")
    message_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    message_entry = ctk.CTkTextbox(frame, height=100, width=320)
    message_entry.grid(row=0, column=1, padx=10, pady=10)

    shift_label = ctk.CTkLabel(frame, text="Shift:")
    shift_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
    shift_entry = ctk.CTkEntry(frame)
    shift_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

    result_label = ctk.CTkLabel(frame, text="Result:")
    result_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
    result_entry = ctk.CTkTextbox(frame, height=100, width=320)
    result_entry.grid(row=2, column=1, padx=10, pady=10)

    button_frame = ctk.CTkFrame(root)
    button_frame.pack(pady=10)

    encrypt_button = ctk.CTkButton(button_frame, text="Encrypt", command=encrypt_message)
    encrypt_button.grid(row=0, column=0, padx=10, pady=10)
    
    decrypt_button = ctk.CTkButton(button_frame, text="Decrypt", command=decrypt_message)
    decrypt_button.grid(row=0, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
