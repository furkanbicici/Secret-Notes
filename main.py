import tkinter
from tkinter import *
import hashlib
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_encrypt():
    my_one_entry = my_entry.get()
    my_one_text = my_text.get(1.0,END)
    my_one_entry2 = my_entry3.get()

    if len(my_one_entry) == 0 or len(my_one_text) == 0 or len(my_one_entry2) ==0:
        messagebox.showinfo(title="Error", message="Please enter all info")
    else:
        input_encrypt = encode(my_one_entry2, my_one_text)
        with open("secretnotes.txt", mode="a") as my_file:
            my_file.write(my_one_entry + "\n")
            my_file.write(input_encrypt + "\n")
            ("\n")
            my_entry.delete(0, END)
            my_text.delete(1.0, END)
            my_entry3.delete(0, END)

def decrypt_password():
    input_text = my_text.get(1.0, END)
    input_entry = my_entry3.get()

    if len(input_text) == 0 or len(input_text) == 0:
        messagebox.showinfo(title="Error", message="Please Enter All info")
    else:
        try:
            decrypt_pass = decode(input_entry, input_text)
            my_text.delete(1.0, END)
            my_text.insert(1.0, decrypt_pass)
        except:
            messagebox.showinfo(title="Error", message="Please make sure of encrypted info.")
#ui

window = tkinter.Tk()
window.title("Secret Notes")
window.config(pady=20 ,padx=20)


photo = PhotoImage(file="topsecret.png")
photo_label = Label(image=photo)
photo_label.pack()


my_text_label = Label(text="Enter Your Title")
my_text_label.pack()


my_entry = Entry(width=50)
my_entry.pack()


my_label_new = Label(text="Enter Your Secret")
my_label_new.pack()


my_text = Text(width=45, height=18)
my_text.pack()


my_label3 = Label(text="Enter Master Key")
my_label3.pack()


my_entry3 = Entry(width=50)
my_entry3.pack()


my_button1 = Button(text="Save & Encrypt", command=save_encrypt)
my_button1.pack()

def decrypt_button():
    pass

my_button2 = Button(text="Decrypt", command=decrypt_password)
my_button2.pack()

window.mainloop()