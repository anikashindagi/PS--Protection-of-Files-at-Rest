from tkinter import *
from tkinter import filedialog
import base64
import os

root = Tk()
root.geometry("450x550")
root.configure(bg="white")
root.title("File Encryptor")

Tops = Frame(root, width=1500, relief=SUNKEN)
Tops.pack(side=TOP)

f1 = Frame(root, width=800, relief=SUNKEN)
f1.pack(side=LEFT)

IbInfo = Label(Tops, font=("calibri", 30, "bold"),
               text="FILE ENCRYPTOR\n Welcome!",
               fg="black", bd=10, anchor='w')
IbInfo.grid(row=0, column=0)

msgg = StringVar()
key = StringVar()  
mode = StringVar()
result = StringVar()
password = StringVar()

Ibkey = Label(f1, font=("arial", 10, 'bold'),
              text="Key:", bd=16, anchor='center')
Ibkey.grid(row=2, column=0)

txtkey = Entry(f1, font=("arial", 12, 'bold'),
               textvariable=key, bd=10, insertwidth=4,
               bg="lavender", justify="center")
txtkey.grid(row=2, column=1)

Ibresult = Label(f1, font=("arial", 10, 'bold'),
                 text="Status:", bd=16, anchor='center')
Ibresult.grid(row=5, column=0)

txtresult = Entry(f1, font=("arial", 12, 'bold'),
                  textvariable=result, bd=8, insertwidth=4,
                  bg="lavender", justify="center")
txtresult.grid(row=5, column=1)

file_to_encrypt = ""
file_to_decrypt = ""

desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

def file_encrypt(key):
    global file_to_encrypt
    if file_to_encrypt == "":
        result.set("No file selected for encryption.")
        return
    
    try:
        with open(file_to_encrypt, 'rb') as f:
            data = f.read()
        
        encodee = []
        for i in range(len(data)):
            key_c = key[i % len(key)]
            enc_c = chr((data[i] + ord(key_c)) % 256)
            encodee.append(enc_c)
        
        encoded_data = base64.urlsafe_b64encode("".join(encodee).encode()).decode()
        
        encrypted_file_path = os.path.join(desktop_path, os.path.basename(file_to_encrypt) + ".enc")
        with open(encrypted_file_path, 'w') as f:
            f.write(encoded_data)
        
        result.set(f"File encrypted successfully. Saved to {encrypted_file_path}")
        
    except Exception as e:
        result.set(f"Encryption error: {str(e)}")

def file_decrypt(key):
    global file_to_decrypt
    if file_to_decrypt == "":
        result.set("No file selected for decryption.")
        return
    
    try:
        with open(file_to_decrypt, 'r') as f:
            encoded_data = f.read()
        
        decodee = []
        decoded_data = base64.urlsafe_b64decode(encoded_data).decode()
        
        for i in range(len(decoded_data)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(decoded_data[i]) - ord(key_c)) % 256)
            decodee.append(dec_c)
        
        decrypted_file_path = os.path.join(desktop_path, os.path.basename(file_to_decrypt) + ".dec")
        with open(decrypted_file_path, 'wb') as f:
            f.write("".join(decodee).encode())
        
        result.set(f"File decrypted successfully. Saved to {decrypted_file_path}")
        
    except Exception as e:
        result.set(f"Decryption error: {str(e)}")

def select_file_to_encrypt():
    global file_to_encrypt
    file_to_encrypt = filedialog.askopenfilename()
    result.set(f"Selected file for encryption: {file_to_encrypt}")

def select_file_to_decrypt():
    global file_to_decrypt
    file_to_decrypt = filedialog.askopenfilename()
    result.set(f"Selected file for decryption: {file_to_decrypt}")

def exitt():
    root.destroy()

def reset():
    global file_to_encrypt, file_to_decrypt
    file_to_encrypt = ""  
    file_to_decrypt = ""
    result.set("Loading---")
    key.set("") 
    password.set("")

btn_select_encrypt = Button(f1, padx=5, pady=4, bd=16, fg="black",
                            font=("arial", 10, 'bold'), width=15,
                            text="Select File to Encrypt", bg="light green",
                            command=select_file_to_encrypt)
btn_select_encrypt.grid(row=7, column=0)

btn_encrypt = Button(f1, padx=5, pady=4, bd=16, fg="black",
                     font=("arial", 10, 'bold'), width=15,
                     text="Encrypt File", bg="light green",
                     command=lambda: file_encrypt(key.get()))
btn_encrypt.grid(row=7, column=1)

btn_select_decrypt = Button(f1, padx=5, pady=4, bd=16, fg="black",
                            font=("arial", 10, 'bold'), width=15,
                            text="Select File to Decrypt", bg="light yellow",
                            command=select_file_to_decrypt)
btn_select_decrypt.grid(row=8, column=0)

btn_decrypt = Button(f1, padx=5, pady=4, bd=16, fg="black",
                     font=("arial", 10, 'bold'), width=15,
                     text="Decrypt File", bg="light yellow",
                     command=lambda: file_decrypt(key.get()))
btn_decrypt.grid(row=8, column=1)

BTNRESET = Button(f1, padx=5, pady=4, bd=16, fg="black",
                  font=("arial", 10, 'bold'), width=10,
                  text="RESET", bg="light yellow",
                  command=reset)
BTNRESET.grid(row=9, column=0)

btnexit = Button(f1, padx=5, pady=4, bd=16, fg="white",
                 font=("arial", 10, 'bold'), width=10,
                 text="EXIT", bg="black",
                 command=exitt)
btnexit.grid(row=9, column=1)

root.mainloop()
