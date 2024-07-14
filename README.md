# PS--Protection-of-Files-at-Rest

ENCRYPTOR/DECRYPTOR

Introduction:
A feature-rich GUI that makes file encryption and decryption easier is part of this project. Through the interface, users can choose a file from their system for encryption with ease. Upon selecting a file, the application encrypts it and stores the encrypted version on the user's desktop for convenient accessibility. Furthermore, the GUI offers users the ability to decrypt previously encrypted files, allowing them to recover the original content of the file whenever necessary. The application's user-friendly interface and dual encryption and decryption capabilities make it practical and effective for securely storing critical files.

Explaining the code:

-	Two variables- ‘file_to_encrypt’ and ‘file_to_decrypt’ are used to save the file input given by the user. The module ‘os’ is imported to save the files inputted into a particular location. 
-	‘Encryption key’ is accepted from the user to make sure that every encrypted file is unique and the code is only known to the user. 
-	The file_encrypt function uses a straightforward substitution cypher in conjunction with Base64 encoding to encrypt the content of the chosen file after reading it in binary mode. The ASCII value of a corresponding character from the key is shifted by each byte in the file; this process is done cyclically. After that, the encrypted data is Base64 encoded and saved to the desktop as a new file.
-	The reverse process is carried out by the file_decrypt function, which reads the encrypted file, Base64 decodes it, and then uses the same key to decrypt the information. The decrypted data is then saved as a new file on the desktop.

Demo of the Application:
Image: (https://github.com/user-attachments/assets/0977c786-4804-43d1-8d35-5ee5ae524a6b)


 




