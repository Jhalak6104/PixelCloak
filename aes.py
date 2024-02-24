from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt(plaintext, key):
    # Create an AES cipher object with the key and AES.MODE_ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Pad the plaintext and encrypt it
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    #return ciphertext
    filenameforcipher="cipher.txt"
    filegenerator(filenameforcipher,ciphertext)
    #print(ciphertext)
 
def decrypt(ciphertext, key):
    # Create an AES cipher object with the key and AES.MODE_ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Decrypt the ciphertext and remove the padding

    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print(decrypted_data.decode())
    #return decrypted_data
 
def filegenerator(filename,text):
    with open(filename,"wb") as f:
        #f.write(str(text,'UTF-8'))
        #f.write(text.decode())
        f.write(text)


def menu():
    print("")
    print("")
    print("1. ENCYPTION USING AES ALGORITHM")
    print("2. DECRYPTION USING AES ALGORITHM")
    print("")
    print("")
    n=int(input())
    if n==1:
        #encrypted_data = encrypt(plaintext, key)
        #print("Encrypted data:", encrypted_data)
        key = get_random_bytes(32)  # Generating keys/passphrase
        filenameforkey="keyfile.txt"
        filegenerator(filenameforkey, key)
        #print(key)
        with open("keyfile.txt","rb") as f:
            key=f.read()
        
        plaintext = bytes(input("ENTER YOUR TEXT"),'utf-8')

        encrypt(plaintext, key)

    elif n==2:
        #decrypted_data = decrypt(encrypted_data, key)
        #print("Decrypted data:", decrypted_data)
        with open("after.txt","rb") as f:
            encrypted_data=f.read()
            
        with open("keyfile.txt","rb") as f:
            key=f.read()
        #print(encrypted_data)
        
        #print(key)  
        decrypt(encrypted_data, key)


menu()
