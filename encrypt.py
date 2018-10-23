#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Oct  8 18:14:05 2018

@author: Quang Le & Sean Dinh
"""
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac



#Encrypt function
def MyEncrypt(m,key):
    if(len(key)<32):
        print("Key is < 32 byte")
        return
    
    
    backend = default_backend() #use default backend
    iv = os.urandom(16) #generate 16 byte iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend) #cipher in AES and CBC mode
    encryptor = cipher.encryptor() # make an encryptor
    m=base64.b64encode(m)#encode the message using base64 to encrypt
    padder = padding.PKCS7(128).padder()#create a padder
    paddata = padder.update(m) # pad the message by appending N-1 bytes with the value of 0 and a last byte with the value of chr(N)
    paddata += padder.finalize() #Finalize the current context and return the rest of the data.
    
    m = encryptor.update(paddata) + encryptor.finalize() #finish the operation and obtain the remainder of the data.
    return (m,iv) #return encrypted message and iv
    

#Decrypt function
def MyDecrypt(m,key,iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()# make a decryptor
    m=decryptor.update(m) + decryptor.finalize() #decrypt the m
    unpad = padding.PKCS7(128).unpadder()#make an unpadder
    data = unpad.update(m) #unpad the decrypted data
    data += unpad.finalize() #Finalize the current context and return the rest of the data.
    m=base64.b64decode(data) #decode the data using base64
    return m

#Encrypt a file function
def MyfileEncrypt(filepath):#filepath to the file
    key = os.urandom(32) #make a 32 byte key

    file = open(filepath,"rb")#open the file to encrypt
    m =file.read()# read the file
    
    (encr,iv) = MyEncrypt(m,key)#set encrypt to encrypted data, and iv to returned iv
    name,ext=os.path.splitext(filepath) #split to get the name and file extension
    out_file = open(filepath , "wb") #make a new file to write in binary
    out_file.write(encr) #write to the new file
    out_file.close() #close the file
    return (encr,iv,key,ext)#return encrypted m, iv, key and extension

#Decrypt a file function
def MyfileDecrypt(filepath,key,iv):
    file = open(filepath,"rb") #open a file to decrypt
    content=file.read() #read the file
    content = MyDecrypt(content,key,iv) #get the decrypt data
    out_file1 = open(filepath, "wb") #make a new file
    out_file1.write(content ) #write a new file
    out_file1.close() #close that file

def MyencryptMAC(message, EncKey, HMACKey):
    m,iv= MyEncrypt(message,EncKey) #get the m and iv from encrypt
    
    h= hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #make an hmac
    h.update(m) #create the hash 
    return (m,iv,h.finalize()) #return encrypted message and iv


def MydecryptMAC(message,EncKey,HMACKey,iv,tag):
    try:
        h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
        h.update(message)
        h.verify(tag)
        m=MyDecrypt(message,EncKey,iv)
        return m
    except:
        print("Invalid tag")
    
# =============================================================================
# def MyfileEncryptMAC(filepath):
#     Hkey=os.urandom(32)
#     m,iv,key,ext=MyfileEncrypt(filepath)
#     h= hmac.HMAC(Hkey, hashes.SHA256(), backend=default_backend())
#     h.update(m)
#     return (m,iv,h.finalize(),key,Hkey,ext)
# =============================================================================
    
def MyfileEncryptMAC(filepath):
    key = os.urandom(32) #make a 32 byte key
    Hkey = os.urandom(32) #make a 32 byte hmac key
    
    file = open(filepath,"rb")#open the file to encrypt
    m =file.read()# read the file
    name,ext=os.path.splitext(filepath) #split to get the name and file extension
    
    (m,iv,tag)= MyencryptMAC(m,key,Hkey)
    out_file = open(filepath , "wb") #make a new file to write in binary
    out_file.write(m) #write to the new file
    out_file.close() #close the file
    return (m,iv,tag,key,Hkey,ext)
    
def MyfileDecryptMAC(filepath,EncKey,HMACKey,iv,tag):
    file = open(filepath,"rb") #open a file to decrypt
    content=file.read() #read the file
    m=MydecryptMAC(content,EncKey,HMACKey,iv,tag)
    out_file1 = open(filepath, "wb") #make a new file
    out_file1.write(m) #write a new file
    out_file1.close() #close that file
    
m=b"test"
key = os.urandom(32)
hkey= os.urandom(32)
message,IV,tag =MyencryptMAC(m,key,hkey)
print(message)
message = MydecryptMAC(message,key,hkey,IV,tag)
print(message)

C,IV,tag,Enckey,HMACKey,ext=MyfileEncryptMAC("test.jpg")
inp=input("Press enter to continue")
MyfileDecryptMAC("test.jpg",Enckey,HMACKey,IV,tag)