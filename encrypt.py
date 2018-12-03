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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric

keySize = 32
ivSize = 16
blockSize = 128

#Encrypt function
def MyEncrypt(m,key):
    if(len(key)<keySize):
        print("Key is < 32 byte")
        return
    
    
    backend = default_backend() #use default backend
    iv = os.urandom(ivSize) #generate 16 byte iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend) #cipher in AES and CBC mode
    encryptor = cipher.encryptor() # make an encryptor
    m=base64.b64encode(m)#encode the message using base64 to encrypt
    padder = padding.PKCS7(blockSize).padder()#create a padder
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
    unpad = padding.PKCS7(blockSize).unpadder()#make an unpadder
    data = unpad.update(m) #unpad the decrypted data
    data += unpad.finalize() #Finalize the current context and return the rest of the data.
    m=base64.b64decode(data) #decode the data using base64
    return m

#Encrypt a file function
def MyfileEncrypt(filepath):#filepath to the file
    key = os.urandom(keySize) #make a 32 byte key

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

