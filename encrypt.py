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
from cryptography.hazmat.backends import default_backend
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

def MyencryptMAC(message, EncKey, HMACKey):
    m,iv= MyEncrypt(message,EncKey) #get the m and iv from encrypt
    h= hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #make an hmac
    h.update(m) #create the hash 
    return (m,iv,h.finalize()) #return encrypted message and iv


def MydecryptMAC(message,EncKey,HMACKey,iv,tag):
    try:
        h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #make an hmac
        h.update(message) #recalculate the message
        h.verify(tag) #compare to the tag
        m=MyDecrypt(message,EncKey,iv) #Decrypt the message
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
    key = os.urandom(keySize) #make a 32 byte key
    Hkey = os.urandom(keySize) #make a 32 byte hmac key
    
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
    m=MydecryptMAC(content,EncKey,HMACKey,iv,tag) #decrypt the file
    out_file1 = open(filepath, "wb") #make a new file
    out_file1.write(m) #write a new file
    out_file1.close() #close that file

pubKey= 'PublicKey.pem'
priKey= 'PrivateKey.pem'

def RSAKey(pubKey,priKey):
    if(os.path.exists(pubKey) and os.path.exists(pubKey)):
        print("Key files exist")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537,\
                                               key_size=2048,\
                                               backend=default_backend())
        
        public_key = private_key.public_key()  
    
        pub = public_key.public_bytes(encoding=serialization.Encoding.PEM,\
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo )
        #pub.splitlines()[0]
        
        pri =private_key.private_bytes(encoding=serialization.Encoding.PEM,\
                                       format=serialization.PrivateFormat.TraditionalOpenSSL,\
                                       encryption_algorithm=serialization.NoEncryption())
        #pri.splitlines()[0]
        
        pubFile=open(pubKey,"wb")
        pubFile.write(pub)
        pubFile.close()
        
        
        priFile=open(priKey,"wb")
        priFile.write(pri)
        priFile.close()
        
    
def  MyRSAEncrypt(filepath, RSA_Publickey_filepath):
     (C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC(filepath)
     key = Enckey + HMACKey
     with open(pubKey, "rb") as key_file:
         pub = serialization.load_pem_public_key(key_file.read(),\
                                                          backend=default_backend())
     RSACipher = pub.encrypt(key,\
                                   asymmetric.padding.OAEP(\
                                                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),\
                                                algorithm=hashes.SHA256(),\
                                                label=None))
     
     return RSACipher,C, IV, tag, ext
    

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    with open(priKey, "rb") as key_file:
         private = serialization.load_pem_private_key(key_file.read(),\
                                                          password=None,\
                                                          backend=default_backend())
    key= private.decrypt(RSACipher,\
                             asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),\
                                          algorithm=hashes.SHA256(),\
                                          label=None))
    EncKey=key[:32]
    HMACKey= key[-32:]
    
    m=MydecryptMAC(C,EncKey,HMACKey,IV,tag)
    out_file1 = open("Decyptedfile", "wb") #make a new file
    out_file1.write(m) #write a new file
    out_file1.close() #close that file
    
    
    


#C,IV,tag,Enckey,HMACKey,ext=MyfileEncryptMAC("test.jpg")
#inp=input("Press enter to continue")
#RSAKey(pubKey,priKey)

RSACipher,C, IV, tag, ext= MyRSAEncrypt("test.jpg",pubKey)
MyRSADecrypt(RSACipher, C, IV, tag, ext, priKey)
