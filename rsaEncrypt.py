#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 25 17:56:41 2018

@author: QuangLe
"""
import os
import macEncrypt as mEnc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

pubKey= '/Users/QuangLe/Desktop/testransom/PublicKeyTB378.pem'
priKey= '/Users/QuangLe/Desktop/testransom/PrivateKeyTB378.pem'
def RSAKey(pubKey,priKey):
    #check if files exist
    if(os.path.exists(pubKey) and os.path.exists(pubKey)):
        print("Key files exist")
    else:
        #generate private key
        private_key = rsa.generate_private_key(public_exponent=65537,\
                                               key_size=2048,\
                                               backend=default_backend())
        #generate public key
        public_key = private_key.public_key()  
    
        #serialize private key
        pri =private_key.private_bytes(encoding=serialization.Encoding.PEM,\
                                       format=serialization.PrivateFormat.TraditionalOpenSSL,\
                                       encryption_algorithm=serialization.NoEncryption())
        #pri.splitlines()[0]
        
        #serialize public key
        pub = public_key.public_bytes(encoding=serialization.Encoding.PEM,\
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo )
        #pub.splitlines()[0]
        
        #create private pem file
        priFile=open(priKey,"wb")
        priFile.write(pri)
        priFile.close()
        
        #create public pem dile
        pubFile=open(pubKey,"wb")
        pubFile.write(pub)
        pubFile.close()
        
    
def  MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    #encrypt the file first
     (C, IV, tag, Enckey, HMACKey, ext)= mEnc.MyfileEncryptMAC(filepath)
     
     #concatenate encrypt key and hmac key
     key = Enckey + HMACKey
     
     #open the public key pem file
     with open(RSA_Publickey_filepath, "rb") as key_file:
         pub = serialization.load_pem_public_key(key_file.read(),\
                                                          backend=default_backend())
     #encrypt the key
     RSACipher = pub.encrypt(key,\
                                   padding.OAEP(\
                                                mgf=padding.MGF1(algorithm=hashes.SHA256()),\
                                                algorithm=hashes.SHA256(),\
                                                label=None))
     
     return RSACipher,C, IV, tag, ext
    

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath,name):
    #open the private key pem file
    with open(RSA_Privatekey_filepath, "rb") as key_file:
         private = serialization.load_pem_private_key(key_file.read(),\
                                                          password=None,\
                                                          backend=default_backend())
    #decrypt to get the enckey and hmackey
    key= private.decrypt(RSACipher,\
                             padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),\
                                          algorithm=hashes.SHA256(),\
                                          label=None))
    #first 32 bytes are enckey
    EncKey=key[:32]
    #last 32 byets are hmac key
    HMACKey= key[-32:]
    
    #decrypt the cipher
    m=mEnc.MydecryptMAC(C,EncKey,HMACKey,IV,tag)
    
    #write the file
    out_file1 = open(name+ext, "wb") #make a new file
    out_file1.write(m) #write a new file
    out_file1.close() #close that file