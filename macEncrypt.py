#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 25 17:51:53 2018

@author: QuangLe & Sean Dinh
"""

import os
import encrypt as enc

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

def MyencryptMAC(message, EncKey, HMACKey):
    m,iv= enc.MyEncrypt(message,EncKey) #get the m and iv from encrypt
    h= hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #make an hmac
    h.update(m) #create the hash 
    return (m,iv,h.finalize()) #return encrypted message and iv


def MydecryptMAC(message,EncKey,HMACKey,iv,tag):
    try:
        h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #make an hmac
        h.update(message) #recalculate the message
        h.verify(tag) #compare to the tag
        m=enc.MyDecrypt(message,EncKey,iv) #Decrypt the message
        return m
    except:
        print("Invalid tag")
        
def MyfileEncryptMAC(filepath):
    key = os.urandom(enc.keySize) #make a 32 byte key
    Hkey = os.urandom(enc.keySize) #make a 32 byte hmac key
    
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