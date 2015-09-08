from flask import Flask, request, jsonify
import json
from Crypto.Cipher import AES
from Crypto import Random
import base64

app = Flask(__name__)

# Make the WSGI interface available at the top level so wfastcgi can get it.
wsgi_app = app.wsgi_app

dict = {'plaintext':'No message recieved.'}

def pad(data):
     length = 16 - (len(data) % 16)
     data += chr(length)*length
     return data

def unpad(data):
     data = data[:-ord(data[len(data)-1:])]
     return data

class AESHandler:
     def __init__(self):
         self.key = Random.get_random_bytes(32)

     def encrypt(self, plaintext):
         plaintext = pad(plaintext)
         self.iv = Random.get_random_bytes(16)
         cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
         ciphertext = cipher.encrypt(plaintext)
         return ciphertext

     def decrypt(self, ciphertext_iv):
         self.iv = base64.b64decode(ciphertext_iv[-24:])
         ciphertext = base64.b64decode(ciphertext_iv[:-24])
         cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
         plaintext = unpad(cipher.decrypt(ciphertext))
         return plaintext

aeshandler = AESHandler()

@app.route('/encrypt', methods=['GET', 'POST'])
def recieve_and_encrypt():
    json_message = request.get_json(force=True)
    dict['plaintext'] = json_message['message']
    dict['ciphertext_iv'] = base64.b64encode(aeshandler.encrypt(dict['plaintext'])) + base64.b64encode(aeshandler.iv)
    return dict['ciphertext_iv']

@app.route('/decrypt', methods=['GET', 'POST'])
def recieve_and_decrypt():
    json_message = request.get_json(force=True)
    dict['ciphertext_iv'] = json_message['message']
    dict['plaintext'] = aeshandler.decrypt(dict['ciphertext_iv'])
    return dict['plaintext']

@app.route('/key')
def show_key():
    return base64.b64encode(aeshandler.key)

@app.route('/iv')
def show_iv():
    return base64.b64encode(aeshandler.iv)

@app.route('/plaintext')
def show_message():
    return dict['plaintext']

@app.route('/ciphertext')
def show_encrypted_message():
    return dict['ciphertext_iv']

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')
