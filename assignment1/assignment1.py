import hashlib
import unittest
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode


class AESCipher(object):
    def __init__(self,key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest() 

    def __padding(self, plaintext):
        numberOfBytesToPad = self.block_size - len(plaintext) % self.block_size
        asciiString = chr(numberOfBytesToPad)
        paddingStr = numberOfBytesToPad * asciiString
        paddedPlainText = plaintext + paddingStr
        return paddedPlainText
    
    @staticmethod
    def __unpadding(plaintext):
        lastCharacter = plaintext[len(plaintext) - 1 :]
        bytesToRemove = ord(lastCharacter)
        return plaintext[:-bytesToRemove]
    
    def encrypt(self, plaintext):
        plaintext = self.__padding(plaintext)
        iv = Random.new().read(self.block_size)
        cipher  = AES.new(self.key, AES.MODE_CBC , iv)
        encryptedText = cipher.encrypt(plaintext.encode())
        return b64encode(iv + encryptedText).decode("utf-8")
    
    def decrypt(self,encryptedtext):
        encryptedtext = b64decode(encryptedtext)
        iv = encryptedtext[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC,iv)
        plaintext = cipher.decrypt(encryptedtext[self.block_size : ]).decode("utf-8")
        return self.__unpadding(plaintext)


def aesTest(clientmsg):
    clientmsg = "Hi from Kathmandu University"
    algo = AESCipher("thisIsKey")
    encryptedForm = algo.encrypt(clientmsg)
    print("The encrypted form is:")
    print(encryptedForm)
    decryptedForm = algo.decrypt(encryptedForm)
    print("The decrypted Form is")
    print(decryptedForm)
    return decryptedForm


class TestCase(unittest.TestCase):
    def test_AEStry(self):
        print("From test")
        clientmsg = "Hi from Kathmandu University"
        self.assertEqual(aesTest(clientmsg), clientmsg)

if __name__ == "__main__":
    unittest.main()