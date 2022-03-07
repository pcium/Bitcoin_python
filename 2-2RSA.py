# Public Key(RSA) 알고리즘 연습
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Private key와 Public key 쌍을 생성한다
# Private key는 소유자가 보관하고, Public key는 공개한다
keyPair = RSA.generate(2048)
privKey = keyPair.exportKey() # 개인키
pubKey = keyPair.publickey() # 공개키 (외부 공개 가능)

print(pubKey)

# keyPair의 p, q, e, d를 확인해 본다
keyObj = RSA.importKey(privKey)
print("p = ", keyObj.p)
print("q = ", keyObj.q)
print("e = ", keyObj.e)
print("d = ", keyObj.d)

# 암호화할 원문
plainText = b'This is Plain text. It will be encrypted using RSA.'
print()
print("원문 : ")
print(plainText)

# 공개키로 원문을 암호화한다.
cipherText = pubKey.encrypt(plainText.encode(), 10)
print("\n")
print("암호문 : ")
print(cipherText[0].hex())

# Private key를 소유한 수신자는 자신의 Private key로 암호문을 해독한다.
# pubKey와 쌍을 이루는 privKey만이 이 암호문을 해독할 수 있다.
key = RSA.importKey(privKey)
plainText2 = key.decrypt(cipherText)
plainText2 = plainText2.decode("utf-8")
print("\n")
print("해독문 : ")
print(plainText2)
