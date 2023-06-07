from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import base64

# 定义加密函数
def encrypt_data(key, plaintext):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(iv + ciphertext)

# 定义生成陷门函数
def generate_trapdoor(key, keyword):
    h = SHA256.new(keyword.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(h)

# 定义检索函数
def search_index(index, trapdoor):
    result = []
    for key, value in index.items():
        if trapdoor in value:
            result.append(key)
    return result

# 定义解密函数
def decrypt_data(key, ciphertext):
    decoded_ciphertext = base64.b64decode(ciphertext)
    iv = decoded_ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(decoded_ciphertext[AES.block_size:])
    plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
    return plaintext

# 测试函数
def test():
    # 生成加密密钥
    key = get_random_bytes(AES.block_size)
    print("the key is:"+key.hex())
    # 生成索引
    index = {'doc1': generate_trapdoor(key, 'apple'), 'doc2': generate_trapdoor(key, 'banana'), 'doc3': generate_trapdoor(key, 'orange')}

    encrypt_docs=[]
    # 加密文档
    encrypted_doc1 = encrypt_data(key, 'This is an apple')
    encrypted_doc2 = encrypt_data(key, 'This is a banana')
    encrypted_doc3 = encrypt_data(key, 'This is an orange')

    # 检索
    trapdoor = generate_trapdoor(key, 'banana')
    result = search_index(index, trapdoor)
    print(result)  # ['doc1']

    # 解密
    plaintext = decrypt_data(key, encrypted_doc2)
    print(plaintext)  # 'This is an apple'

test()
