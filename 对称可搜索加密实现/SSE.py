import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import os
from Crypto.Hash import SHA256

class EncryptedIndex:
    """
    用于建立加密的反向索引和检索加密文档的类
    """
    def __init__(self):
        self.key = None
        self.inverted_index = {}
        self.encrypted_documents = []
    
    def _encrypt_document(self, document):
        """
        使用AES GCM模式加密文档并返回密文、初始化向量和认证标签
        """
        # 生成随机初始化向量
        iv = os.urandom(AES.block_size)

        # 使用GCM模式加密文档
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        cipher_text, tag = cipher.encrypt_and_digest(pad(document.encode('utf-8'), AES.block_size))

        return cipher_text, iv, tag



    def _generate_trapdoor(self, query):
        """
        根据查询语句生成查询陷门
        """
        # 查询每个关键词对应的加密文档ID
        trapdoor = {}
        for keyword in query.split():
            if keyword in self.inverted_index:
                trapdoor[keyword] = self.inverted_index[keyword]
            else:
                trapdoor[keyword] = set()

        # 使用SHA256哈希函数计算加密文档ID的集合为一个128位的陷门
        hash_object = SHA256.new(data=str(trapdoor).encode('utf-8'))
        return hash_object.digest()

    def build_index(self, documents):
        """
        建立加密的反向索引并返回加密后的文档和反向索引
        """
        # 生成密钥
        self.key = os.urandom(16)

        # 初始化反向索引
        self.inverted_index = {}

        # 加密文档
        self.encrypted_documents = []
        for document in documents:
            # 加密文档并存储加密后的文档、初始化向量和认证标签
            self.encrypted_documents.append(self._encrypt_document(document))

            # 更新反向索引
            for keyword in document.split():
                if keyword not in self.inverted_index:
                    self.inverted_index[keyword] = set()
                self.inverted_index[keyword].add(len(self.encrypted_documents) - 1)

        # 返回加密后的文档和反向索引
        return self.encrypted_documents, self.inverted_index, self.key

    def search_index(self, query, trapdoor=None):
        """
        用GCM加密模式解密相关文档并返回
        """
        # 检索相关文档ID
        related_document_ids = set()
        if trapdoor is None:
            # 生成查询陷门
            trapdoor = {}
            for keyword in query.split():
                trapdoor[keyword] = set()
                if keyword in self.inverted_index:
                    trapdoor[keyword] = self.inverted_index[keyword]
            return trapdoor
        else:
            for keyword in trapdoor:
                if keyword in self.inverted_index:
                    related_document_ids |= trapdoor[keyword]

        # 解密相关文档并返回
        decrypted_documents = []
        for document_id in related_document_ids:
            # 解密文档
            cipher_text, iv, tag = self.encrypted_documents[document_id]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            output = bytearray(len(cipher_text))
            plaintext = unpad(cipher.decrypt_and_verify(cipher_text, tag, output=output), AES.block_size).decode('utf-8')

            # 添加到结果列表
            decrypted_documents.append(plaintext)

        # 返回解密后的文档列表
        return decrypted_documents




    def generate_and_encrypt_trapdoor(self, query):
        """
        生成查询陷门并加密
        """
        trapdoor = self._generate_trapdoor(query)

        # 将查询陷门序列化为字节串
        trapdoor_bytes = pickle.dump(trapdoor)

        # 生成随机初始化向量
        iv = os.urandom(AES.block_size)

        # 使用GCM模式加密查询陷门
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        cipher_text, tag = cipher.encrypt_and_digest(pad(trapdoor_bytes, AES.block_size))

        return cipher_text, iv, tag

    def decrypt_trapdoor(self, cipher_text, iv, tag):
        """
        解密查询陷门并反序列化为Python对象
        """
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        output = bytearray(len(cipher_text))
        trapdoor_bytes = unpad(cipher.decrypt_and_verify(cipher_text, tag, output=output), AES.block_size)
        trapdoor = pickle.load(trapdoor_bytes)
        return trapdoor
   
#测试 
documents = ['Hello world', 'I am chenruiying', 'I love nku',
             'apple', 'banana', 'orange', 'hahahaha', 'kiwi', 'pepper','nonono I hate the apple',
             'apple', 'banana', 'orange', 'haha', 'ki','cannot think more about this','everything is fine!']
encrypted_index = EncryptedIndex()

# 建立加密索引
encrypted_documents, inverted_index, key = encrypted_index.build_index(documents)

# 为查询构建陷门
query = 'I'
cipher = AES.new(key, AES.MODE_ECB)
trapdoor = cipher.encrypt(pad(query.encode('utf-8'), AES.block_size))

# 使用陷门进行检索
decrypted_documents = []
for document_id, (cipher_text, iv, tag) in enumerate(encrypted_documents):
    # 解密陷门
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_trapdoor = cipher.decrypt(trapdoor)

   #计算密文和陷门之间是否匹配
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    output = bytearray(len(cipher_text))
    score = output == decrypted_trapdoor

    # 匹配成功，将密文加入到解密文档中
    if score:
        decrypted_documents.append(documents[document_id])

# 打印解密文档
print(decrypted_documents)
