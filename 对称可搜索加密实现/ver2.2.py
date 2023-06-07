import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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
    
    def build_index(self, documents, trapdoor):
        """
        建立加密的反向索引并返回加密后的文档和反向索引
        """
        # 选择哈希函数
        hasher = hashlib.sha256

        # 计算陷门值
        trapdoor_value = hasher(trapdoor.encode('utf-8')).digest()

        # 生成密钥
        self.key = hasher(trapdoor_value).digest()[:16]

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

    def search_index(self, query, trapdoor):
        """
        用GCm加密模式解密相关文档并返回
        """
        # 选择哈希函数
        hasher = hashlib.sha256

        # 计算陷门值
        trapdoor_value = hasher(trapdoor.encode('utf-8')).digest()

        # 生成密钥
        key = hasher(trapdoor_value).digest()[:16]

        # 检索相关文档ID
        related_document_ids = set()
        for keyword in query.split():
            if keyword in self.inverted_index:
                related_document_ids |= self.inverted_index[keyword]
                
        # 遍历相关文档ID列表，并使用相应文档的加密数据和给定的陷门解密文档
        decrypted_documents = []                
        for document_id in related_document_ids:
            # 解密文档
            cipher_text, iv, tag = self.encrypted_documents[document_id]
            key = SHA256.new(trapdoor.encode('utf-8')).digest()
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            plaintext = unpad(cipher.decrypt_and_verify(cipher_text, tag), AES.block_size).decode('utf-8')

            # 将解密后的文档添加到结果列表
            decrypted_documents.append(plaintext)
# 测试
documents = ['Hello world', 'I am chenruiying', 'I love nku',             
             'apple', 'banana', 'orange', 'hahahaha', 'kiwi', 'pepper','nonono I hate the apple',             'apple', 'banana', 'orange', 'haha', 'ki','cannot think more about this','everything is fine!']
encrypted_index = EncryptedIndex()
trapdoor = "apple"
encrypted_index.build_index(documents,trapdoor)
query = 'I'
decrypted_documents = encrypted_index.search_index(query, trapdoor)
print(decrypted_documents)
