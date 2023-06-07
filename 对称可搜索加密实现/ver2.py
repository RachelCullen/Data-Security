from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import os

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

    def search_index(self, query):
        """
        用GCm加密模式解密相关文档并返回
        """
        # 检索相关文档ID
        related_document_ids = set()
        for keyword in query.split():
            if keyword in self.inverted_index:
                related_document_ids |= self.inverted_index[keyword]

        # 解密相关文档并返回
        decrypted_documents = []
        for document_id in related_document_ids:
            # 解密文档
            cipher_text, iv, tag = self.encrypted_documents[document_id]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            plaintext = unpad(cipher.decrypt_and_verify(cipher_text, tag), AES.block_size).decode('utf-8')

            # 添加到结果列表
            decrypted_documents.append(plaintext)

        # 返回解密后的文档列表
        return decrypted_documents
# 测试
documents = ['Hello world', 'I am chenruiying', 'I love nku',
             'apple', 'banana', 'orange', 'hahahaha', 'kiwi', 'pepper','nonono I hate the apple',
             'apple', 'banana', 'orange', 'haha', 'ki','cannot think more about this','everything is fine!']
encrypted_index = EncryptedIndex()
encrypted_index.build_index(documents)
query = 'I'
decrypted_documents = encrypted_index.search_index(query)
print(decrypted_documents)
