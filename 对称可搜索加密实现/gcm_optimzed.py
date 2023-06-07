from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import os

def encrypt_and_build_index(documents):
    """
    用GCm加密模式，通过将索引中存储的文档ID加密来保护文档的隐私。
    """
    # 生成密钥
    key = os.urandom(16)

    # 初始化反向索引
    inverted_index = {}

    # 加密文档
    encrypted_documents = []
    for document in documents:
        # 生成随机初始化向量
        iv = os.urandom(AES.block_size)

        # 使用GCM模式加密文档
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher_text, tag = cipher.encrypt_and_digest(pad(document.encode('utf-8'), AES.block_size))

        # 存储加密后的文档、初始化向量和认证标签
        encrypted_documents.append((cipher_text, iv, tag))

        # 更新反向索引
        for keyword in document.split():
            if keyword not in inverted_index:
                inverted_index[keyword] = set()
            inverted_index[keyword].add(len(encrypted_documents) - 1)

    # 返回加密后的文档和反向索引
    return encrypted_documents, inverted_index, key


def decrypt_and_search_index(query, encrypted_documents, inverted_index, key):
    """
    用GCm加密模式解密相关文档并返回
    """
    # 检索相关文档ID
    related_document_ids = set()
    for keyword in query.split():
        if keyword in inverted_index:
            related_document_ids |= inverted_index[keyword]

    # 解密相关文档并返回
    decrypted_documents = []
    for document_id in related_document_ids:
        # 解密文档
        cipher_text, iv, tag = encrypted_documents[document_id]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = unpad(cipher.decrypt_and_verify(cipher_text, tag), AES.block_size).decode('utf-8')

        # 添加到结果列表
        decrypted_documents.append(plaintext)

    # 返回解密后的文档列表
    return decrypted_documents

# 测试
documents = ['Hello world', 'Hello chatbot', 'Goodbye chatbot']
encrypted_documents, inverted_index, key = encrypt_and_build_index(documents)
query = 'Hello'
decrypted_documents = decrypt_and_search_index(query, encrypted_documents, inverted_index, key)
print(decrypted_documents)
