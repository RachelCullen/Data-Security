import re
from pyDes import triple_des as des, PAD_PKCS5, ECB
import pyDes
import base64
import hashlib
import hmac
import random
test_strs = ["I love apple","I like Chinese","banana and apple"]

#利用正则表达式分割字符串
def split_str(str):
    word_list=re.split(r"\b[\.,\s\n\r\n]+?\b",str)
    return word_list

#使用DES加密
def encrypt(s,DES_KEY):
    fin_str = ""
    s = s.encode() # 这里中文要转成字节
    iv = b'abcdefgh' # 定义初始化向量，长度为8个字符（64位）
    des_obj = des(DES_KEY, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)  # 初始化一个des对象，参数是秘钥，加密方式，偏移， 填充方式
    while len(fin_str)<64:
        secret_bytes = des_obj.encrypt(s)  # 用对象的encrypt方法加密
        secret_hex = secret_bytes.hex()
        secret_str = str(secret_hex)
        s = secret_str
        fin_str = fin_str + secret_str
    return fin_str

#使用DES解密
def decrypt(secret_bytes,DES_KEY):
    secret_bytes = bytes.fromhex(secret_bytes) # 这里中文要转成字节
    iv = b'abcdefgh' # 定义初始化向量，长度为8个字符（64位）
    des_obj = des(DES_KEY, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)  # 初始化一个des对象，参数是秘钥，加密方式，偏移， 填充方式
    s = des_obj.decrypt(secret_bytes)  # 用对象的decrypt方法解密
    return s.decode()

#拆分成左右两边
def split_str_2(str):
    left = str[:len(str)//2]
    right = str[len(str)//2:]
    return left,right

#使用hmac_MD5加密
def hmac_md5(msg,key):
    return hmac.new(key.encode(), msg.encode(), hashlib.md5).hexdigest()

#通过随机种子生成随机数
def gen_random(seed):
    res = ""
    dic = ["0123456789abcde"]
    random.seed(seed)
    for i in range(32):
        r = random.randint(0,14)
        res = res + dic[0][r]
    return res

#做异或操作
def strXOR(str1,str2):
    if len(str1) != len(str2):
        print('ERROR: the length of two strings must be equal')
        print(len(str1),len(str2))
        return ""
    standard = len(str1)+2
    num1 = int(str1,16)
    num2 = int(str2,16)
    bin1 = bin(num1)
    bin2 = bin(num2)
    res = int(bin1,2) ^ int(bin2,2)
    res = hex(res)
    # 这里是一种特殊情况，如果异或完之后出现了0开头的结果，就会导致返回的值不足原来的比特位的情况。
    if len(res)<standard:
        res = str(res)
        res = res[2:]
        while len(res)<standard-2:
            res = '0' + res
        res = '0x' + res
    return res


#加密算法的pipeline
def Encrypt_pipeline(word,seed,DES_KEY,HASH_KEY):
    print()
    print('=====================ENCRYPT PROCESS=====================')
    if word == "":
        print("THIS IS AN EXAMPLE")
        word_list = split_str(test_strs[1])
        print('[ENCRYPT_LOG] word:',word_list[2])
        word = encrypt(word_list[2],DES_KEY) #64位
        print('[ENCRYPT_LOG] word:',word)
    else:
        print('[ENCRYPT_LOG] word:',word)
        word = encrypt(word,DES_KEY) #64位
        print('[ENCRYPT_LOG] word:',word)
    left,right = split_str_2(word)
    print('[ENCRYPT_LOG] left,right:',left,right)
    Ki = hmac_md5(left,HASH_KEY) #32位
    print('[ENCRYPT_LOG] Ki:',Ki)
    ran = gen_random(seed) #产生32位随机数
    print('[ENCRYPT_LOG] Si:',ran)
    Fki = hmac_md5(ran,Ki)
    print('[ENCRYPT_LOG] Fki:',Fki)
    res = str(ran) + str(Fki)
    print('[ENCRYPT_LOG] join_res:',res)
    Ci = strXOR(res,word)
    print('[ENCRYPT_LOG] Ci:',Ci)
    return Ci,word,Ki,ran


#检索算法的pipline
def Search_pipeline(Ci,Xi,ki,HASH_KEY):
    print()
    print('=====================SEARCH PROCESS=====================')
    Ti = strXOR(Ci,Xi)[2:]
    print('[SEARCH_LOG] Ti:',Ti)
    left,right = split_str_2(Ti)
    print('[SEARCH_LOG] left,right:',left,right)
    cal_Right = hmac_md5(left,ki)
    print('[SEARCH_LOG] cal_Right:',cal_Right)
    print('[SEARCH_LOG] right:',right)
    if right == cal_Right:
        print('[SEARCH_LOG] Search Success!')
        return True
    else:
        return False


def Decrypt_pipeline(Si,Ci,Ki,DES_KEY,HASH_KEY):
    print()
    print('=====================DECRYPT PROCESS=====================')
    # Ci = Ci[2:]
    print('[DECRYPT_LOG] Ci:',Ci)
    Cil,Cir = split_str_2(Ci)
    print('[DECRYPT_LOG] Cil,Cir:',Cil,Cir)
    Li = strXOR(Si,Cil)
    print('[DECRYPT_LOG] Li:',Li)
    Fki = hmac_md5(Si,Ki)
    print('[DECRYPT_LOG] Fki:',Fki)
    Ri = strXOR(Cir,Fki)
    print('[DECRYPT_LOG] Ri:',Ri)
    X = Li + Ri
    print('[DECRYPT_LOG] X:',X)
    word = decrypt(str(X)[2:18],DES_KEY)
    print('[DECRYPT_LOG] word:',word)
    return word
    

def Pipeline(word="",seed=1,DES_KEY=b'1234567812345678',HASH_KEY='12345678'):
    Ci,Xi,Ki,Si= Encrypt_pipeline(word,seed,DES_KEY,HASH_KEY)
    print()
    print('=====================MAIN PROCESS=====================')
    print('[MAIN_LOG] Ci',Ci)
    print('[MAIN_LOG] Xi',Xi)
    print('[MAIN_LOG] Ki',Ki)
    print('[MAIN_LOG] Si',Si)
    Search_pipeline(Ci[2:],Xi,Ki,HASH_KEY)
    Decrypt_pipline(Si,Ci,Ki,DES_KEY,HASH_KEY)
    




if __name__ == '__main__':
    Pipeline()
    