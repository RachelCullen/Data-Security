import Encrypt


test_strs = ["I love apple","I love Chinese","banana and apple"]
seed = 1
DES_KEY = "1234567812345678"
HASH_KEY = "12345678"
Encrypt_Emails = []
Server_Emails = []
Decrypt_Emails = []

class Encrypt_word:
    def __init__(self,Ci,Xi,Ki,Si):
        self.Ci = Ci
        self.Xi = Xi
        self.Ki = Ki
        self.Si = Si
    def getCi(self):
        if(self.Ci[0:2] == "0x"):
            return self.Ci[2:]
        return self.Ci
    def getXi(self):
        if(self.Xi[0:2] == '0x'):
            return self.Xi[2:]
        return self.Xi
    def getKi(self):
        if(self.Ki[0:2] == '0x'):
            return self.Ki[2:]
        return self.Ki
    def getSi(self):
        if(self.Si[0:2] == '0x'):
            return self.Si[2:]
        return self.Si
    def ew_print(self):
        print("========================================")
        print("[CHECK ENCRYPT_WORD] CI = ",self.Ci)
        print("[CHECK ENCRYPT_WORD] XI = ",self.Xi)
        print("[CHECK ENCRYPT_WORD] KI = ",self.Ki)
        print("[CHECK ENCRYPT_WORD] SI = ",self.Si)
        print("========================================")

class Server_word:
    def __init__(self,Ci):
        self.Ci = Ci
    def getCi(self):
        if(self.Ci[0:2] == "0x"):
            return self.Ci[2:]
        return self.Ci
    def sw_print(self):
        print("========================================")
        print("[CHECK SERVER_WORD] CI = ",self.Ci)
        print("========================================")

def print_Encrypt_Emails():
    count = 1
    for email in Encrypt_Emails:
        print("==================displaying %s  Client_email===============" % str(count))
        for ew in email:
            ew.ew_print()
        count+=1

def print_Server_Emails():
    count = 1
    for email in Server_Emails:
        print("==================displaying %s  Server_email===============" % str(count))
        for sw in email:
            sw.sw_print()
        count+=1

def Encrypt_email(ss):
    Encrypt_email = []
    Server_email = []
    words = Encrypt.split_str(ss)
    for word in words:
        Ci,Xi,Ki,Si= Encrypt.Encrypt_pipeline(word,seed,DES_KEY,HASH_KEY)
        ew = Encrypt_word(Ci,Xi,Ki,Si)
        Encrypt_email.append(ew)
        se = Server_word(Ci)
        Server_email.append(se)
    
    Encrypt_Emails.append(Encrypt_email)
    Server_Emails.append(Server_email)

def Encrypt_emails():
    for email in test_strs:
        Encrypt_email(email)

def Search_emails(ss):
    # 直接检查所有的邮件列表里有没有这个词，有的话把对应位置的Encrypt_word对象取出来
    '''
    其实在这一步应该直接让用户输入对应的CI、XI、KI、SI
    但是就一个简单的demo而言还要用户交互几百个hex不太现实
    不如我直接在所有的已有的email里搜索
    '''
    index_i = -1
    index_j = -1
    for i in range(0,len(test_strs)):
        words = Encrypt.split_str(test_strs[i])
        for j in range(0,len(words)):
            if words[j] == ss:
                index_i = i
                index_j = j
                break
    if index_i == -1 & index_j == -1:
        print("[ERROR TRACK] : DO NOT HAVE THIS WORD")
        return None,None
        
    ee = Encrypt_Emails[index_i][index_j]
    correct_emails = []
    for email in Server_Emails:
        for sw in email:
            if Encrypt.Search_pipeline(sw.getCi(),ee.getXi(),ee.getKi(),HASH_KEY):
                correct_emails.append(email)
    
    return correct_emails,ee

def Decrypt_emails(ew):
    mails = []
    for mail in Decrypt_Emails:
        temp_mail = []
        for sw in mail:
            temp_mail.append(Encrypt.Decrypt_pipeline(ew.getSi(),sw.getCi(),ew.getKi(),DES_KEY,HASH_KEY))
        mails.append(temp_mail)
    
    print("================DISPLAY EMIAL========================")
    for email in mails:
        print("[email]",end=' ')
        for word in email:
            print(word,end=' ')
        print()
        
            
if __name__ == '__main__':
    Encrypt_emails()
    print_Encrypt_Emails()
    # 这个时候所有的邮件都加载好了，如果存在服务端，这个时候服务端应该保存Server_emails，客户端保存Encrypt_Emails
    # 但此时Encrypt_Emails应该不存CI，只存Xi,Ki,Si，但这里没有这么操作，为了debug我都存了，但其实后面都没有用到
    print_Server_Emails()
    search_word = "Chinese"
    Searched_emails,ew = Search_emails(search_word)
    if Searched_emails == None:
        print('error search_word')
        exit()
    Decrypt_Emails = Searched_emails
    print('Searching',len(Searched_emails),'eamil containing',search_word)
    Decrypt_emails(ew)
    
    
    