import base64
import binascii
import socket
from SM import sm2, sm3, sm4, func
from SM.sm4 import SM4_ENCRYPT, SM4_DECRYPT
Receiverip = ("127.0.0.1",9876)
receivcerID = "7e8ef89487142b14"
private_key_B = "becddb019b2f8314162929e38d04b150e5693a7387554ca1bd96f284615aa9fb"
public_key_B = "fa9d8dc60b2c971340dd5c9acb45802d002522b2811fc68e0efee0039a3649e4a5d2f70a476bb0f469be8549e096215a1242a055ec010ea7a301c1785e27b105"

if __name__ == '__main__':
    print("接收方程序")

    sk = socket.socket()
    sk.bind(Receiverip)
    sk.listen(5)
    while True:
        c,addr = sk.accept()
        print("收到连接来自"+str(addr))


        #第一阶段
        #验证Pa||IDa||IDb||Za
        msga1 = c.recv(1024).decode("utf8")
        public_key_A = msga1[0:128]
        initiatorID = msga1[128:144]
        testreceiverID = msga1[144:160]
        siga1 = msga1[-128:]
        if(testreceiverID == receivcerID):
            print("接收者id验证正确")
        else:
            print("接收者id验证失败退出")
            c.close()
            break
        sm2_verify = sm2.CryptSM2(
            public_key=public_key_A, private_key="")
        verify = sm2_verify.verify(siga1,bytes(msga1[0:160], encoding="utf8"))
        if verify == True:
            print("发起者签名验证正确")
        else:
            print("发起者签名验证失败退出")
            c.close()
            break
        #发送Pb||IDa||IDb||Zb、
        msgb1 = public_key_B + initiatorID + receivcerID
        sm2_sign = sm2.CryptSM2(
            public_key=public_key_B, private_key=private_key_B)
        random_hex_str = func.random_hex(sm2_sign.para_len)
        sigb1 = sm2_sign.sign(bytes(msgb1, encoding="utf8"), random_hex_str)
        msgb1 = msgb1 + sigb1
        c.send((msgb1.encode("utf8")))
        #阶段一结束

        #第二阶段
        #接收临时密钥Ta
        msga2 = c.recv(1024)
        EtempkeyA = msga2[0:160]
        StempkeyA = msga2[-128:].decode("utf8")
        temp = sm2_sign.decrypt(EtempkeyA)
        verify = sm2_verify.verify(StempkeyA, temp)
        if verify == True:
            print("临时密钥A传输完毕")
            tempkeyA = temp.decode("utf8")
            print("Ta = " + tempkeyA)
        else:
            print("临时密钥A传输失败退出")
            c.close()
            break
        #生成临时密钥Tb，生成信息Pa（Ta）||Db（Tb）
        tempkeyB = func.random_hex(64)
        EtempkeyB = sm2_verify.encrypt(bytes(tempkeyB, encoding="utf8"))
        random_hex_str = func.random_hex(sm2_sign.para_len)
        StempkeyB = sm2_sign.sign(bytes(tempkeyB, encoding="utf8"), random_hex_str)
        c.send(EtempkeyB + StempkeyB.encode("utf8"))
        #第二阶段结束

        #第三阶段
        msga3 = c.recv(1024)
        KEYstr = sm3.sm3_kdf((siga1 + sigb1 + public_key_A + public_key_B + tempkeyA + tempkeyB).encode("utf8"),16)
        KEY = KEYstr.encode("utf8")
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(KEY, SM4_DECRYPT)
        iv = crypt_sm4.crypt_ecb(msga3).decode("utf8")
        print("iv = " + iv)
        iv = hex(int(iv,16)+1)
        crypt_sm4.set_key(KEY, SM4_ENCRYPT)
        msgb3 = crypt_sm4.crypt_ecb(iv.encode("utf8"))
        c.send(msgb3)
        c.close()