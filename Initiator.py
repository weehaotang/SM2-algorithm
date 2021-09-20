import base64
import binascii
import socket
from SM import sm2, sm3, sm4, func
from SM.sm4 import SM4_ENCRYPT, SM4_DECRYPT

Receiverip = ("127.0.0.1",9876)
initiatorID = "ff98384d662526f7"
receivcerID = "7e8ef89487142b14"
private_key_A = "daf40f7d7728eb010ff393759f8f0a7ba018630e89e5a321c1d3c6027f431ab0"
public_key_A = "d89c9df54e764b29b64caf275039f4e4375912302ff98cc587d1c5c8e0b2db6bab831bba311973e6ef1d55a8aae57b80c39fb7235b2ed0d277c641d15bc626ce"
if __name__ == '__main__':
    print("发起方程序")

    sk = socket.socket()
    sk.connect(Receiverip)

    #第一阶段
    #发送Pa||IDa||IDb||Za
    msga1 = public_key_A + initiatorID + receivcerID
    sm2_sign = sm2.CryptSM2(
        public_key=public_key_A, private_key=private_key_A)
    random_hex_str = func.random_hex(sm2_sign.para_len)
    siga1 = sm2_sign.sign(bytes(msga1, encoding="utf8"),random_hex_str)
    msga1 = msga1 + siga1
    sk.send(msga1.encode("utf8"))
    # 验证Pb||IDa||IDb||Zb
    msgb1 = sk.recv(1024).decode("utf8")
    public_key_B = msgb1[0:128]
    testinitiatorID = msgb1[128:144]
    testreceiverID = msgb1[144:160]
    sigb1 = msgb1[-128:]
    if (testinitiatorID == initiatorID):
        print("发起者id验证正确")
    else:
        print("发起者id验证失败退出")
        sk.close()
        exit(-1)
    if (testreceiverID == receivcerID):
        print("接收者id验证正确")
    else:
        print("接收者id验证失败退出")
        sk.close()
        exit(-1)
    sm2_verify = sm2.CryptSM2(public_key=public_key_B, private_key="")
    verify = sm2_verify.verify(sigb1, bytes(msgb1[0:160], encoding="utf8"))
    if verify == True:
        print("接收者签名验证正确")
    else:
        print("接收者签名验证失败退出")
        sk.close()
        exit(-1)
    #阶段一结束

    #第二阶段
    #生成临时密钥Ta，生成信息Pb（Ta） | | Da（Ta）
    tempkeyA = func.random_hex(64)
    EtempkeyA = sm2_verify.encrypt(bytes(tempkeyA, encoding = "utf8"))
    random_hex_str = func.random_hex(sm2_sign.para_len)
    StempkeyA = sm2_sign.sign(bytes(tempkeyA, encoding="utf8"), random_hex_str)
    sk.send(EtempkeyA+StempkeyA.encode("utf8"))
    # 接收临时密钥Tb
    msgb2 = sk.recv(1024)
    EtempkeyB = msgb2[0:160]
    StempkeyB = msgb2[-128:].decode("utf8")
    temp = sm2_sign.decrypt(EtempkeyB)
    verify = sm2_verify.verify(StempkeyB, temp)
    if verify == True:
        print("临时密钥B传输完毕")
        tempkeyB = temp.decode("utf8")
        print("Tb = "+ tempkeyB)
    else:
        print("临时密钥B传输失败退出")
        sk.close()
        exit(-1)
    #第二阶段结束

    #第三阶段
    #密钥派生Za||Zb||Pa||Pb||Ta||Tb
    KEYstr = sm3.sm3_kdf((siga1 + sigb1 + public_key_A + public_key_B + tempkeyA + tempkeyB).encode("utf8"),16)
    KEY = KEYstr.encode("utf8")
    iv = func.random_hex(64)
    print("iv = "+ iv)
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(KEY, SM4_ENCRYPT)
    msga3 = crypt_sm4.crypt_ecb(iv.encode("utf8"))
    sk.send(msga3)
    msgb3 = sk.recv(1024)
    crypt_sm4.set_key(KEY, SM4_DECRYPT)
    testiv = crypt_sm4.crypt_ecb(msgb3).decode("utf8")
    if int(testiv, 16) == int(iv, 16) + 1:
        print("密钥协商成功")
        print("会话密钥KEY = " + KEYstr)
    else:
        print("协商失败")
    sk.close()
    exit(0)