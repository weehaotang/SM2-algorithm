import base64
import binascii
from SM import sm2, func


if __name__ == '__main__':

    private_key = func.random_hex(64)
    print(private_key)
    sm2_Schedule = sm2.CryptSM2(
       public_key='', private_key='')
    K = int(private_key,16)
    print(type(K))
    public_key = sm2_Schedule._kg(K,sm2_Schedule.ecc_table['g'])
    print(public_key)
    sm2_crypt = sm2.CryptSM2(
         public_key=public_key, private_key=private_key)
    # public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    #
    # sm2_crypt = sm2.CryptSM2(
    #     public_key=public_key, private_key=private_key)
    data = b"111"
    enc_data = sm2_crypt.encrypt(data)
    print(type(enc_data))

    #print("enc_data:%s" % enc_data)
    #print("enc_data_base64:%s" % base64.b64encode(bytes.fromhex(enc_data)))
    dec_data = sm2_crypt.decrypt(enc_data)
    print(type(dec_data))
    print(b"dec_data:%s" % dec_data)
    assert data == dec_data

    print("-----------------test sign and verify---------------")
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(data, random_hex_str)
    print(type(sign))
    print('sign:%s' % sign)
    sm2_v = sm2.CryptSM2(
         public_key=public_key,private_key = "")
    verify = sm2_v.verify(sign, data)
    print(type(verify))
    print('verify:%s' % verify)
    assert verify
