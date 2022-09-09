#! /usr/bin/env python3
import base64
from base64 import encode 
from distutils.log import error
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

AES_N_LEN = 16
AES_TAG_LEN =16
EC_KEY_LEN = 32
EC_SIGN_LEN=64




#holding private keys 
#bundle1=dict()
#bundle2={'IKa':'', 'EKa':''}




# ____________________________________common function____________________________________

def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode('utf-8').strip()
    

def unb64(msg):
    return base64.b64decode(msg)

def encode(msg):
    message=base64.b64encode(msg)
    base64_message=message.decode('ascii')
    return base64_message

def decode(msg):
    mesg=msg.encode('ascii')
    m=base64.decodebytes(mesg)
    return m 


#byte to x25519
def load_public(public_bytes):
    loaded_public_key = X25519PublicKey.from_public_bytes(public_bytes)
    return loaded_public_key

def load_private(private_bytes):
    loaded_private_key = X25519PrivateKey.from_private_bytes_bytes(private_bytes)
    return loaded_private_key


#hkdf function 
def hkdf(inp, length):
    # use HKDF on an input to derive a key
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)


def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]


#convert x25519PublicKey to string
def toString1(key):

    newkey=key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)
    s=base64.b16encode(newkey).decode()
    return s

#convert x25519PublicKey to byte


#convert x25519PrivateKey to string
def toString2(key):

    newkey=key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)
    s=base64.b16encode(newkey).decode()
    return s





#convert string to x25519Publickey
def toPublic(string):
    key1=base64.b16decode(string.encode())
    public=X25519PublicKey.from_public_bytes(key1)
    return public

#convert string to ED25519Publickey
def toPublic1(string):
    key1=base64.b16decode(string.encode())
    public=Ed25519PublicKey.from_public_bytes(key1)
    return public

#convert string to ED25519Privatekey
def toPrivate1(string):
    key1=base64.b16decode(string.encode())
    private=Ed25519PrivateKey.from_private_bytes(key1)
    return private




#convert string to x25519Privatekey
def toPrivate(string):
    key1=base64.b16decode(string.encode())
    private=X25519PrivateKey.from_private_bytes(key1)
    return private


#read private keys 
def loadPrivate1():
    with open("/home/ayoub/devHacking/python/api/keys.txt","r") as msg:
        myline= json.loads(msg.readline())
        
        
        while myline:
            if 'OPKb' in myline.keys():
                recu=myline
                break
            else:
                myline= json.loads(msg.readline())

    msg.close()
    print(recu)
    return recu 

def loadPrivate2():
    with open("/home/ayoub/devHacking/python/api/keys.txt","r") as msg:
        myline= json.loads(msg.readline())
        
        
        while myline:
            if 'EKa' in myline.keys():
                recu=myline
                break
            else:
                myline= json.loads(msg.readline())

    msg.close()
    #print(recu)
    
    return recu 


def reform(list):
        l=[]
        for i in list:
            s=toString1(i)
            l.append(s)
        for i in l:
            print(i)
        return l 


#extract public keys from server 
def extract(name):

        
        res=requests.get('http://127.0.0.1:5000/getKeys?username='+name)
        data=res.json()
        return data 
        print(data)


def dump_privatekey(private_key, to_str=True):
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key

def dump_publickey(public_key):
    public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return public_key



def getMessage(name):
    res=requests.get('http://127.0.0.1:5000/getCipher?from='+name)
    data=res.json()
    print(data)
    return data 

def updateFlag(name):
    try:
        requests.post('http://127.0.0.1:5000/updateFlag?from='+name)
        print('ok')
    except:
        print("error")
    


class SymmRatchet(object):
    def __init__(self, key):
        self.state = key
        


    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv







#--------------------------------------------CLIENT1---------------------------------------

def client1():
        IKb= X25519PrivateKey.generate()
        
        SPKb= X25519PrivateKey.generate()
        
        OPKb = X25519PrivateKey.generate()

        bundle2=dict()
        bundle2['IKb']=toString2(IKb)
        bundle2['SPKb']=toString2(SPKb) 
        bundle2['OPKb']=toString2(OPKb) 
        IKb_p=IKb.public_key()
        SPKb_p=SPKb.public_key()
        OPKb_p=OPKb.public_key()

        s=toString1(IKb_p)
        print(s)

        f=toString1(SPKb_p)
        print(f)
        try:
            with open ("/home/ayoub/devHacking/python/api/keys.txt","a") as m:
                json.dump(bundle2,m)
                #print(request.data)
                m.write('\n')
            
        except(error):
            print(error)

        
        print(SPKb_p)
        print(IKb_p)
        print(OPKb_p)
        list=[IKb_p,SPKb_p,OPKb_p]
        return list 


#PUBLISH PUBLIC KEYS
def publish1(name,lis):
        list=reform(lis)
        print(list)
        x=dict()
        x["name"]=name
        x["IKb_p"]=list[0]
        x["SPKb_p"]=list[1]
        x["OPKb_p"]=list[2]
        #print(json.dumps(x))
        #requests.post('http://127.0.0.1:5000/login/Bob',json=x, timeout=5)
        return x 


#X3DH
def x3dh1(name):

    data=extract(name)

    k1=data['IKa_p']
    k2=data['EKa_p']
    
            
            
    '''key1=base64.b16decode(k1.encode())
    key2=base64.b16decode(k2.encode())
    key3=base64.b16decode(k3.encode())
            #print(key1)
    k1=X25519PublicKey.from_public_bytes(key1)
    k2=X25519PublicKey.from_public_bytes(key2)
    k3=X25519PublicKey.from_public_bytes(key3)'''
    k1=toPublic(k1)
    k2=toPublic(k2)
    
        #s=k1.public_bytes(
                        #encoding=serialization.Encoding.Raw,
                        #format=serialization.PublicFormat.Raw)
            #print(l)
            #print(s)
            #string=base64.b16encode(s).decode()
            #print(string)
                
                
            #alice=Alice()
            #alice.x3dh(k1,k2,k3)
            #bob.x3dh(alice)
    keys=dict()
    keys['IKa_p']=k1
    keys['EKa_p']=k2
    
    print(keys)
        #list.append(k1)
        #list.append(k2)
        #list.append(k3)
    #print(keys)
    #return keys
    dh1 = toPrivate(loadPrivate1()['SPKb']).exchange(keys['IKa_p'])    #bob.SPKb.public_key())
    dh2 = toPrivate(loadPrivate1()['IKb']).exchange(keys['EKa_p'])#bob.IKb.public_key())
    dh3 = toPrivate(loadPrivate1()['SPKb']).exchange(keys['EKa_p'])#bob.SPKb.public_key())
    dh4 = toPrivate(loadPrivate1()['OPKb']).exchange(keys['EKa_p'])#bob.OPKb.public_key())
        # the shared key is KDF(DH1||DH2||DH3||DH4)
    sk = hkdf( dh1+dh2 + dh3 + dh4, 32)
    print(sk)
    print('[Bob]\tShared key:', b64(sk))
    #shared_key= b64(sk)
    return sk 


def recv_x3dh_hello_message():
    res=requests.get('http://127.0.0.1:5000/getMessage')
    dataa=res.json()['message']
    data=decode(dataa)
    IK_pa = data[:EC_KEY_LEN]
    EK_pa = data[EC_KEY_LEN:EC_KEY_LEN*2]
    OPK_pb = data[EC_KEY_LEN*2:EC_KEY_LEN*3]
    nonce = data[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
    tag = data[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
    ciphertext = data[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]
    #l=decode(IK_pa)
    #ll=b64(l)
    #print(ll)
    loaded_public_key = load_public(IK_pa)
    #s=toString1(loaded_public_key)
    IK_p=toString1(loaded_public_key)
    #verification if IKa_p in message match IK_p in server
    if (IK_p != extract('alice')['IKa_p']):
        print("Key in hello message doesn't match key from server")
        return
    else:
        print('ok')

    

def x3dh_decrypt_and_verify():
    res=requests.get('http://127.0.0.1:5000/getMessage')
    dataa=res.json()['message']
    data=decode(dataa)
    tag = data[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
    nonce = data[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
    ciphertext = data[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]
    IK_pa = data[:EC_KEY_LEN]
    EK_pa = data[EC_KEY_LEN:EC_KEY_LEN*2]
    OPK_pb = data[EC_KEY_LEN*2:EC_KEY_LEN*3]


    cipher = AES.new(x3dh1('alice'), AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
    #print(cipher)
    try:
        p_all=cipher.decrypt_and_verify(ciphertext,tag)
        print(p_all)

    except ValueError:
        print('unbale to verify/decrypt cipher text')


    sign = p_all[:EC_SIGN_LEN]
    IK_pa_p = p_all[EC_SIGN_LEN:EC_SIGN_LEN+EC_KEY_LEN]
    IK_pb_p = p_all[EC_SIGN_LEN+EC_KEY_LEN:EC_SIGN_LEN+EC_KEY_LEN*2]
    ad = p_all[EC_SIGN_LEN+EC_KEY_LEN*2:]
    ###
    loaded_public_key = load_public(IK_pa_p)
    IKa_p=toString1(loaded_public_key)
    ####
    loaded=load_public(IK_pb_p)
    IKp_p=toString1(loaded)
    ####
    loaded_public_k = load_public(IK_pa)
    #s=toString1(loaded_public_key)
    IK_pa=toString1(loaded_public_k)
    IKpa_p=dump_publickey(toPublic(extract('alice')['IKa_p']))
    EKa_p=dump_publickey(toPublic(extract('alice')['EKa_p']))
    OPKb_p=dump_publickey(toPublic(extract('bob')['OPKb_p']))
    try:
        if (IKa_p != IK_pa and IKp_p != extract('bob')['IKb_p']):
            print("Keys from header and ciphertext not match")
            return "false"

    except:
        print("all goes well")

    '''sig_p=toPublic1(extract('alice')['Sig_p'])
    if not sig_p.verify( sign,   IKpa_p + EKa_p + OPKb_p+ad):
        print("Unable to verify the message signature")
        return
    else:
        print('ok')'''

    



   
    









#---------------------------------------------CLIENT2--------------------------------------------

def client2():


        
        bundle2=dict()   
        IKa= X25519PrivateKey.generate()
        EKa= X25519PrivateKey.generate()
        Sig= Ed25519PrivateKey.generate()
        

        
        IKa_p=IKa.public_key()
        EKa_p=EKa.public_key()
        Sig_p=Sig.public_key()
        bundle2['IKa']=toString2(IKa)
        print(bundle2)
        bundle2['EKa']=toString2(EKa)
        bundle2['Sig']=toString2(Sig)
        
    
        try:
            with open ("/home/ayoub/devHacking/python/api/keys.txt","a") as m:
                json.dump(bundle2,m)
                #print(request.data)
                m.write('\n')
            
        except(error):
            print(error)
        
        list=[IKa_p,EKa_p,Sig_p]
        print(list)
        return list 



#PUBLISH PUBLIC KEYS
def publish2(name,lis):
        list=reform(lis)
        print(list)
        x=dict()
        x["name"]=name
        x["IKa_p"]=list[0]
        x["EKa_p"]=list[1]
        x["Sig_p"]=list[2]
        print(x)
        
        #print(json.dumps(x))
        #requests.post('http://127.0.0.1:5000/login/Bob',json=x, timeout=5)
        return x 




#X3DH
def x3dh2(name):

    data=extract(name)
    print(data)

    k1=data['SPKb_p']
    k2=data['IKb_p']
    k3=data['OPKb_p']
            
            
    '''key1=base64.b16decode(k1.encode())
    key2=base64.b16decode(k2.encode())
    key3=base64.b16decode(k3.encode())
            #print(key1)
    k1=X25519PublicKey.from_public_bytes(key1)
    k2=X25519PublicKey.from_public_bytes(key2)
    k3=X25519PublicKey.from_public_bytes(key3)'''
    k1=toPublic(k1)
    k2=toPublic(k2)
    k3=toPublic(k3)
        #s=k1.public_bytes(
                        #encoding=serialization.Encoding.Raw,
                        #format=serialization.PublicFormat.Raw)
            #print(l)
            #print(s)
            #string=base64.b16encode(s).decode()
            #print(string)
                
                
            #alice=Alice()
            #alice.x3dh(k1,k2,k3)
            #bob.x3dh(alice)
    keys=dict()
    keys['SPKb_p']=k1
    keys['IKb_p']=k2
    keys['OPKb_p']=k3
    print(keys)
        #list.append(k1)
        #list.append(k2)
        #list.append(k3)
    #print(keys)
    #return keys
    dh1 = toPrivate(loadPrivate2()['IKa']).exchange(keys['SPKb_p'])    #bob.SPKb.public_key())
    dh2 = toPrivate(loadPrivate2()['EKa']).exchange(keys['IKb_p'])#bob.IKb.public_key())
    dh3 = toPrivate(loadPrivate2()['EKa']).exchange(keys['SPKb_p'])#bob.SPKb.public_key())
    dh4 = toPrivate(loadPrivate2()['EKa']).exchange(keys['OPKb_p'])#bob.OPKb.public_key())
        # the shared key is KDF(DH1||DH2||DH3||DH4)
    sk = hkdf( dh1+dh2 + dh3 + dh4, 32)
    print(sk)
    print('[Alice]\tShared key:', b64(sk))
    #print(len(b64(sk)))
    #print(len(sk))
    return  sk




def build_x3dh_hello(name,to,ad):
    # Binary additional data
    b_ad = (json.dumps({
      'from': name,
      'to': to,
      'message': ad
    })).encode('utf-8')
    print(type(b_ad))
    
    key_comb = dump_publickey(toPublic(extract('alice')['IKa_p'])) + dump_publickey(toPublic(extract('alice')['EKa_p'])) +dump_publickey(toPublic(extract('bob')['OPKb_p']))
    
    print(key_comb)
    privateSig=loadPrivate2()["Sig"]
    privSig=toPrivate1(privateSig)
    #print(privateSig)
    signature = privSig.sign( key_comb + b_ad)
    
    print("Alice message signature: ", b64(signature))
    print("data: ", key_comb + b_ad)
    nonce = get_random_bytes(AES_N_LEN)
    print(len(nonce))
    cipher = AES.new(x3dh2('bob'), AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
    print(cipher)
    # 32 + 32 + len(ad) byte cipher text
    ciphertext, tag = cipher.encrypt_and_digest(signature + dump_publickey(toPublic(extract('alice')['IKa_p']))+dump_publickey(toPublic(extract('bob')['IKb_p']))+b_ad)

    # initial message: (32 + 32 +32) + 16 + 16 + 64 + 32 + 32 + len(ad)
    message = key_comb + nonce + tag + ciphertext
    print(message)
    mesg=encode(message)
    """msg=mesg.encode('ascii')
    m=base64.decodebytes(msg)"""
    
    msg=dict()
    msg['message']=mesg
    msg['flag']=1
    print(msg)
    print(mesg)
    ss=decode(mesg)
    print(ss)
    s=ss[:32]
    loaded_public_key = X25519PublicKey.from_public_bytes(s)
    print(loaded_public_key)
    k=toString1(loaded_public_key)
    print(k)

    return msg

sk=b'\x06\xcd\xd1\x16>\xab\xf1\x14\xd8\x8e0\xc9;\xf4?\xe5W\xee\xb0\x8an\xcf\x99}P\xe63\xd6%\x1de"'
###############################double ratchat algorithm#########################
class Alice(object):
    def __init__(self):
        # Alice's DH ratchet starts out uninitialised
        self.DHratchet = None

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(sk)
        # initialise the sending and recving chains
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self):
        # perform a DH ratchet rotation using Bob's public key
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.DHratchet.exchange(toPublic(getMessage('bob')["public_key"]))
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = SymmRatchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = X25519PrivateKey.generate()
        print(getMessage('bob')["public_key"])
        dh_send = self.DHratchet.exchange(toPublic(getMessage('bob')["public_key"]))
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))
        


    def send(self,  msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print(type(cipher))
        print(cipher)
        print(type(b64(cipher)))
        c=b64(cipher)
        print(c)
        cc=base64.b64decode(c)
        print(cc)
        print(type(cc))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        # send ciphertext and current DH public key
        print(self.DHratchet.public_key())
        x=dict()
        x["public_key"]=toString1(self.DHratchet.public_key())
        x["ciphertext"]=b64(cipher)
        x["from"]="alice"
        x["to"]="bob"
        x["flag"]=1
        requests.post('http://127.0.0.1:5000/postCipher',json=x)
        #bob.recv(cipher, self.DHratchet.public_key())
        #updateFlag('bob')

    def recv(self):
        # receive Bob's new public key and use it to perform a DH
        self.dh_ratchet()
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(unb64(getMessage('bob')["ciphertext"])))
        print('[Alice]\tDecrypted message:', msg)
        updateFlag('bob')



class Bob(object):
    def __init__(self):
        
        # initialise Bob's DH ratchet
        self.DHratchet = X25519PrivateKey.generate()
        x=dict()
        x["public_key"]=toString1(self.DHratchet.public_key())
        x["ciphertext"]=''
        x["from"]="bob"
        x["to"]="alice"
        x["flag"]=1

        requests.post('http://127.0.0.1:5000/postCipher',json=x)


    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(sk)
        # initialise the sending and recving chains
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    

    def dh_ratchet(self):
        # perform a DH ratchet rotation using Alice's public key
        dh_recv = self.DHratchet.exchange(toPublic(getMessage('alice')["public_key"]))
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        # use Alice's public and our old private key
        # to get a new recv ratchet
        self.recv_ratchet = SymmRatchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Alice
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(toPublic(getMessage('alice')["public_key"]))
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))

    def send(self,  msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice:', b64(cipher))
        # send ciphertext and current DH public key to server 
        x=dict()
        x["public_key"]=toString1(self.DHratchet.public_key())
        x["ciphertext"]=b64(cipher)
        x["from"]="bob"
        x["to"]="alice"
        x["flag"]=1
        requests.post('http://127.0.0.1:5000/postCipher',json=x)
        #updateFlag('alice')

        
        #alice.recv(cipher, self.DHratchet.public_key())

    def recv(self):
        # receive Alice's new public key and use it to perform a DH
        self.dh_ratchet()
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(unb64(getMessage('alice')["ciphertext"])))
        print('[Bob]\tDecrypted message:', msg)
        updateFlag('alice')

        





#extract("alice")
#requests.post('http://127.0.0.1:5000/login',json=publish2("alice",client2()))
#requests.post('http://127.0.0.1:5000/login',json=publish1("bob",client1()))
#requests.post('http://127.0.0.1:5000/postMessage',json=build_x3dh_hello('alice','bob','hello'))
#publish2("alice",client2())
#x3dh("bob")
#x3dh2("bob")
#
#x3dh1("alice")
#client1()
#client2()
#print(bundle2)
#s=toPrivate(loadPrivate2()['EKa'])
#print(s)

#build_x3dh_hello("alice","bob","hello")

'''data=extract("bob")
print(data)
a=toPublic(data["OPKb_p"])
print(a)
c=dump_publickey(a)
print(c)'''
#build_x3dh_hello("alice","bob","hello")
#recv_x3dh_hello_message()
#x3dh_decrypt_and_verify()
#dh_ratchet(x3dh2('bob'))
#getMessage('alice')

alice = Alice()
bob = Bob()
alice.init_ratchets()
bob.init_ratchets()
alice.dh_ratchet()
updateFlag('bob')
alice.send( b'Hello Bob!')
bob.recv()
'''bob.send( b'Hello alice!')
alice.recv()'''
alice.send( b'How are you!')
bob.recv()
'''bob.send(b'fine')
alice.recv()'''
'''bob.send(b'hello alice')
alice.recv()
alice.send(b'how are you')
bob.recv()
#alice.send(b'fine thank you')
#bob.recv()'''


#getMessage('bob')
#updateFlag('alice')