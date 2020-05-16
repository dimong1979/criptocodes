import os, binascii, hashlib, base58, ecdsa

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

priv_key = os.urandom(32)
#print(priv_key.encode('hex'))

ptwifprefix = '\x80' + priv_key
#print(ptwifprefix.encode('hex'))

wif1sha256 = hashlib.sha256(ptwifprefix)
#print(wif1sha256.digest().encode('hex'))

wif2sha256 = hashlib.sha256(wif1sha256.digest())                                         
#print(wif2sha256.digest().encode('hex'))

wifchecksum = wif2sha256.digest()[:4]
#print( wifchecksum.encode('hex') )

addwifchecksum = ptwifprefix + wifchecksum
#print( addwifchecksum.encode('hex') )

WIF = base58.b58encode( addwifchecksum )
print("Wallet Import Format " + WIF)

sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
vk = sk.verifying_key
pubKey=('\04'+sk.verifying_key.to_string()) 
#print( pubKey.encode('hex') )

ptafirstsha256 = hashlib.sha256(pubKey)
#print( ptafirstsha256.digest().encode('hex') )

hash160 = ripemd160( ptafirstsha256.digest() )
#print( hash160.digest().encode('hex') )

ptaprefix = '\x00'+hash160.digest()
#print( ptaprefix.encode('hex') )

ptasecondsha256 = hashlib.sha256(ptaprefix)
#print(ptasecondsha256.digest().encode('hex'))

ptathirdsha256 = hashlib.sha256(ptasecondsha256.digest())
#print(ptathirdsha256.digest().encode('hex') )

checksum = ptathirdsha256.digest()[:4]
#print( checksum.encode('hex') )

addchecksum = ptaprefix + checksum
#print( addchecksum.encode('hex') )

public_address = base58.b58encode( addchecksum )
print( public_address )

