# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

from random import randint
import hashlib, hmac
from binascii import hexlify, unhexlify

from .. import util
from ..util import base58, ecc
from ..util.ecdsa import numbertheory, ellipticcurve, curves
from ..util.ecdsa import SECP256k1 as curve
from ..util.ecdsa.util import number_to_string, string_to_number

from .address import _aesEncrypt, _aesDecrypt

def CHR(i):    # compatible to python3
  return bytes(bytearray((i,)))

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def hash_160(public_key):
  h256 = hashlib.sha256(public_key).digest()
  return hashlib.new('ripemd160',h256).digest()

def point_compress(point):
  x = point.x(); y = point.y()
  curve = point.curve()
  return CHR(2 + (y & 1)) + number_to_string(x,curve.p())

def point_decompress(curve, data):
  prefix = data[0]; ch = ORD(prefix)
  assert(ch in (2,3))  # data[0] should be b'\x02' or b'\x03'
  parity = 1 if ch == 2 else -1
  
  x = string_to_number(data[1:])
  y = numbertheory.square_root_mod_prime( 
    ( x * x * x + curve.a() * x + curve.b() ) % curve.p(),  curve.p()
  )
  y = parity * y % curve.p()
  return ellipticcurve.Point(curve, x, y)

class HDWallet(object):
  _chain  = None   # ByteSeq
  _pubkey = None   # ellipticcurve.Point
  
  _prvkey = None   # Int
  _testnet = None
  
  _depth    = None
  _parentfp = None
  _childnum = None
  
  def __init__(self, key, chain, vcn=0, coin_type=b'\x00', testnet=False, depth=None, parentfp=None, childnum=None):
    if type(key) == ellipticcurve.Point:        # public key is a point
      self._pubkey = key  
    elif type(key) == int or type(key) == long: # private key an integer
      assert(0 < key < curve.order)
      self._prvkey = key
    else:
      raise TypeError('Unknown key type "{0}"'.format(type(key)))
    
    assert(len(chain) == 32)
    self._chain = chain
    self._coin_type = coin_type
    self._testnet = testnet
    
    if vcn is None:
      self.vcn = vcn  # for bitcoin
    else: self.vcn = int(vcn) & 0xffff
    
    if depth == None: # master wallet
      depth = 0
      parentfp = b'\x00' * 4
      childnum = 0
    assert(depth < 256)
    
    self._depth = depth
    self._parentfp = parentfp
    self._childnum = childnum
  
  coin_type  = property(lambda s: s._coin_type)
  
  def child(self, i):
    assert(0 <= i <= 2**32-1)
    priv_deriv = (i & 0x80000000) != 0
    
    if (priv_deriv and not self._prvkey):
      raise Exception('Unable to do private derivation')
    
    # only allow up to a depth of 255
    assert(self._depth < 0xff)
    
    str_i = number_to_string(i,2**32-1)
    
    if priv_deriv:
      str_k = number_to_string(self._prvkey,curve.order)
      deriv = hmac.new(key=self._chain, msg=b'\x00' + str_k + str_i, digestmod=hashlib.sha512).digest()
    else:
      str_K = point_compress(self.point())
      deriv = hmac.new(key=self._chain, msg=str_K + str_i, digestmod=hashlib.sha512).digest()
    
    childChain = deriv[32:]
    childModifier = string_to_number(deriv[:32])
    
    if childModifier >= curve.order:
      raise Exception('This is higly unprovable IL >= n, but it did happen')
    
    if self._prvkey:
      childPrvkey = (self._prvkey + childModifier) % curve.order 
      if childPrvkey == 0:
        raise Exception('This is higly unprovable ki = 0, but it did happen')
      
      childKey = childPrvkey
    else: 
      childPubkey = self.point() + curve.generator * childModifier
      if childPubkey == ellipticcurve.INFINITY:
        raise Exception('This is higly unprovable Ki = INFINITY, but it did happen')
      
      childKey = childPubkey
    
    return self.__class__(childKey, childChain, 
      testnet=self._testnet,
      depth=self._depth + 1,
      parentfp=self.fingerprint(),
      childnum=i)
      
  def to_extended_key(self, include_prv=False):
    if not self._testnet:
      version = 0x0488B21E if not include_prv else 0x0488ADE4  # 0x0488B21E for BIP-32 extended public key (xpub)
    else:
      version = 0x043587CF if not include_prv else 0x04358394
    
    version  = number_to_string(version,2**32-1)
    depth    = number_to_string(self._depth,2**8-1)
    parentfp = self.parentfp()
    childnum = number_to_string(self._childnum,2**32-1)
    chaincode = self._chain
    
    if include_prv:
      if self._prvkey == None: raise Exception('unknown private key')
      data = b'\x00' + number_to_string(self._prvkey,curve.order)
    else:
      # compress point
      data = point_compress(self.point())
    
    ekdata = b''.join([version, depth, parentfp, childnum, chaincode, data])
    checksum = hashlib.sha256(hashlib.sha256(ekdata).digest()).digest()[:4]
    return base58.b58encode(ekdata + checksum)
  
  def point(self):
    if not self._pubkey:
      self._pubkey = curve.generator * self._prvkey
    return self._pubkey
  
  def pubkey(self):
    x_str = number_to_string(self.point().x(),curve.order)
    y_str = number_to_string(self.point().y(),curve.order)
    return x_str + y_str
  
  def prvkey(self):
    if self._prvkey:
      return number_to_string(self._prvkey,curve.order)
    return None
  
  def chain(self):
    return self._chain
  
  def address(self, version=None):  # only support compressed address
    if version == None:
      version = b'\x00' if not self._testnet else b'\x6f'
    return util.key.publickey_to_address(point_compress(self.point()),self.vcn,self._coin_type,version)
  
  def publicKey(self):
    return point_compress(self.point())
  
  def publicHash(self):
    return util.key.publickey_to_hash(point_compress(self.point()),self.vcn)
  
  def depth(self):
    return self._depth
  
  def fingerprint(self):
    return hash_160(point_compress(self.point()))[:4]
  
  def parentfp(self):
    if self._depth == 0: # master node has no parent
      return b'\x00' * 4
    return self._parentfp
  
  def childnum(self):
    return self._childnum
  
  def _get_priv(self):
    prvKey = self.prvkey()
    if not prvKey:
      raise ValueError('invalid private key')
    return prvKey
  
  def sign(self, data):
    pk = self._get_priv()
    return ecc.sign(data,pk)
  
  def verify(self, data, signature):
    pt = self.point()
    pubKey = ( b'\x04' +
          number_to_string(pt.x(),curve.order) +
          number_to_string(pt.y(),curve.order) )
    return ecc.verify(data,pubKey,signature)
  
  @staticmethod
  def from_extended_key(extended_key, vcn=0, coin_type=b'\x00'):
    decoded = base58.b58decode(extended_key,78+4)
    assert(decoded)
    ekdata = decoded[:78]
    checksum = decoded[78:78+4]
    # validate checksum
    valid_checksum = hashlib.sha256(hashlib.sha256(ekdata).digest()).digest()[:4]
    assert (checksum == valid_checksum)
    
    version = string_to_number(ekdata[0:0+4])
    depth   = string_to_number(ekdata[4:4+1])
    parentfp = ekdata[5:5+4]
    childnum = string_to_number(ekdata[9:9+4])
    chaincode = ekdata[13:13+32]
    data = ekdata[45:45+33]
    
    testnet = version in (0x043587CF, 0x04358394)
    
    if version in (0x0488B21E, 0x043587CF): # data contains pubkey
      assert(ORD(data[0]) in (2,3))
      key = point_decompress(curve.curve,data)
    elif version in (0x0488ADE4, 0x04358394): # data contains privkey
      assert(ORD(data[0]) == 0)
      key = string_to_number(data[1:])
    else:
      raise Exception('unknown version')
    
    return HDWallet( key, chaincode, vcn=vcn, coin_type=coin_type,
      testnet=testnet, depth=depth,
      childnum=childnum, parentfp=parentfp )
  
  @staticmethod
  def from_master_seed(master_seed, vcn=None, coin_type=b'\x00', testnet=False):
    if type(master_seed) != bytes:
      master_seed = master_seed.encode('latin-1')
    
    deriv = hmac.new(key=b'Newbitcoin seed', msg=master_seed, digestmod=hashlib.sha512).digest()
    master_key = string_to_number(deriv[:32]) % curve.order
    if master_key == 0: raise ValueError('zeror key, try again')
    master_chain = deriv[32:]
    return HDWallet(master_key, master_chain, vcn=vcn, coin_type=coin_type, testnet=testnet)
  
  def dump_to_cfg(self, passphrase=''):
    cfg = { 'encrypted': False, 'type': 'HD',
      'chain': hexlify(self._chain).decode('latin-1'),
      'vcn': self.vcn,
      'coin_type': hexlify(self._coin_type).decode('latin-1'),
      'testnet': self._testnet,
      'depth': self._depth,
      'parentfp': hexlify(self.parentfp()).decode('latin-1'),
      'childnum': self._childnum,
    }
    
    if self._prvkey:   # int or long, can not be 0
      sPrv = number_to_string(self._prvkey,curve.order)
      assert(len(sPrv) <= 255)
      sPrv = (b'%02x' % len(sPrv)) + sPrv
      
      if passphrase:
        sPrv = _aesEncrypt(sPrv,passphrase)
        cfg['encrypted'] = True
      
      cfg['prvkey'] = hexlify(sPrv).decode('latin-1')
      cfg['pubkey'] = None
    elif self._pubkey:
      cfg['prvkey'] = None
      cfg['pubkey'] = hexlify(point_compress(self._pubkey)).decode('latin-1')
    return cfg
  
  @staticmethod
  def load_from_cfg(cfg, passphrase=''):
    prvKey = cfg['prvkey']; pubKey = cfg['pubkey']
    if prvKey:
      prvKey = unhexlify(prvKey)
      if cfg.get('encrypted'):
        prvKey = _aesDecrypt(prvKey,passphrase)
      
      try:
        orgLen = int(prvKey[:2],16); nowLen = len(prvKey)
        if nowLen < 2 + orgLen or nowLen > orgLen + 17:   # 17 is 2 + padding(15)
          raise ValueError('out of range')
        prvKey = prvKey[2:2+orgLen]      # first 2 bytes is original length
      except:
        raise ValueError('invalid private key')
      prvKey = string_to_number(prvKey)  # prvKey must not be 0
    elif pubKey:
      pubKey = point_decompress(curve.curve,unhexlify(pubKey))
    
    return HDWallet( prvKey or pubKey, unhexlify(cfg['chain']), vcn=cfg['vcn'],
      coin_type=unhexlify(cfg['coin_type']), testnet=cfg['testnet'], depth=cfg['depth'],
      childnum=cfg['childnum'], parentfp=unhexlify(cfg['parentfp']) )
  
  def __str__(self):
    privateKey = 'None'
    if self._prvkey: privateKey = '**redacted**'
    return '<HD address=%s private=%s>' % (self.address(),privateKey)

def main():
  # 1. generate a master wallet with a (random) seed 
  master = HDWallet.from_master_seed('HDWallet seed')
  # 2. store the Private Extended Key somewhere very (!) safe
  prv_master_key = master.to_extended_key(include_prv=True)
  # 3. store the Public Extended Key on the webserver
  pub_master_key = master.to_extended_key()
  
  # 4. On the webserver we can generate child wallets, 
  webserver_wallet = HDWallet.from_extended_key(pub_master_key)
  child2342 = webserver_wallet.child(23).child(42)
  print('- Public Extended Key (M):',pub_master_key)
  print('Child: M/23/42')
  print('Address:',child2342.address())
  print('Privkey:',child2342.prvkey()) # ... but the private keys remain _unknown_
  print('')
  
  # 5. In case we need the private key for a child wallet, start with the private master key
  cold_wallet = HDWallet.from_extended_key(prv_master_key)
  child2342 = cold_wallet.child(23).child(42)
  print('- Private Extended Key (m):',prv_master_key)
  print('Child: m/23/42')
  print('Address:',child2342.address())
  print('Privkey:',hexlify(child2342.prvkey()))

if __name__ == "__main__":
  main()
