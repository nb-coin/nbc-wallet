# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

from random import randint

from .. import util
from ..util.ecdsa import SECP256k1 as curve
from ..util.ecdsa.util import string_to_number, number_to_string, randrange

import getpass
from binascii import hexlify, unhexlify
from ..util.pyaes.aes import AESModeOfOperationCBC as AES

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def _aesEncrypt(sText, passphrase):
  if type(passphrase) != bytes:
    passphrase = passphrase.encode('utf-8')
  passphrase = passphrase[:16].ljust(16,b'\x00')
  aes = AES(passphrase)
  
  m,n = divmod(len(sText),16)
  if n:
    sText = sText + b'\x00' * (16 - n)  # align to 16 * N
    m += 1
  
  sEncoded = b''; iFrom = 0
  for i in range(m):
    sEncoded += aes.encrypt(sText[iFrom:iFrom+16])
    iFrom += 16
  return sEncoded

def _aesDecrypt(sText, passphrase=''):
  m,n = divmod(len(sText),16)
  if m == 0 or m >= 16 or n != 0:  # encrypted text should be 16 * N
    raise ValueError('invalid encrypted text')
  
  while not passphrase:
    passphrase = getpass.getpass('Passphrase:').strip()
  if type(passphrase) != bytes:
    passphrase = passphrase.encode('utf-8')
  passphrase = passphrase[:16].ljust(16,b'\x00')
  aes = AES(passphrase)
  
  sDecoded = b''; iFrom = 0
  for i in range(m):
    sDecoded += aes.decrypt(sText[iFrom:iFrom+16])
    iFrom += 16
  return sDecoded

def _keyFromPoint(point, compressed):
  'Converts a point into a key.'
  key = ( b'\x04' +
          number_to_string(point.x(),curve.order) +
          number_to_string(point.y(),curve.order) )
  if compressed:
    key = util.key.compress_public_key(key)
  return key

class Address(object):
  def __init__(self, pub_key=None, priv_key=None, vcn=0, coin_type=b'\x00', testnet=False):
    self._compressed = False
    self._priv_key = priv_key
    self._coin_type = coin_type
    self._testnet = testnet
    
    if priv_key:
      if pub_key is not None:
        raise ValueError('cannot specify public and private key both')
      assert(type(priv_key) == bytes)
      
      # this is a compressed private key
      ch = ORD(priv_key[0])
      if ch == 76 or ch == 75:  # 76 is 'L', 75 is 'K'
        self._compressed = True
      elif ch != 53:            # 53 is '5'
        raise ValueError('unknown private key type: %r' % priv_key[0])
      
      secexp = string_to_number(util.key.privkey_from_wif(self._priv_key))
      point = curve.generator * secexp
      pub_key = _keyFromPoint(point,False)
    else: self._priv_key = None
    
    if pub_key:
      assert(type(pub_key) == bytes)
      
      ch = ORD(pub_key[0])
      if ch == 4:  # prefix with 0x04 means decompressed
        if len(pub_key) != 65:
          raise ValueError('invalid uncomprssed public key')
      elif ch == 2 or ch == 3:
        pub_key = util.key.decompress_public_key(pub_key)
        self._compressed = True
      else:
        raise ValueError('invalid public key')
      self._pub_key = pub_key
    else:
      raise ValueError('no address parameters')
    
    if vcn is None:
      self._vcn = vcn
    else: self._vcn = int(vcn) & 0xffff
    
    # public address
    ver = b'\x6f' if self._testnet else b'\x00'
    self._address = util.key.publickey_to_address(self.publicKey(),self._vcn,self._coin_type,version=ver)
  
  pub_key  = property(lambda s: s._pub_key)
  priv_key = property(lambda s: s._priv_key)
  vcn      = property(lambda s: s._vcn)       # vcn maybe None, for old bitcoin system
  coin_type  = property(lambda s: s._coin_type)
  compressed = property(lambda s: s._compressed)
  testnet = property(lambda s: s._testnet)
  
  def address(self):
    return self._address
  
  def publicHash(self):   # according to compressed
    return util.key.publickey_to_hash(self.publicKey(),self._vcn)
  
  def publicKey(self):    # according to compressed
    return util.key.compress_public_key(self._pub_key)
  
  def _priv_key_(self):
    if self._priv_key is None:
      return None
    return util.key.privkey_from_wif(self.priv_key)  # the binary representation of private
  
  @staticmethod
  def generate(vcn=0, coin_type=b'\x00', testnet=False, compressed=True): # suggest only using compressed address
    'Generate a new random address.'
    secexp = randrange(curve.order)              # return: 1 <= k < order
    key = number_to_string(secexp,curve.order)   # get 32 bytes number
    if compressed:
      key = key + b'\x01'
    return Address(priv_key=util.key.privkey_to_wif(key),vcn=vcn,coin_type=coin_type,testnet=testnet)
  
  def decompress(self):  # convert to decompressed
    if not self._compressed: return self
    
    if self._priv_key:
      return Address(priv_key=util.key.privkey_to_wif(self._priv_key_()),vcn=self._vcn,coin_type=self._coin_type,testnet=self._testnet)
    if self._pub_key:
      return Address(pub_key=util.key.decompress_public_key(self._pub_key),vcn=self._vcn,coin_type=self._coin_type,testnet=self._testnet)
    raise ValueError('address cannot be decompressed')
  
  def compress(self):    # convert to compress
    if self._compressed: return self
    
    if self._priv_key:
      return Address(priv_key=util.key.privkey_to_wif(self._priv_key_()+b'\x01'),vcn=self._vcn,coin_type=self._coin_type,testnet=self._testnet)
    if self._pub_key:
      return Address(pub_key=util.key.compress_public_key(self._pub_key),vcn=self._vcn,coin_type=self._coin_type,testnet=self._testnet)
    raise ValueError('address cannot be compressed')
  
  def _get_priv(self):
    if self._priv_key is None: raise ValueError('invalid private key')
    return util.key.privkey_from_wif(self._priv_key)
  
  def sign(self, data):  # signs data with private key
    pk = self._get_priv()
    return util.ecc.sign(data,pk)
  
  def verify(self, data, signature):  # verifies data and signature with public key
    if self._pub_key is None: raise ValueError('invalid public key')
    return util.ecc.verify(data,self._pub_key,signature)
  
  def __str__(self):
    privateKey = 'None'
    if self._priv_key: privateKey = '**redacted**'
    return '<Address address=%s private=%s>' % (self._address,privateKey)
  
  def dump_to_cfg(self, passphrase=''):
    cfg = { 'encrypted': False, 'type': 'default',
      'vcn': self._vcn,
      'coin_type': hexlify(self._coin_type).decode('latin-1'),  # hexlify char is '0-f'
      'testnet': self._testnet,
      'prvkey': None, 'pubkey': None,
    }
    
    privKey = self._priv_key; pubKey = self._pub_key
    if privKey:
      assert(len(privKey) <= 255)
      privKey = (b'%02x' % len(privKey)) + privKey
      
      if passphrase:
        privKey = _aesEncrypt(privKey,passphrase)
        cfg['encrypted'] = True
      
      cfg['prvkey'] = hexlify(privKey).decode('latin-1')
    elif pubKey:
      cfg['pubkey'] = hexlify(pubKey).decode('latin-1')
    return cfg
  
  @staticmethod
  def load_from_cfg(cfg, passphrase=''):
    pubKey = cfg['pubkey']; prvKey = cfg['prvkey']
    if prvKey:
      prvKey = unhexlify(prvKey)
      if cfg.get('encrypted'):
        prvKey = _aesDecrypt(prvKey,passphrase)
      
      try:
        orgLen = int(prvKey[:2],16); nowLen = len(prvKey)
        if nowLen < 2 + orgLen or nowLen > orgLen + 17:   # 17 is 2 + padding(15)
          raise ValueError('out of range')
        prvKey = prvKey[2:2+orgLen]  # first 2 bytes is original length
      except:
        raise ValueError('invalid private key')
    elif pubKey:
      pubKey = unhexlify(pubKey)
    
    coin_type = unhexlify(cfg['coin_type'])
    return Address(pub_key=pubKey,priv_key=prvKey,vcn=cfg['vcn'],coin_type=coin_type,testnet=cfg['testnet'])
