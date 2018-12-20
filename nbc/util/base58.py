# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from hashlib import sha256

__all__ = ['decode_check', 'encode_check']

# 58 character alphabet, from https://bitcointalk.org/index.php?topic=1026.0
alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

if bytes == str:  # python2
  iseq, bseq, buffer = (
    lambda s: map(ord,s),
    lambda s: ''.join(map(chr,s)),
    lambda s: s )
else:  # python3
  iseq, bseq, buffer = (
    lambda s: s,
    bytes,
    lambda s: s.buffer )

def scrub_input(v):
  if isinstance(v,str) and not isinstance(v,bytes):
    v = v.encode('ascii')
  if not isinstance(v, bytes):
    raise TypeError("a bytes-like object is required, not '%s'" % type(v).__name__)
  return v

def b58encode_int(i, default_one=True):
  '''encode an integer using base58'''
  
  if not i and default_one:  # i can not be 0
    return alphabet[0:1]
  s = b''
  while i:
    i,idx = divmod(i,58)
    s = alphabet[idx:idx+1] + s
  return s

def b58encode(v):
  '''encode a string using base58'''
  
  v = scrub_input(v)
  nPad = len(v)
  v = v.lstrip(b'\x00')
  nPad -= len(v)
  
  p,acc = 1,0
  for c in iseq(reversed(v)):
    acc += p * c
    p = p << 8
  
  ret = b58encode_int(acc,default_one=False)
  return (alphabet[0:1] * nPad + ret)

def b58decode_int(v):
  '''decode a base58 encoded string as an integer'''
  
  v = scrub_input(v)
  decimal = 0
  for ch in v:
    decimal = decimal*58 + alphabet.index(ch)
  return decimal

def b58decode(v):
  '''decode a base58 encoded string'''
  
  v = scrub_input(v)
  origlen = len(v)
  v = v.lstrip(alphabet[0:1])
  newlen = len(v)
  
  acc = b58decode_int(v)
  
  ret = []
  while acc > 0:
    acc, mod = divmod(acc, 256)
    ret.append(mod)
  
  return (b'\0' * (origlen - newlen) + bseq(reversed(ret)))

def encode_check(v):
  '''encode a string using base58 with a 4 character checksum'''
  
  digest = sha256(sha256(v).digest()).digest()
  return b58encode(v + digest[:4])

def decode_check(v):
  '''decode and verify the checksum of a base58 encoded string'''
  
  ret = b58decode(v)
  ret, check = ret[:-4], ret[-4:]
  digest = sha256(sha256(ret).digest()).digest()
  
  if digest[:4] == check:
    return ret
  else: return None
