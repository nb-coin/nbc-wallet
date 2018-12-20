# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import operator

__all__ = ['ByteVector']

import six
from binascii import hexlify

if six.PY3:
  def make_long(x):
    return int(x)
else:
  make_long = long

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def CHR(i):    # compatible to python3
  return bytes(bytearray((i,)))

def get_vector(value):  # convert an integer into a byte-vector string
  if value == 0: return b''
  
  vector = []
  sign = 1
  if value < 1:
    sign = -1
    value *= -1
  
  while value:
    vector.insert(0,value % 256)
    value //= 256
  
  if vector[0] & 0x80:
    vector.insert(0,0)
  
  if sign == -1:
    vector[0] |= 0x80
  return b''.join(CHR(c) for c in vector)

def get_value(vector):  # convert a byte-vector string into an integer
  if len(vector) == 0:
    return 0
  
  vector = [ORD(c) for c in vector]
  
  sign = 1
  if vector[0] & 0x80:
    vector[0] = (vector[0] & 0x7f)
    sign = -1
  
  value = 0
  for c in vector:
    value *= 256
    value += c
  
  return sign * value

class ByteVector(object):
  def __init__(self, vector=b''):
    self.set_vector(vector)
  
  value = property(lambda s: s.__value)
  vector = property(lambda s: s.__vector)
  
  def set_value(self, value):    # by value
    self.__vector = get_vector(value)
    self.__value = value
  
  def set_vector(self, vector):  # by byte string
    self.__value = get_value(vector)
    self.__vector = vector
  
  @staticmethod
  def from_value(value):
    return ByteVector(get_vector(value))
  
  # Binary operators
  
  def __add__(self, other):
    return ByteVector.from_value(self.value + other.value)
  
  def __sub__(self, other):
    return ByteVector.from_value(self.value - other.value)
  
  def __mul__(self, other):
    return ByteVector.from_value(self.value * other.value)
  
  def __floordiv__(self, other):
    return ByteVector.from_value(self.value // other.value)
  
  def __mod__(self, other):
    return ByteVector.from_value(self.value % other.value)
  
  def __divmod__(self, other):  # how to use?
    return ByteVector.from_value(divmod(self.value, other.value))
  
  def __pow__(self, other, modulo = None):
    if modulo is None:
      return ByteVector.from_value(pow(self.value, other.value))
    return ByteVector.from_value(pow(self.value, other.value, modulo))
  
  def __lshift__(self, other):
    return ByteVector.from_value(self.value << other.value)
  
  def __rshift__(self, other):
    return ByteVector.from_value(self.value >> other.value)
  
  def __and__(self, other):
    return ByteVector.from_value(self.value & other.value)
  
  def __xor__(self, other):
    return ByteVector.from_value(self.value ^ other.value)
  
  def __or__(self, other):
    return ByteVector.from_value(self.value | other.value)
  
  def __or__(self, other):
    return ByteVector.from_value(self.value | other.value)
  
  def __div__(self, other):
    return ByteVector.from_value(operator.truediv(self.value, other.value))
  
  def __truediv__(self, other):
    return ByteVector.from_value(operator.truediv(self.value, other.value))
  
  # In-place operators
  
  def __iadd__(self, other):
    self.set_value(self.value + other.value)
  
  def __isub__(self, other):
    self.set_value(self.value - other.value)
  
  def __imul__(self, other):
    self.set_value(self.value * other.value)
  
  def __idiv__(self, other):
    self.set_value(operators.truediv(self.value, other.value))
  
  def __itruediv__(self, other):
    self.set_value(operators.truediv(self.value, other.value))
  
  def __ifloordiv__(self, other):
    self.set_value(self.value // other.value)
  
  def __imod__(self, other):
    self.set_value(self.value % other.value)
  
  def __ipow__(self, other, modulo = None):
    if modulo is None:
      self.set_value(pow(self.value, other.value))
    self.set_value(pow(self.value, other.value, modulo))
  
  def __ilshift__(self, other):
    self.set_value(self.value << other.value)
  
  def __irshift__(self, other):
    self.set_value(self.value >> other.value)
  
  def __iand__(self, other):
    self.set_value(self.value & other.value)
  
  def __ixor__(self, other):
    self.set_value(self.value ^ other.value)
  
  def __ior__(self, other):
    self.set_value(self.value | other.value)
  
  # Unary operators
  
  def __neg__(self):
    return ByteVector.from_value(-self.value)
  
  def __pos__(self):
    return ByteVector.from_value(self.value)
  
  def __abs__(self):
    return ByteVector.from_value(abs(self.value))
  
  def __invert__(self):
    return ByteVector(b''.join(CHR(~c) for c in self.vector))
  
  # Type conversion
  
  def __int__(self):
    return self.value
  
  def __long__(self):
    return make_long(self.value)
  
  def __float__(self):
    return float(self.value)
  
  # Display
  
  #def __oct__(self):
  #  return oct(self.value)
  
  #def __hex__(self):
  #  return hex(self.value)
  
  def __repr__(self):
    return '<ByteVector value=%d vector=%s>' % (self.value,hexlify(self.vector))
  
  def __str__(self):
    return repr(self)
    #return self.vector.encode('hex')
  
  # Misc
  
  def __index__(self):
    return operator.index(self.value)
  
  def __hash__(self):
    return hash(self.value)
  
  # Comparison
  
  def __eq__(self, other):
    if isinstance(other, int):
      return self.value == other
    if isinstance(other, bytes):
      return self.vector == other
    if isinstance(other, ByteVector):
      return self.vector == other.vector  # compare by bytes
    return self.value == other
  
  def __ne__(self, other):
    if isinstance(other, int):
      return self.value != other
    if isinstance(other, bytes):
      return self.vector != other
    if isinstance(other, ByteVector):
      return self.vector != other.vector
    return self.value != other
  
  def __lt__(self, other):
    if isinstance(other, int):
      return self.value < other
    if isinstance(other, bytes):
      return self.vector < other
    if isinstance(other, ByteVector):
      return self.value < other.value
    return self.value < other
  
  def __le__(self, other):
    if isinstance(other, int):
      return self.value <= other
    if isinstance(other, bytes):
      return self.vector <= other
    if isinstance(other, ByteVector):
      return self.value <= other.value
    return self.value <= other
  
  def __gt__(self, other):
    if isinstance(other, int):
      return self.value > other
    if isinstance(other, bytes):
      return self.vector > other
    if isinstance(other, ByteVector):
      return self.value > other.value
    return self.value > other
  
  def __ge__(self, other):
    if isinstance(other, int):
      return self.value >= other
    if isinstance(other, bytes):
      return self.vector >= other
    if isinstance(other, ByteVector):
      return self.value >= other.value
    return self.value >= other
  
  def __nonzero__(self):
    return self.value != 0
  
  # Array access
  
  def __len__(self):
    return len(self.vector)
  
  def __getitem__(self, name):
    return self.vector[name]
  
  def __iter__(self):
    return iter(self.vector)
