# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import struct
from binascii import hexlify
from six import integer_types, add_metaclass

from .. import util

_ZERO_STR10  = b'\x00' * 10
_IP_HEAD_STR = _ZERO_STR10 + b'\xff\xff'

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def parse_var_set(data, kind):
  '''Reads a set of parsable objects prefixed with a VarInteger.'''
  
  (off, count) = FtVarInteger.parse(data)
  ret = []; index = 0
  while index < count:
    (itemLen,itemObj) = kind.parse(data[off:])
    ret.append(itemObj)
    index += 1
    off += itemLen
  return (off,ret)

class ParameterError(Exception):
  def __init__(self, name, value, kind=None):
    if kind is None: kind = type(value)
    Exception.__init__(self,'Bad Parameter: %s = %r (%s)' % (name,value,kind))
    self._name = name
    self._value = value
    self._kind = kind
  
  name = property(lambda s: s._name)
  value = property(lambda s: s._value)
  kind = property(lambda s: s._kind)

# This metaclass will convert all the (name,kind) pairs in properties into
# class properties and if the base class has a register(cls) method, call it.
class _AutoRegister(type):
  def __init__(cls, name, bases, dct):
    super(_AutoRegister,cls).__init__(name,bases,dct)
    
    def getPara(k):
      return property(lambda s: s._properties[k])
    for (key, vt) in cls.properties:
      setattr(cls,key,getPara(key))
    
    cls._name = name
    
    for base in bases:
      if hasattr(base,'register'):
        if hasattr(base,'not_regist') and not base.not_regist:
          base.register(cls)
        break

@add_metaclass(_AutoRegister)
class CompoundType(object):
  properties = []  # [(sName,type), ...]
  
  def __init__(self, *args, **kw):
    keys = [k for (k, t) in self.properties] # self.properties defines all args and kw
    
    # convert the positional arguments into kw
    params = dict(zip(keys,args))
    for k in kw:
      if k in params:    # can not redefine
        raise TypeError('got multiple values for keyword argument %r' % k)
    keys = set(keys)
    for k in kw:
      if k not in keys:  # unknown keywords
        raise TypeError('got an unexpected keyword argument %r' % k)
    
    params.update(kw)    # add keyword arguments
    
    if len(params) != len(keys):  # check number of properties
      suffix = '' if len(keys) <= 1 else 's'
      raise TypeError('takes exactly %d argument%s (%d given)' % (len(keys),suffix,len(params)))
    
    # verify all properties and convert to immutable types.
    for (key, vt) in self.properties:
      value = vt.validate(params[key])
      if value is None:
        raise ParameterError(key,params[key])
      params[key] = value
    
    self._properties = params
  
  def binary(self):
    return b''.join(vt.binary(self._properties[key]) for (key,vt) in self.properties)
  
  @classmethod
  def parse(cls, data):
    kw = dict()
    offset = 0
    for (key, vt) in cls.properties:
      try:
        (length,kw[key]) = vt.parse(data[offset:])
        offset += length
      except Exception as e:
        raise ParameterError(key,data[offset:],vt)
    
    # create without __init__ (would unnecessarily verify the parameters)
    self = cls.__new__(cls)
    self._properties = kw
    return (offset,self)
  
  def __str__(self):
    output = [self._name]
    for (key,vt) in self.properties:
      output.append('%s=%s' % (key,vt.str(self._properties[key])))
    return '<%s>' % ' '.join(output)

class FormatType(object):
  def validate(self, obj):
    '''Returns the object when obj is valid, otherwise None.'''
    raise NotImplemented()
  
  def binary(self, obj):
    raise NotImplemented()
  
  def parse(self, data):
    '''Returns a (consumed_length, value)'''
    raise NotImplemented()
  
  def str(self, obj):
    return str(obj)
  
  def __str__(self):
    cls = str(self.__class__).split('.')[-1].strip(">'")
    return '<%s>' % cls

class FtCompoundType(object):
  expected_type = None
  
  @classmethod
  def validate(cls, obj):
    if isinstance(obj, cls.expected_type):
      return obj
    return None
  
  @staticmethod
  def binary(obj):
    return obj.binary()
  
  @classmethod
  def parse(cls, data):
    return cls.expected_type.parse(data)
  
  @classmethod
  def str(cls, obj):
    return str(obj)

class FtOptional(FormatType):
  def __init__(self, child, default):
    self._child = child
    self._default = default
  
  def validate(self, obj):
    try:
      value = self._child.validate(obj)
      if value is not None:
        return value
    except Exception as e:
      print(e)
    return self._default
  
  def binary(self, obj):
    return self._child.binary(obj)
  
  def parse(self, data):
    try:
      return self._child.parse(data)
    except Exception as e:
      pass
    return (0,self._default)
  
  def __str__(self):
    return '<FtOptional child=%s default=%s>' % (self._child, self._default)
  
  def str(self, obj):
    return self._child.str(obj)

class FtNumber(FormatType):
  def __init__(self, format='i', big_endian=False, allow_float=False):
    if format not in self._ranges:
      raise ValueError('invalid format type: %s' % format)
    self._format = ('>' if big_endian else '<') + format
    self._allow_float = allow_float
  
  _ranges = dict(
    b = (-128, 128),
    B = (0, 256),
    h = (-32768, 32768),
    H = (0, 65536),
    i = (-2147483648, 2147483648),
    I = (0, 4294967296),
    q = (-9223372036854775808, 9223372036854775808), # python2.7 supports instant long int
    Q = (0, 18446744073709551616)
  )
  
  def validate(self, obj):
    # check type
    if not (self._allow_float and isinstance(obj,float)):
      if self._format[1] in 'qQ':
        if not isinstance(obj,integer_types):
          return None
      elif not isinstance(obj,int):
        return None
    
    # check valid range
    (minValue, maxValue) = self._ranges[self._format[1]]
    if minValue <= obj < maxValue:
      return obj
    return None
  
  def binary(self, obj):
    return struct.pack(self._format,int(obj))
  
  def parse(self, data):
    length = dict(b=1,h=2,i=4,q=8)[self._format.lower()[-1]]
    return (length,struct.unpack(self._format,data[:length])[0])
  
  def __str__(self):
    return '<FtNumber format=%s>' % (self._format,)

class FtVarInteger(FormatType):
  @staticmethod
  def validate(obj):
    if isinstance(obj, int):
      return obj
    return None
  
  @staticmethod
  def binary(obj):
    if obj < 0xfd:
      return struct.pack('<B',obj)
    elif obj < 0xffff:
      return b'\xfd' + struct.pack('<H',obj)
    elif obj < 0xffffffff:
      return b'\xfe' + struct.pack('<I',obj)
    return b'\xff' + struct.pack('<Q',obj)

  @staticmethod
  def parse(data):
    value = ORD(data[0])
    if value == 0xfd:
      return (3,struct.unpack('<H', data[1:3])[0])
    elif value == 0xfe:
      return (5,struct.unpack('<I', data[1:5])[0])
    elif value == 0xfd:
      return (9,struct.unpack('<Q', data[1:9])[0])
    return (1,value)
  
  def str(self, obj):
    return str(obj)

class FtIPAddress(FormatType):
  @staticmethod
  def _ipv4_groups(obj):
    # convert each group to its value
    try:
      groups = [int(i) for i in obj.split('.')]
    except ValueError as e:
      return None
    
    if len(groups) != 4:
      return None
    for group in groups:
      if not (0x00 <= group <= 0xff):
        return None
    
    return groups
  
  @staticmethod
  def _ipv6_groups(obj):  # not support '::192.1.56.10/96'
    # multiple double-colons or more than 8 groups; bad address
    objs = obj.split(':')
    if len(objs) < 2: return None
    if objs[0] == '' and objs[1] == '':      # starts with ::
      del objs[0]
    elif objs[-1] == '' and objs[-2] == '':  # ends with ::
      del objs[-1]
    if objs.count('') > 1 or len(objs) > 8:
      return None
    
    # calculate each group's value
    groups = []
    for group in objs:
      if group == '':
        groups.extend([ 0 ] * (9 - len(objs)))
      else:
        groups.append(int(group,16))
    
    # is each group in the correct range?
    for group in groups:
      if not (0x0000 <= group <= 0xffff):
        return None
    
    return groups
  
  @staticmethod
  def validate(obj):
    if not isinstance(obj, str):
      return None
    if FtIPAddress._ipv4_groups(obj) is not None:
      return obj
    if FtIPAddress._ipv6_groups(obj) is not None:
      return obj
    return None
  
  @staticmethod
  def parse(data):
    if data.startswith(_ZERO_STR10) and data[10:12] == (b'\xff\xff'): # ipv4
      return (16, '.'.join(str(i) for i in struct.unpack('>BBBB', data[12:16])))
    return (16, ':'.join(('%x' % i) for i in struct.unpack('>HHHHHHHH', data[:16])))
  
  def binary(self, obj):
    groups = self._ipv4_groups(obj)
    if groups is not None:
      return _IP_HEAD_STR + struct.pack('>BBBB',*groups)
    
    groups = self._ipv6_groups(obj)
    if groups is not None:
      return struct.pack('>HHHHHHHH',*groups)
    
    raise ValueError('invalid ip address')

class FtBytes(FormatType):
  def __init__(self, length):
    self._length = length
  
  def validate(self, obj):
    if isinstance(obj,bytes) and len(obj) == self._length:
      return obj
    return None
  
  def binary(self, obj):
    return obj
  
  def parse(self, data):
    return (self._length, data[:self._length])
  
  def str(self, obj):
    return b'0x' + hexlify(obj)
  
  def __str__(self):
    return '<FtBytes length=%d>' % self._length

class FtVarString(FormatType):
  @staticmethod
  def validate(obj):
    if isinstance(obj,(bytes,str)):
      return obj
    return None
  
  @staticmethod
  def binary(obj):
    if type(obj) == bytes:
      pass
    else: obj = obj.encode('latin-1') # for python3
    return FtVarInteger.binary(len(obj)) + obj
  
  @staticmethod
  def parse(data):
    if type(data) == bytes:  # bytes == str in python2
      pass
    else: data = data.encode('latin-1') # for python3
    (vl,length) = FtVarInteger.parse(data)
    obj = data[vl:vl+length]
    return (vl + len(obj), obj)
  
  def str(self, obj):
    return repr(obj)

class FtArray(FormatType):
  def __init__(self, child_type, min_length = None, max_length = None):
    self._child_type = child_type
    self._min_length = min_length
    self._max_length = max_length
  
  def validate(self, obj):
    if not isinstance(obj,(list, tuple)):
      return None
    if self._min_length and len(obj) < self._min_length:
      return None
    if self._max_length and len(obj) > self._max_length:
      return None
    
    obj = [self._child_type.validate(o) for o in obj]
    if None in obj:
      return None
    return tuple(obj)
  
  def binary(self, obj):
    return ( FtVarInteger.binary(len(obj)) +
             b''.join(self._child_type.binary(o) for o in obj))
  
  def parse(self, data):
    return parse_var_set(data, self._child_type)
  
  def str(self, obj):
    return "[%s]" % ", ".join(self._child_type.str(o) for o in obj)
  
  def __str__(self):
    return '<FtArray child=%s length=[%s, %s]>' % (self._child_type, self._min_length, self._max_length)

class NetworkAddress(CompoundType):
  properties = [
    ('timestamp', FtNumber('I', allow_float=True)),
    ('services', FtNumber('Q')),
    ('address', FtIPAddress()),
    ('port', FtNumber('H', big_endian=True)),
  ]

class FtNetworkAddress(FtCompoundType):
  expected_type = NetworkAddress

class FtNetworkAddressNoTimestamp(FtNetworkAddress):
  @classmethod
  def parse(cls, data):
    (vl,obj) = FtNetworkAddress.parse(b'\x00\x00\x00\x00' + data) # timestamp will be 0
    return (vl - 4, obj)
  
  def binary(self, obj):
    return FtNetworkAddress.binary(obj)[4:]

class InventoryVector(CompoundType):
  properties = [
    ('object_type', FtNumber('I')),
    ('hash', FtBytes(32)),
  ]

class FtInventoryVector(FtCompoundType):
  expected_type = InventoryVector

class OutPoint(CompoundType):
  properties = [
    ('hash', FtBytes(32)),
    ('index', FtNumber('I')),
  ]
  
  def __hash__(self):
    return hash((self.hash,self.index))

  def __eq__(self, other):
    if not isinstance(other,OutPoint):
      return False
    return (self.hash == other.hash) and (self.index == otehr.index)

class FtOutPoint(FtInventoryVector):
  expected_type = OutPoint

class TxnIn(CompoundType):
  properties = [
    ('prev_output', FtOutPoint()),
    ('sig_script', FtVarString()),
    ('sequence', FtNumber('I')),
  ]

class FtTxnIn(FtCompoundType):
  expected_type = TxnIn

class TxnOut(CompoundType):
  properties = [
    ('value', FtNumber('q')),
    ('pk_script', FtVarString()),
  ]

class FtTxnOut(FtCompoundType):
  expected_type = TxnOut

class Txn(CompoundType):
  properties = [
    ('version', FtNumber('I')),
    ('tx_in', FtArray(FtTxnIn, 1)),
    ('tx_out', FtArray(FtTxnOut, 1)),
    ('lock_time', FtNumber('I')),
    ('sig_raw', FtVarString()),     # Txn.hash will exclude sig_raw
  ]
  
  @property
  def hash(self):
    if '__hash' not in self._properties:
      self._properties['__hash'] = h = util.sha256d(self.binary()[:-1-len(self.sig_raw)])
    else: h = self._properties['__hash']
    return h

class FtTxn(FtInventoryVector):
  expected_type = Txn

class BlockHeader(CompoundType):
  properties = [
    ('version', FtNumber('I')),
    ('link_no', FtNumber('I')),
    ('prev_block', FtBytes(32)),
    ('merkle_root', FtBytes(32)),
    ('timestamp', FtNumber('I',allow_float=True)),
    ('bits', FtNumber('I')),
    ('nonce', FtNumber('I')),     # 80 ~ 83, hash = sha256d(header.binary()[:84])
    ('miner', FtBytes(32)),       # 84 ~ 115
    ('sig_tee', FtVarString()),
    ('txn_count',FtVarInteger()), # will be included in txns
  ]
  
  @staticmethod
  def from_block(block):
    return BlockHeader( block.version, block.link_no, 
             block.previous_hash, block.merkle_root, block.timestamp,
             block.bits, block.nonce, block.miner, block.sig_tee, block.txn_count )
  
  @property
  def hash(self):
    if '__hash' not in self._properties:
      self._properties['__hash'] = util.sha256d(self.binary()[:84])
    return self._properties['__hash']

class FtBlockHeader(FtInventoryVector):
  expected_type = BlockHeader

class VarStrList(CompoundType):
  properties = [
    ('items', FtArray(FtVarString, 1)),
  ]

class FtVarStrList(FtCompoundType):
  expected_type = VarStrList

class PayFrom(CompoundType):
  properties = [
    ('value', FtNumber('q')),
    ('address', FtVarString()),  # base58 address: ver1 + vcn2 + pubhash32 + cointype
  ]

class FtPayFrom(FtCompoundType):
  expected_type = PayFrom

class PayTo(CompoundType):
  properties = [
    ('value', FtNumber('q')),
    ('address', FtVarString()),  # base58 address, or RETURN script (when value is 0)
  ]

class FtPayTo(FtCompoundType):
  expected_type = PayTo

class UockValue(CompoundType):
  properties = [
    ('uock', FtNumber('q')),
    ('value', FtNumber('q')),
    ('height', FtNumber('I')),
  ]

class FtUockValue(FtCompoundType):
  expected_type = UockValue
