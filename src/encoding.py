import struct
from enum import Enum


def decodeUnsignedLEB(f):
    res = 0
    shift = 0
    while True:
        b = ord(f.read(1))
        res |= (b&0x7f) << shift
        if b & 0x80 == 0:
            return res, shift
        shift += 7

def decodeSignedLEB(f):
    res, shift = decodeUnsignedLEB(f)
    if res & (1<<(shift+7-1)):
        res -= 1<<(shift+7)
    return res, shift

def encodeUnsignedLEB(val):
    ret = b''
    while True:
        b = val & 0x7f
        val >>= 7
        if val != 0:
            b |= 0x80
        ret += bytes([b])
        if val == 0:
            return ret

def encodeSignedLEB(val, sz):
    ret = b''
    more = 1
    neg = val < 0
    while more:
        b = val & 0x7f
        val >>= 7
        if neg:
            val |= (~0<<(sz-7))
        if (val == 0 and (b & 0x40) == 0) or (val == -1 and (b & 0x40) != 0):
            more = 0
        else:
            b |= 0x80
        ret += bytes([b])
    return ret

def peek(f, length=1):
    pos = f.tell()
    data = f.read(length) # Might try/except this line, and finally: f.seek(pos)
    f.seek(pos)
    return data


# https://github.com/sunfishcode/wasm-reference-manual/blob/master/WebAssembly.md#primitive-encoding-types
UInt32 = lambda x: struct.unpack('<I', x.read(4))[0]
VaruInt1 = VaruInt7 = VaruInt32 = VaruInt64 = lambda x: decodeUnsignedLEB(x)[0]
VarsInt1 = VarsInt7 = VarsInt32 = VarsInt64 = lambda x: decodeSignedLEB(x)[0]
Float32 = lambda x: struct.unpack('<f', x.read(4))[0]
Float64 = lambda x: struct.unpack('<d', x.read(8))[0]
# A varuPTR immediate is either varuint32 or varuint64 depending on whether the linear memory associated with the instruction using it is 32-bit or 64-bit.
VaruPTR = None
MemFlags = VaruInt32

def Array(f, Type):
    len = VaruInt32(f)
    val = [Type(f) for _ in range(len)]
    return val

def ByteType(f):
    return f.read(1)

ByteArray = lambda x: b''.join(Array(x, ByteType))
Identifier = ByteArray # An identifier is a byte array which is valid UTF-8. TODO: Figure that out

ExternalKind = VarsInt7
Boolean = UInt32
Index = VaruInt32

def ValueType(f):
    type = TypeEncoding(VarsInt7(f))
    assert type in [TypeEncoding.i32, TypeEncoding.i64, TypeEncoding.f32, TypeEncoding.f64], "`ValueType` is required to be integer or floating-point"
    return type

def TableElementType(f):
    type = TypeEncoding(VarsInt7(f))
    assert type == TypeEncoding.funcref, "`TableElementType` is required to be `funcref`"
    return type

def SignatureType(f):
    type = TypeEncoding(VarsInt7(f))
    assert type == TypeEncoding.func, "`SignatureType` is required to be `func`"
    return type

def BlockType(f):
    type = TypeEncoding(VarsInt7(f))
    assert type == TypeEncoding.void, "`BlockType` is required to be `void`"
    return type

class TypeEncoding(Enum):
    # TODO: Use enum
    # Type Encoding (whatever that is)
    i32 = -0x1
    i64 = -0x2
    f32 = -0x3
    f64 = -0x4
    funcref = -0x10
    func = -0x20
    void = -0x40

    def get_size(self):
        match self:
            case TypeEncoding.i32 | TypeEncoding.f32 | TypeEncoding.funcref:
                return 4
            case TypeEncoding.i64 | TypeEncoding.f64:
                return 8
            case _:
                raise Exception("Unknown size")

class ExternalEncoding(Enum):
    # TODO: Use enum
    # Type Encoding (whatever that is)
    Function = 0
    Table = 1
    Memory = 2
    Global = 3