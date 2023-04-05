from collections import namedtuple
from dataclasses import dataclass
from enum import Enum, auto, IntFlag
from .encoding import *

Opcode = namedtuple('Opcode', 'mnemonic opcode immediates signature families')
Instruction = namedtuple('Instruction', 'mnemonic opcode immediates size')

# InstructionFamily
class IF(IntFlag, Enum):
    B = auto()
    Q = auto()
    L = auto()
    G = auto()
    S = auto()
    U = auto()
    T = auto()
    R = auto()
    F = auto()
    E = auto()
    C = auto()
    M = auto()
    Z = auto()

# Shameless copy https://github.com/athre0z/wasm/blob/fa88deaeb6f2e50a7f2796efc8f8ba70e59baafa/wasm/immtypes.py
@dataclass
class BlockImm:
    signature: int
    def __init__(self, f):
        self.signature = BlockType(f)

@dataclass
class BranchImm:
    depth: int
    depth_addr: int
    def __init__(self, f):
        self.depth = VaruInt32(f)
        self.depth_addr = None

@dataclass
class BranchTableImm:
    table: list[int]
    default: int
    def __init__(self, f):
        self.table = Array(f, VaruInt32)
        self.default = VaruInt32(f)

@dataclass
class CallImm:
    callee: int
    def __init__(self, f):
        self.callee = VaruInt32(f)

@dataclass
class IndirectCallImm:
    signature: int
    reserved: bool
    def __init__(self, f):
        self.signature = VaruInt32(f)
        self.reserved = bool(VaruInt1(f))

@dataclass
class LocalVarImm:
    id: int
    def __init__(self, f):
        self.id = VaruInt32(f)

@dataclass
class MemoryImm:
    flags: int
    offset: int
    def __init__(self, f):
        self.flags = VaruInt32(f)
        self.offset = VaruInt32(f)

@dataclass
class CurMemoryImm:
    reserved: bool
    def __init__(self, f):
        self.reserved = VaruInt1(f)

@dataclass
class ConstImm:
    value: int
    size: int

@dataclass
class I32ConstImm(ConstImm):
    value: int
    size: int = 4
    def __init__(self, f):
        self.value = VarsInt32(f)

@dataclass
class I64ConstImm(ConstImm):
    value: int
    size: int = 8
    def __init__(self, f):
        self.value = VarsInt64(f)

@dataclass
class F32ConstImm(ConstImm):
    value: float
    size: int = 4
    def __init__(self, f):
        self.value = Float32(f)

@dataclass
class F64ConstImm(ConstImm):
    value: float
    size: int = 8
    def __init__(self, f):
        self.value = Float64(f)

opcodes = [
    Opcode('unreachable', 0x00, None, '() : ()', IF.Q),
    Opcode('nop', 0x01, None, '() : ()', None), # DONE
    Opcode('block', 0x02, BlockImm, '() : ()', None), # DONE
    Opcode('loop', 0x03, BlockImm, '() : ()', None), # DONE (I think)
    Opcode('if', 0x04, BlockImm, '($condition: i32) : ()', IF.B),
    Opcode('else', 0x05, None, '($T[$any]) : ($T[$any])', IF.B),
    Opcode('end', 0x0b, None, '($T[$any]) : ($T[$any])', None), # DONE
    Opcode('br', 0x0c, BranchImm, '($T[$block_arity]) : ($T[$block_arity])', IF.B | IF.Q), # DONE
    Opcode('br_if', 0x0d, BranchImm, '($T[$block_arity], $condition: i32) : ($T[$block_arity])', IF.B),
    Opcode('br_table', 0x0e, BranchTableImm, '($T[$block_arity], $index: i32) : ($T[$block_arity])', IF.B | IF.Q),
    Opcode('return', 0x0f, None, '($T[$block_arity]) : ($T[$block_arity])', IF.B | IF.Q), # DONE

    Opcode('call', 0x10, CallImm, '($T[$args]) : ($T[$returns])', IF.L), # DONE
    Opcode('call_indirect', 0x11, IndirectCallImm, '($T[$args], $callee: i32) : ($T[$returns])', IF.L),

    Opcode('drop', 0x1a, None, '($T[1]) : ()', None), # DONE
    Opcode('select', 0x1b, None, '($T[1], $T[1], $condition: i32) : ($T[1])', None), # DONE
    
    Opcode('local.get', 0x20, LocalVarImm, '() : ($T[1])', None), # DONE
    Opcode('local.set', 0x21, LocalVarImm, '($T[1]) : ()', None), # DONE
    Opcode('local.tee', 0x22, LocalVarImm, '($T[1]) : ($T[1])', None), # DONE
    Opcode('global.get', 0x23, LocalVarImm, '() : ($T[1])', None), # DONE
    Opcode('global.set', 0x24, LocalVarImm, '($T[1]) : ()', None), # DONE

    Opcode('i32.load', 0x28, MemoryImm, '($base: iPTR) : (i32)', IF.M | IF.G), # DONE
    Opcode('i64.load', 0x29, MemoryImm, '($base: iPTR) : (i64)', IF.M | IF.G), # DONE
    Opcode('f32.load', 0x2a, MemoryImm, '($base: iPTR) : (f32)', IF.M | IF.E), # DONE
    Opcode('f64.load', 0x2b, MemoryImm, '($base: iPTR) : (f32)', IF.M | IF.E), # DONE
    Opcode('i32.load8_s', 0x2c, MemoryImm, '($base: iPTR) : (i32)', IF.M | IF.S), # DONE
    Opcode('i32.load8_u', 0x2d, MemoryImm, '($base: iPTR) : (i32)', IF.M | IF.U), # DONE
    Opcode('i32.load16_s', 0x2e, MemoryImm, '($base: iPTR) : (i32)', IF.M | IF.S), # DONE
    Opcode('i32.load16_u', 0x2f, MemoryImm, '($base: iPTR) : (i32)', IF.M | IF.U), # DONE
    Opcode('i64.load8_s', 0x30, MemoryImm, '($base: iPTR) : (i64)', IF.M | IF.S), # DONE
    Opcode('i64.load8_u', 0x31, MemoryImm, '($base: iPTR) : (i64)', IF.M | IF.U), # DONE
    Opcode('i64.load16_s', 0x32, MemoryImm, '($base: iPTR) : (i64)', IF.M | IF.S), # DONE
    Opcode('i64.load16_u', 0x33, MemoryImm, '($base: iPTR) : (i64)', IF.M | IF.U), # DONE
    Opcode('i64.load32_s', 0x34, MemoryImm, '($base: iPTR) : (i64)', IF.M | IF.S), # DONE
    Opcode('i64.load32_u', 0x35, MemoryImm, '($base: iPTR) : (i64)', IF.M | IF.U), # DONE
    Opcode('i32.store', 0x36, MemoryImm, '($base: iPTR, $value: i32) : ()', IF.M | IF.G), # DONE
    Opcode('i64.store', 0x37, MemoryImm, '($base: iPTR, $value: i64) : ()', IF.M | IF.G), # DONE
    Opcode('f32.store', 0x38, MemoryImm, '($base: iPTR, $value: f32) : ()', IF.M | IF.F), # DONE
    Opcode('f64.store', 0x39, MemoryImm, '($base: iPTR, $value: f64) : ()', IF.M | IF.F), # DONE
    Opcode('i32.store8', 0x3a, MemoryImm, '($base: iPTR, $value: i32) : ()', IF.M | IF.G), # DONE
    Opcode('i32.store16', 0x3b, MemoryImm, '($base: iPTR, $value: i32) : ()', IF.M | IF.G), # DONE
    Opcode('i64.store8', 0x3c, MemoryImm, '($base: iPTR, $value: i64) : ()', IF.M | IF.G), # DONE
    Opcode('i64.store16', 0x3d, MemoryImm, '($base: iPTR, $value: i64) : ()', IF.M | IF.G), # DONE
    Opcode('i64.store32', 0x3e, MemoryImm, '($base: iPTR, $value: i64) : ()', IF.M | IF.G), # DONE
    Opcode('memory.size', 0x3f, CurMemoryImm, '() : (iPTR)', IF.Z),
    Opcode('memory.grow', 0x40, CurMemoryImm, '($delta: iPTR) : (iPTR)', IF.Z),
    Opcode('i32.const', 0x41, I32ConstImm, '() : (i32)', None), # DONE
    Opcode('i64.const', 0x42, I64ConstImm, '() : (i64)', None), # DONE
    Opcode('f32.const', 0x43, F32ConstImm, '() : (f32)', None), # DONE
    Opcode('f64.const', 0x44, F64ConstImm, '() : (f64)', None), # DONE

    Opcode('i32.eqz', 0x45, None, '(i32) : (i32)', IF.G), # DONE
    Opcode('i32.eq', 0x46, None, '(i32, i32) : (i32)', IF.C | IF.G), # DONE
    Opcode('i32.ne', 0x47, None, '(i32, i32) : (i32)', IF.C | IF.G), # DONE
    Opcode('i32.lt_s', 0x48, None, '(i32, i32) : (i32)', IF.C | IF.S), # DONE
    Opcode('i32.lt_u', 0x49, None, '(i32, i32) : (i32)', IF.C | IF.U), # DONE
    Opcode('i32.gt_s', 0x4a, None, '(i32, i32) : (i32)', IF.C | IF.S), # DONE
    Opcode('i32.gt_u', 0x4b, None, '(i32, i32) : (i32)', IF.C | IF.U), # DONE
    Opcode('i32.le_s', 0x4c, None, '(i32, i32) : (i32)', IF.C | IF.S), # DONE
    Opcode('i32.le_u', 0x4d, None, '(i32, i32) : (i32)', IF.C | IF.U), # DONE
    Opcode('i32.ge_s', 0x4e, None, '(i32, i32) : (i32)', IF.C | IF.S), # DONE
    Opcode('i32.ge_u', 0x4f, None, '(i32, i32) : (i32)', IF.C | IF.U), # DONE
    Opcode('i64.eqz', 0x50, None, '(i64) : (i32)', IF.G), # DONE
    Opcode('i64.eq', 0x51, None, '(i64, i64) : (i32)', IF.C | IF.G), # DONE
    Opcode('i64.ne', 0x52, None, '(i64, i64) : (i32)', IF.C | IF.G), # DONE
    Opcode('i64.lt_s', 0x53, None, '(i64, i64) : (i32)', IF.C | IF.S), # DONE
    Opcode('i64.lt_u', 0x54, None, '(i64, i64) : (i32)', IF.C | IF.U), # DONE
    Opcode('i64.gt_s', 0x55, None, '(i64, i64) : (i32)', IF.C | IF.S), # DONE
    Opcode('i64.gt_u', 0x56, None, '(i64, i64) : (i32)', IF.C | IF.U), # DONE
    Opcode('i64.le_s', 0x57, None, '(i64, i64) : (i32)', IF.C | IF.S), # DONE
    Opcode('i64.le_u', 0x58, None, '(i64, i64) : (i32)', IF.C | IF.U), # DONE
    Opcode('i64.ge_s', 0x59, None, '(i64, i64) : (i32)', IF.C | IF.S), # DONE
    Opcode('i64.ge_u', 0x5a, None, '(i64, i64) : (i32)', IF.C | IF.U), # DONE
    Opcode('f32.eq', 0x5b, None, '(f32, f32) : (i32)', IF.C | IF.F), # DONE
    Opcode('f32.ne', 0x5c, None, '(f32, f32) : (i32)', IF.C | IF.F), # DONE
    Opcode('f32.lt', 0x5d, None, '(f32, f32) : (i32)', IF.C | IF.F), # DONE
    Opcode('f32.gt', 0x5e, None, '(f32, f32) : (i32)', IF.C | IF.F), # DONE
    Opcode('f32.le', 0x5f, None, '(f32, f32) : (i32)', IF.C | IF.F), # DONE
    Opcode('f32.ge', 0x60, None, '(f32, f32) : (i32)', IF.C | IF.F), # DONE
    Opcode('f64.eq', 0x61, None, '(f64, f64) : (i32)', IF.C | IF.F), # DONE
    Opcode('f64.ne', 0x62, None, '(f64, f64) : (i32)', IF.C | IF.F), # DONE
    Opcode('f64.lt', 0x63, None, '(f64, f64) : (i32)', IF.C | IF.F), # DONE
    Opcode('f64.gt', 0x64, None, '(f64, f64) : (i32)', IF.C | IF.F), # DONE
    Opcode('f64.le', 0x65, None, '(f64, f64) : (i32)', IF.C | IF.F), # DONE
    Opcode('f64.ge', 0x66, None, '(f64, f64) : (i32)', IF.C | IF.F), # DONE

    Opcode('i32.clz', 0x67, None, '(i32) : (i32)', IF.G),
    Opcode('i32.ctz', 0x68, None, '(i32) : (i32)', IF.G),
    Opcode('i32.popcnt', 0x69, None, '(i32) : (i32)', IF.G),
    Opcode('i32.add', 0x6a, None, '(i32) : (i32)', IF.G), # DONE
    Opcode('i32.sub', 0x6b, None, '(i32) : (i32)', IF.G), # DONE
    Opcode('i32.mul', 0x6c, None, '(i32) : (i32)', IF.G), # DONE
    Opcode('i32.div_s', 0x6d, None, '(i32) : (i32)', IF.S), # DONE
    Opcode('i32.div_u', 0x6e, None, '(i32) : (i32)', IF.U), # DONE
    Opcode('i32.rem_s', 0x6f, None, '(i32) : (i32)', IF.S | IF.R), # DONE
    Opcode('i32.rem_u', 0x70, None, '(i32) : (i32)', IF.U | IF.R), # DONE
    Opcode('i32.and', 0x71, None, '(i32) : (i32)', IF.G), # DONE
    Opcode('i32.or', 0x72, None, '(i32) : (i32)', IF.G), # DONE
    Opcode('i32.xor', 0x73, None, '(i32) : (i32)', IF.G), # DONE
    Opcode('i32.shl', 0x74, None, '(i32) : (i32)', IF.T | IF.G), # DONE
    Opcode('i32.shr_s', 0x75, None, '(i32) : (i32)', IF.T | IF.S), # DONE
    Opcode('i32.shr_u', 0x76, None, '(i32) : (i32)', IF.T | IF.U), # DONE
    Opcode('i32.rotl', 0x77, None, '(i32) : (i32)', IF.T | IF.G), # DONE
    Opcode('i32.rotr', 0x78, None, '(i32) : (i32)', IF.T | IF.G), # DONE
    Opcode('i64.clz', 0x79, None, '(i64) : (i64)', IF.G),
    Opcode('i64.ctz', 0x7a, None, '(i64) : (i64)', IF.G),
    Opcode('i64.popcnt', 0x7b, None, '(i64) : (i64)', IF.G),
    Opcode('i64.add', 0x7c, None, '(i64) : (i64)', IF.G), # DONE
    Opcode('i64.sub', 0x7d, None, '(i64) : (i64)', IF.G), # DONE
    Opcode('i64.mul', 0x7e, None, '(i64) : (i64)', IF.G), # DONE
    Opcode('i64.div_s', 0x7f, None, '(i64) : (i64)', IF.S), # DONE
    Opcode('i64.div_u', 0x80, None, '(i64) : (i64)', IF.U), # DONE
    Opcode('i64.rem_s', 0x81, None, '(i64) : (i64)', IF.S | IF.R), # DONE
    Opcode('i64.rem_u', 0x82, None, '(i64) : (i64)', IF.U | IF.R), # DONE
    Opcode('i64.and', 0x83, None, '(i64) : (i64)', IF.G), # DONE
    Opcode('i64.or', 0x84, None, '(i64) : (i64)', IF.G), # DONE
    Opcode('i64.xor', 0x85, None, '(i64) : (i64)', IF.G), # DONE
    Opcode('i64.shl', 0x86, None, '(i64) : (i64)', IF.T | IF.G), # DONE
    Opcode('i64.shr_s', 0x87, None, '(i64) : (i64)', IF.T | IF.S), # DONE
    Opcode('i64.shr_u', 0x88, None, '(i64) : (i64)', IF.T | IF.U), # DONE
    Opcode('i64.rotl', 0x89, None, '(i64) : (i64)', IF.T | IF.G), # DONE
    Opcode('i64.rotr', 0x8a, None, '(i64) : (i64)', IF.T | IF.G), # DONE

    Opcode('f32.abs', 0x8b, None, '(f32) : (f32)', IF.E), # DONE
    Opcode('f32.neg', 0x8c, None, '(f32) : (f32)', IF.E), # DONE
    Opcode('f32.ceil', 0x8d, None, '(f32) : (f32)', IF.F), # DONE
    Opcode('f32.floor', 0x8e, None, '(f32) : (f32)', IF.F), # DONE
    Opcode('f32.trunc', 0x8f, None, '(f32) : (f32)', IF.F), # DONE
    Opcode('f32.nearest', 0x90, None, '(f32) : (f32)', IF.F), # DONE
    Opcode('f32.sqrt', 0x91, None, '(f32) : (f32)', IF.F), # DONE
    Opcode('f32.add', 0x92, None, '(f32, f32) : (f32)', IF.F), # DONE
    Opcode('f32.sub', 0x93, None, '(f32, f32) : (f32)', IF.F), # DONE
    Opcode('f32.mul', 0x94, None, '(f32, f32) : (f32)', IF.F), # DONE
    Opcode('f32.div', 0x95, None, '(f32, f32) : (f32)', IF.F), # DONE
    Opcode('f32.min', 0x96, None, '(f32, f32) : (f32)', IF.F),
    Opcode('f32.max', 0x97, None, '(f32, f32) : (f32)', IF.F),
    Opcode('f32.copysign', 0x98, None, '(f32, f32) : (f32)', IF.E),
    Opcode('f64.abs', 0x99, None, '(f64) : (f64)', IF.E), # DONE
    Opcode('f64.neg', 0x9a, None, '(f64) : (f64)', IF.E), # DONE
    Opcode('f64.ceil', 0x9b, None, '(f64) : (f64)', IF.F), # DONE
    Opcode('f64.floor', 0x9c, None, '(f64) : (f64)', IF.F), # DONE
    Opcode('f64.trunc', 0x9d, None, '(f64) : (f64)', IF.F), # DONE
    Opcode('f64.nearest', 0x9e, None, '(f64) : (f64)', IF.F), # DONE
    Opcode('f64.sqrt', 0x9f, None, '(f64) : (f64)', IF.F), # DONE
    Opcode('f64.add', 0xa0, None, '(f64, f64) : (f64)', IF.F), # DONE
    Opcode('f64.sub', 0xa1, None, '(f64, f64) : (f64)', IF.F), # DONE
    Opcode('f64.mul', 0xa2, None, '(f64, f64) : (f64)', IF.F), # DONE
    Opcode('f64.div', 0xa3, None, '(f64, f64) : (f64)', IF.F), # DONE
    Opcode('f64.min', 0xa4, None, '(f64, f64) : (f64)', IF.F),
    Opcode('f64.max', 0xa5, None, '(f64, f64) : (f64)', IF.F),
    Opcode('f64.copysign', 0xa6, None, '(f64, f64) : (f64)', IF.E),

    Opcode('i32.wrap_i64', 0xa7, None, '(i64) : (i32)', IF.G),
    Opcode('i32.trunc_f32_s', 0xa8, None, '(f32) : (i32)', IF.F | IF.S),
    Opcode('i32.trunc_f32_u', 0xa9, None, '(f32) : (i32)', IF.F | IF.U),
    Opcode('i32.trunc_f64_s', 0xaa, None, '(f64) : (i32)', IF.F | IF.S),
    Opcode('i32.trunc_f64_u', 0xab, None, '(f64) : (i32)', IF.F | IF.U),
    Opcode('i64.extend_i32_s', 0xac, None, '(i32) : (i64)', IF.S),
    Opcode('i64.extend_i32_u', 0xad, None, '(i32) : (i64)', IF.U), # DONE
    Opcode('i64.trunc_f32_s', 0xae, None, '(f32) : (i64)', IF.F | IF.S),
    Opcode('i64.trunc_f32_u', 0xaf, None, '(f32) : (i64)', IF.F | IF.U),
    Opcode('i64.trunc_f64_s', 0xb0, None, '(f64) : (i64)', IF.F | IF.S),
    Opcode('i64.trunc_f64_u', 0xb1, None, '(f64) : (i64)', IF.F | IF.U),

    Opcode('f32.convert_i32_s', 0xb2, None, '(i32) : (f32)', IF.F | IF.S),
    Opcode('f32.convert_i32_u', 0xb3, None, '(i32) : (f32)', IF.F | IF.U),
    Opcode('f32.convert_i64_s', 0xb4, None, '(i64) : (f32)', IF.F | IF.S),
    Opcode('f32.convert_i64_u', 0xb5, None, '(i64) : (f32)', IF.F | IF.U),
    Opcode('f32.demote_f64', 0xb6, None, '(f64) : (f32)', IF.F),
    Opcode('f64.convert_i32_s', 0xb7, None, '(i32) : (f64)', IF.F | IF.S),
    Opcode('f64.convert_i32_u', 0xb8, None, '(i32) : (f64)', IF.F | IF.U),
    Opcode('f64.convert_i64_s', 0xb9, None, '(i64) : (f64)', IF.F | IF.S),
    Opcode('f64.convert_i64_u', 0xba, None, '(i64) : (f64)', IF.F | IF.U),
    Opcode('f64.promote_f32', 0xbb, None, '(f32) : (f64)', IF.F),

    Opcode('i32.reinterpret_f32', 0xbc, None, '(f32) : (i32)', None),
    Opcode('i64.reinterpret_f64', 0xbd, None, '(f64) : (i64)', None),
    Opcode('f32.reinterpret_i64', 0xbe, None, '(i32) : (f32)', None),
    Opcode('f64.reinterpret_i32', 0xbf, None, '(i64) : (f64)', None),

    Opcode('i32.extend8_s', 0xc0, None, '(i32) : (i32)', IF.S),
    Opcode('i32.extend16_s', 0xc1, None, '(i32) : (i32)', IF.S),
    Opcode('i64.extend8_s', 0xc2, None, '(i64) : (i64)', IF.S),
    Opcode('i64.extend16_s', 0xc3, None, '(i64) : (i64)', IF.S),
    Opcode('i64.extend32_s', 0xc4, None, '(i64) : (i64)', IF.S),
]

opcode_mapping = {opcode.opcode: opcode for opcode in opcodes}

def disasm(f):
    start = f.tell()
    opcode = ord(f.read(1))
    if opcode not in opcode_mapping:
        raise Exception("Instruction not found", hex(opcode))
        # return Instruction(None, None, None, 0)
    opcode = opcode_mapping[opcode]
    imm = opcode.immediates
    if imm:
        imm = imm(f)
    return Instruction(opcode.mnemonic, opcode.opcode, imm, f.tell()-start)