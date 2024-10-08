import sys
import struct
from io import BytesIO
from dataclasses import dataclass
from enum import Enum
from tokenize import Name
from .encoding import *
from .disasm import BranchImm, BranchTableImm, Instruction, disasm
import functools
from binaryninja import log_info, log_warn


class NameType(Enum):
    Module = 0
    Function = 1
    Local = 2
    Label = 3
    Type = 4
    Table = 5
    Memory = 6
    Global = 7
    ElemSegment = 8
    DataSegment = 9
    Tag = 10

@dataclass
class NameMap:
    index: int
    name: str
    def __init__(self, f):
        self.index = VaruInt32(f)
        self.name = ByteArray(f)

@dataclass
class NameSubSection:
    type: NameType
    module_name: str = None
    function_names: list[NameMap] = None
    local_names: list[NameMap] = None
    label_names: list[NameMap] = None
    table_names: list[NameMap] = None
    memory_names: list[NameMap] = None
    global_names: list[NameMap] = None
    elemsegment_names: list[NameMap] = None
    datasegment_names: list[NameMap] = None
    tag_names: list[NameMap] = None

    def __init__(self, f):
        # So apparently custom subsections has an extended version which the core does not feature
        # https://webassembly.github.io/spec/core/appendix/custom.html    Only 3 tags
        # https://www.scheidecker.net/2019-07-08-extended-name-section-spec/appendix/custom.html  7 tags!
        # I basically went around a few projects, little ever implemented the name subsection and all but
        # wabt implemented the extended name section spec
        # https://github.com/WebAssembly/wabt/blob/main/src/binary-reader.cc#L1824
        # Ahhhhhhhhhh why doesn't the official docs write this down!
        # Apparently there's even more tags?!?!??
        self.type = NameType(VaruInt7(f))
        payload = ByteArray(f)
        match self.type:
            case NameType.Module:
                self.module_name = ByteArray(BytesIO(payload))
            case NameType.Function:
                self.function_names = Array(BytesIO(payload), NameMap)
            case NameType.Local:
                pass
            case NameType.Label:
                pass
            case NameType.Table | NameType.Memory | NameType.Global | NameType.ElemSegment | NameType.DataSegment | NameType.Tag:
                setattr(self, self.type.name.lower()+'_names', Array(BytesIO(payload), NameMap))


@dataclass
class Custom:
    opcode = '\x00'

    subsections: list[NameSubSection] = None

    def __init__(self, f):
        # NOTE: Specifications literally say this section can be basically anything
        # but we'll assume it's a name section because emcc seems to use this as such
        # We'll also wrap everything in a try catch because it can basically be anything
        # Oh, if this does error out, there's a 99% chance the program will just crash
        try:
            self.name = Identifier(f)
            # print(self.name)
            match self.name:
                case b"name":
                    self.subsections = []
                    while peek(f):
                        self.subsections.append(NameSubSection(f))
        except Exception as e:
            pass
        

def bytes_read(func):
    @functools.wraps(func)
    def wrapper(self, f):
        self.start = self.start_addr = f.tell()
        func(self, f)
        self.end = self.end_addr = f.tell()
        self.size = self.end-self.start
    return wrapper

@dataclass
class FunctionSignature:
    opcode = '\x01'
    form: TypeEncoding = None
    params: list[TypeEncoding] = None
    returns: list[TypeEncoding] = None

    @bytes_read
    def __init__(self, f):
        self.form = SignatureType(f)
        self.params = Array(f, ValueType)
        self.returns = Array(f, ValueType)
        assert len(self.returns) <= 1, "Each `returns` array is required to contain at most one element."
        # print("Params", list(map(TypeEncoding.lookup, self.params)))
        # print("returns", list(map(TypeEncoding.lookup, self.returns)))

@dataclass
class ResizableLimits:
    flags: int
    minimum: int
    maximum: int = None

    @bytes_read
    def __init__(self, f):
        self.flags = VaruInt32(f)
        self.minimum = VaruInt32(f)
        if self.flags & 1:
            self.maximum = VaruInt32(f)
            assert self.minimum <= self.maximum, "Maximum must not be smaller than minimum"

@dataclass
class LinearMemoryDescription:
    # NOTE: What was i smoking when i wrote this? can't i replace this with ResizableLimits?
    opcode = '\x05'
    limits: ResizableLimits

    @bytes_read
    def __init__(self, f):
        self.limits = ResizableLimits(f)

@dataclass
class TableDescription:
    opcode = '\x04'
    element_type: TypeEncoding
    resizable: ResizableLimits

    @bytes_read
    def __init__(self, f):
        self.element_type = TableElementType(f)
        self.resizable = ResizableLimits(f)
        

@dataclass
class GlobalDescription:
    type: TypeEncoding
    mutability: int

    @bytes_read
    def __init__(self, f):
        self.type = ValueType(f)
        self.mutability = VaruInt1(f)

@dataclass
class Import:
    opcode = '\x02'
    module_name: bytes
    export_name: bytes
    kind: int
    signature: FunctionSignature = None
    sig_index: int = None
    desc: object = None

    @bytes_read
    def __init__(self, f):
        # TODO: Add assert for the rest of the validations
        self.start_addr = f.tell() + Wasm.base_addr
        self.module_name = Identifier(f)
        self.export_name = Identifier(f)
        self.kind = ExternalEncoding(ExternalKind(f))
        if self.kind == ExternalEncoding.Function:
            self.sig_index = VaruInt32(f)
        elif self.kind == ExternalEncoding.Table:
            self.desc = TableDescription(f)
        elif self.kind == ExternalEncoding.Memory:
            self.desc = LinearMemoryDescription(f)
        elif self.kind == ExternalEncoding.Global:
            self.desc = GlobalDescription(f)
            assert self.desc.mutability == 0, "All global imports are required to be immutable"
        else:
            assert False, "Import kind not found"
        
    def get_return_val(self):
        if len(self.signature.returns) == 0:
            return None
        assert len(self.signature.returns) == 1
        return self.signature.returns[0]

def InstantiationTimeInitializer(f):
    instrs = []
    depth = 0
    while True:
        # TODO: We don't really need to do the checking like this since the data provides the number of bytes
        instrs.append(disasm(f))
        if instrs[-1].mnemonic in ['block', 'loop', 'if']:
            depth += 1
        if instrs[-1].mnemonic == 'end':
            if depth == 0:
                return instrs
            depth -= 1

@dataclass
class Function:
    opcode = '\x03'
    index: int

    @bytes_read
    def __init__(self, f):
        self.index = Index(f)

@dataclass
class GlobalDeclaration:
    opcode = '\x06'
    desc: GlobalDescription
    init: list

    @bytes_read
    def __init__(self, f):
        self.desc = GlobalDescription(f)
        self.start_addr = f.tell() + Wasm.base_addr + 1
        self.init = InstantiationTimeInitializer(f)
        assert len(self.init) == 2
        assert self.init[-1].mnemonic == 'end'
        # assert self.desc.type == self.init.type, "The type of the value returned by init must be the same as desc's type"

    def get_init_value(self):
        return self.init[0].immediates.value
    
    def get_init_size(self):
        return self.init[0].immediates.size
    


@dataclass
class Export:
    opcode = '\x07'
    name: bytes
    kind: ExternalEncoding
    index: int

    @bytes_read
    def __init__(self, f):
        self.name = Identifier(f)
        self.kind = ExternalEncoding(ExternalKind(f))
        self.index = VaruInt32(f)

@dataclass
class StartSection:
    opcode = '\x08'
    index: int

    @bytes_read
    def __init__(self, f):
        self.index = VaruInt32(f)

@dataclass
class TableInitializer:
    opcode = '\x09'
    index: int
    offset: list
    elems: list

    @bytes_read
    def __init__(self, f):
        self.index = VaruInt32(f)
        self.offset = InstantiationTimeInitializer(f)
        # If the `table`'s `element_type`` is `funcref``, the following fields are appended.
        # I have to pass a reference into here
        # FIX ME: This is read only if it satified the comment above
        self.elems = Array(f, VaruInt32)

@dataclass
class LocalEntry:
    count: int
    type: TypeEncoding

    @bytes_read
    def __init__(self, f):
        self.count = VaruInt32(f)
        self.type = ValueType(f)

@dataclass
class FunctionBody:
    opcode = '\x0a'
    body_size: int
    locals: list[LocalEntry]
    instructions: list[Instruction]
    start_addr: int
    name: str
    signature: FunctionSignature

    @bytes_read
    def __init__(self, f):
        self.body_size = VaruInt32(f)
        start = f.tell()
        self.locals = Array(f, LocalEntry)
        # assert all(var.count == 1 for var in self.locals), "TODO, ADD THIS IN"
        self.start_addr = f.tell() + Wasm.base_addr
        self.instruction_size = self.body_size-(f.tell()-start)
        ff = BytesIO(b''.join([ByteType(f) for _ in range(self.body_size-(f.tell()-start))]))
        self.instructions = InstantiationTimeInitializer(ff)
        self.name = None

    def get_var(self, id) -> TypeEncoding:
        if id < len(self.signature.params):
            return self.signature.params[id]
        else:
            cnt = 0
            id -= len(self.signature.params)
            for var in self.locals:
                if id < cnt + var.count:
                    return var.type
                cnt += var.count
            return None

    def get_offset(self, id) -> int:
        if id < len(self.signature.params):
            return True, id*8
            # return True, sum([param.get_size() for param in self.signature.params[:id]])
        else:
            return False, (id - len(self.signature.params)) * 8

    def get_return_val(self) -> TypeEncoding:
        if len(self.signature.returns) == 0:
            return None
        assert len(self.signature.returns) == 1
        return self.signature.returns[0]

@dataclass
class DataInitializer:
    opcode = '\x0b'
    index: int
    offset: list[Instruction]
    size: int
    data: bytes

    @bytes_read
    def __init__(self, f):
        self.index = VaruInt32(f)
        self.offset = InstantiationTimeInitializer(f)
        assert len(self.offset) == 2
        assert self.offset[-1].mnemonic == 'end'
        assert self.offset[0].mnemonic == 'i32.const'
        # Used to be self.data = ByteArray(f)
        # Had to decompose to be able to get start_addr
        self.size = VaruInt32(f)
        self.start_addr = f.tell()
        self.data = f.read(self.size)
        
    def get_offset(self):
        return self.offset[0].immediates.value
        

TypeSection = lambda x: Array(x, FunctionSignature)
ImportSection = lambda x: Array(x, Import)
FunctionSection = lambda x: Array(x, Function)
TableSection = lambda x: Array(x, TableDescription)
LinearMemorySection = lambda x: Array(x, LinearMemoryDescription)
GlobalSection = lambda x: Array(x, GlobalDeclaration)
ExportSection = lambda x: Array(x, Export)
ElementSection = lambda x: Array(x, TableInitializer)
CodeSection = lambda x: Array(x, FunctionBody)
DataSection = lambda x: Array(x, DataInitializer)


SectionOpcodes = {
    0x0: ('customs', Custom),
    0x1: ('types', TypeSection),
    0x2: ('imports', ImportSection),
    0x3: ('functions', FunctionSection),
    0x4: ('tables', TableSection),
    0x5: ('linear_memories', LinearMemorySection),
    0x6: ('globals', GlobalSection),
    0x7: ('exports', ExportSection),
    0x8: ('start', StartSection),
    0x9: ('elements', ElementSection),
    0xa: ('codes', CodeSection),
    0xb: ('datas', DataSection),
}

class Section:
    customs: list[Custom] = []
    types: list[FunctionSignature] = []
    imports: list[Import] = []
    functions: list[Function] = []
    tables: list[TableDescription] = []
    linear_memories: list[LinearMemoryDescription] = []
    globals: list[GlobalDeclaration] = []
    exports: list[Export] = []
    start: StartSection
    elements: list[TableInitializer] = []
    codes: list[FunctionBody] = []
    datas: list[DataInitializer] = []
    
    def __init__(self, f):
        self.magic_cookie = UInt32(f)
        self.version = UInt32(f)
        assert self.magic_cookie == 0x6d736100, "Invalid wasm magic"
        assert self.version == 1, "Invalid wasm version"

        self.sections = []
        while peek(f):
            self.opcode = VaruInt7(f)
            len = VaruInt32(f)
            log_info("Section opcode {} {} {}".format(self.opcode, hex(len), peek(f, 0x10)))
            if self.opcode in SectionOpcodes:
                name, cls = SectionOpcodes[self.opcode]
                if self.opcode == 0:
                    assert hasattr(self, name)  # TODO: Use defaultdict
                    obj = getattr(self, name)
                    obj.append(cls(BytesIO(f.read(len))))
                    setattr(self, name, obj)
                else:
                    # assert not hasattr(self, name)
                    setattr(self, name, cls(f))
            else:
                log_warn("Unknown section {}".format(self.opcode))
                f.read(len)
        # Let's make sure it read all the data
        assert f.read() == b''

class Wasm:
    base_addr: int = 0x8000000

    def __init__(self, f):
        self.sections = Section(f)
        self.functions: list[FunctionBody | Import] = []
        types = self.sections.types
        for imp in self.sections.imports:
            if imp.kind == ExternalEncoding.Function:
                imp.signature = types[imp.sig_index]
                self.functions.append(imp)
        
        self.function_ends = set()
        self.depth_addr_mapping = {}    

        for k, func in enumerate(self.sections.codes):
            func.name = "func_{}".format(func.start_addr - self.base_addr)
            func.signature = types[self.sections.functions[k].index]
            self.functions.append(func)
            self.depth_addr_mapping.update(self.build_branch(func))
        
        for export in self.sections.exports:
            match export.kind:
                case ExternalEncoding.Function:
                    self.functions[export.index].name = export.name
                case ExternalEncoding.Memory:
                    pass
                case ExternalEncoding.Table:
                    pass
                case ExternalEncoding.Global:
                    pass

        for custom in self.sections.customs:
            # This horrible nested stuff is because there's several other cases to conside
            match custom.name:
                case b"name":
                    for name_subsection in custom.subsections:
                        match name_subsection.type:
                            case NameType.Function:
                                for func in name_subsection.function_names:
                                    if func.index >= len(self.functions):
                                        print("WTF", func)
                                        continue
                                    self.functions[func.index].name = func.name

        self.globals = self.sections.globals

    def get_function(self, addr):
        for function in self.functions:
            if isinstance(function, FunctionBody) and function.start_addr <= addr < function.start_addr + function.instruction_size:
                return function
        return None

    
    def build_branch(self, func: FunctionBody):
        # https://openhome.cc/eGossip/WebAssembly/Block.html
        # https://openhome.cc/eGossip/WebAssembly/If.html
        # https://openhome.cc/eGossip/WebAssembly/Loop.html
        branch_stack = []
        # Branch data for if, else
        branch_mapping = {}
        cur_addr = func.start_addr
        # Branch data for br_ instructions
        depth_addr_mapping = {}
        for instr in func.instructions:
            if instr.mnemonic in ['block', 'loop', 'if']:
                branch_stack.append(cur_addr)
            if instr.mnemonic == 'else':
                branch_mapping[branch_stack.pop()] = cur_addr+instr.size
                branch_stack.append(cur_addr)
            if instr.mnemonic == 'end':
                if len(branch_stack) == 0:
                    self.function_ends.add(cur_addr)
                    break
                branch_mapping[branch_stack.pop()] = cur_addr+instr.size
            cur_addr += instr.size

        cur_addr = func.start_addr
        for instr in func.instructions:
            if instr.mnemonic in ['block', 'loop', 'if']:
                branch_stack.append((instr, cur_addr))
            if instr.mnemonic == 'end':
                if len(branch_stack) == 0:
                    break
                branch_stack.pop()
            if isinstance(instr.immediates, BranchImm):
                imm = instr.immediates
                # print(imm.depth, branch_stack, hex(cur_addr), branch_mapping)
                branch_instr, addr = branch_stack[-(imm.depth+1)]
                match branch_instr.mnemonic:
                    case 'block' | 'if':
                        # TODO: properly implement if/else
                        depth_addr_mapping[cur_addr] = imm.depth_addr = branch_mapping[addr]
                    case 'loop':
                        depth_addr_mapping[cur_addr] = addr
            if isinstance(instr.immediates, BranchTableImm):
                imm = instr.immediates
                depth_addr_mapping[cur_addr] = [branch_stack[-(depth+1)][1] for depth in imm.table]

            cur_addr += instr.size
        return depth_addr_mapping | branch_mapping
    

if __name__ == '__main__':
    if len(sys.argv) == 2:
        f = open(sys.argv[1], 'rb')
        Wasm(f)
    else:
        print("python", sys.argv[0], "[file]")