from binaryninja import *
import struct

from isort import file
from .section import GlobalDeclaration, Wasm, Import, FunctionBody
from io import BytesIO
from .disasm import disasm

HEADER_SIZE = 8

class WasmView(BinaryView):
	# IDK
	name = "WASM"
	# IDK
	long_name = "WASM File"

	def __init__(self, data: BinaryView):
		BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
		self.platform = Architecture['WASM'].standalone_platform  # type: ignore

	@classmethod
	def is_valid_for_data(cls, data: BinaryView) -> bool:
		# https://github.com/CarveSystems/binjawa/blob/master/binaryview.py
		# shameless copy
		hdr = data.read(0, HEADER_SIZE)
		if len(hdr) < HEADER_SIZE:
			return False
		if hdr[0:4] != b'\x00asm':
			return False

		ver = struct.unpack('<I', hdr[4:])[0]
		return ver == 1

	def init(self) -> bool:
		# https://github.com/CarveSystems/binjawa/blob/master/binaryview.py
		# shameless copy
		file_size = len(self.parent_view)
		# Define segment which the code lives in
		self.add_auto_segment(0, file_size, 0, file_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentContainsCode)
		self.arch.wasm_obj = Wasm(BytesIO(self.parent_view.read(0, file_size)))

		type, name = self.parse_type_string('''
		struct {char magic_cookie[4]; int version;} Wasm_Header
		''')

		wasm_header_type = self.define_type(Type.generate_auto_type_id("source", name), name, type)
		# Tell BN this addr has a type Wasm_Header
		self.define_data_var(self.start, 'Wasm_Header')
		# Name it __wasm_header
		self.define_auto_symbol(Symbol(SymbolType.DataSymbol, self.start, '__wasm_header'))

		for function in self.arch.wasm_obj.functions:
			match function:
				case Import():
					func_name = function.export_name
					self.add_auto_section(
						"extern_{}".format(hex(function.start_addr)),
						function.start_addr,
						function.size,
						SectionSemantics.ExternalSectionSemantics
					)
					self.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, function.start_addr, func_name))
					self.define_data_var(function.start_addr, 'void')
				case FunctionBody():
					self.add_auto_section(
						"code_{}".format(hex(function.start_addr)),
						function.start_addr,
						function.instruction_size,
						SectionSemantics.ReadOnlyCodeSectionSemantics
					)
					self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, function.start_addr, function.name))
					self.add_function(function.start_addr)
		
		for data in self.arch.wasm_obj.sections.datas:
			self.add_auto_section(
				"data_{}".format(hex(data.start_addr)),
				data.start_addr,
				data.size,
				SectionSemantics.ReadWriteDataSectionSemantics
			)
		
		for idx, glob in enumerate(self.arch.wasm_obj.sections.globals):
			# Each global entry will start with a `GlobalDescription` which *should* be 2 bytes in size
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, glob.start_addr, 'global{}'.format(idx)))
			match glob.init[0].mnemonic:
				case 'i32.const':
					type = 'int'
				case 'i64.const':
					type = 'int64_t'
				case 'f32.const':
					type = 'float'
				case 'f64.const':
					type = 'double'
				case 'global.get':
					type = 'void'
				case _:
					raise Exception("Global value is not a valid instruction")
			self.define_data_var(glob.start_addr, type)
			self.get_data_var_at(glob.start_addr).value = glob.init[0].immediates.value

		return True

	def perform_is_executable(self) -> bool:
		# ????
		return True

WasmView.register()