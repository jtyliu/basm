from binaryninja import *
import struct

from .section import GlobalDeclaration, Wasm, Import, FunctionBody
from io import BytesIO
from .disasm import disasm

HEADER_SIZE = 8
# Note: The user is not allowed to rebase.
# Should simplify things
# TODO: Allow WASM to rebase

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
		self.arch.wasm_obj = Wasm(BytesIO(self.parent_view.read(0, file_size)))

		# Define segment which the code lives in
		linear_memories = self.arch.wasm_obj.sections.linear_memories
		assert len(linear_memories) == 1, "WHY DO YOU HAVE TWO LINEAR MEMORIES, WHAT DOES THAT MEAN?"
		# https://github.com/sunfishcode/wasm-reference-manual/blob/master/WebAssembly.md#linear-memory-section
		# RW Segment
		self.add_auto_segment(0, 0x10000 * linear_memories[0].limits.minimum, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData)
		# Code Segment
		self.add_auto_segment(Wasm.base_addr, file_size, 0, file_size, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentDenyWrite)

		self.add_auto_section("header", Wasm.base_addr, 0x8,SectionSemantics.ReadOnlyDataSectionSemantics)
		# self.add_auto_section("code", Wasm.base_addr + 0x8, file_size - 0x8,SectionSemantics.ReadOnlyCodeSectionSemantics)

		with StructureBuilder.builder(self, "__wasm_header") as header_struct_info:
			header_struct_info.packed = True
			header_struct_info.append(Type.array(Type.char(), 4), "magic_cookie")
			header_struct_info.append(Type.int(4), "version")
			header_struct = Type.structure_type(header_struct_info)

			# Tell BN this addr has a type Wasm_Header		
			self.define_data_var(Wasm.base_addr, header_struct)

		# Define functions
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
					# self.add_auto_section(
					# 	"code_{}".format(hex(function.start_addr)),
					# 	function.start_addr,
					# 	function.instruction_size,
					# 	SectionSemantics.ReadOnlyCodeSectionSemantics
					# )
					self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, function.start_addr, function.name))
					self.add_function(function.start_addr)
		
		for data in self.arch.wasm_obj.sections.datas:
			# self.write(data.get_offset(), data.data) # Replace once https://github.com/Vector35/binaryninja-api/issues/920 is resolved
			self.add_auto_segment(
				data.get_offset(),
				data.size,
				data.start_addr,
				data.size,
				SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData
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
			self.get_data_var_at(glob.start_addr).value = glob.get_init_value()

		return True

	def perform_is_executable(self) -> bool:
		# ????
		return True

WasmView.register()
BinaryViewType['WASM'].register_platform_recognizer