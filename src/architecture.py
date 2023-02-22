from binaryninja import *
from .section import Wasm, Import, FunctionBody
from .disasm import *
from io import BytesIO


class WASM(Architecture):
	name = 'WASM'
	address_size = 4 # 4 byte addresses???
	default_int_size = 8 # 4 byte integers
	instr_alignment = 1	# No instruction alignment
	max_instr_length = 100

	regs = {
		'rsp': RegisterInfo('rsp', address_size),
		'rbp': RegisterInfo('rbp', address_size),
	}

	stack_pointer = "rsp"

	def get_instruction_info(self, data, addr):
		instr = disasm(BytesIO(data))
		if instr.size == 0:
			return None
		wasm_obj: Wasm = Architecture['WASM'].wasm_obj
		result = InstructionInfo()
		result.length = instr.size
		match instr.mnemonic:
			case "call":
				function = wasm_obj.functions[instr.immediates.callee]
				result.add_branch(BranchType.CallDestination, function.start_addr)
			case "br":
				result.add_branch(BranchType.UnconditionalBranch, wasm_obj.depth_addr_mapping[addr])
			case "br_if":
				result.add_branch(BranchType.TrueBranch, wasm_obj.depth_addr_mapping[addr])
				result.add_branch(BranchType.FalseBranch, addr+instr.size)
			case "br_table":
				# Nushy on slack: binja just doesn't support "jumps to N static places" at the disassembly level
				# for addr in wasm_obj.depth_addr_mapping[addr]:
				# 	print(hex(addr))
				# 	result.add_branch(BranchType.UnresolvedBranch, addr)
				pass
			case "end":
				if addr in wasm_obj.function_ends:
				# 	# Quick hack to stop disassembler from going past the "end" instruction
					result.add_branch(BranchType.FunctionReturn)
				
		return result
	
	def get_function_name_text(self, addr):

		for function in Architecture['WASM'].wasm_obj.functions:
			if function.start_addr == addr:
				if isinstance(function, Import):
					return InstructionTextTokenType.ExternalSymbolToken, function.export_name
				elif isinstance(function, FunctionBody):
					return InstructionTextTokenType.CodeSymbolToken, function.name

	def get_instruction_text(self, data, addr):
		instr = disasm(BytesIO(data))
		if instr.size == 0:
			return [], 0
		tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, instr.mnemonic)]
		wasm_obj: Wasm = Architecture['WASM'].wasm_obj
		if instr.immediates:
			imm = instr.immediates
			tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
			match imm:
				case BlockImm():
					pass
					# tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(imm.signature)))
				case BranchImm():
					dest_addr = wasm_obj.depth_addr_mapping[addr]
					tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(dest_addr), dest_addr))
				case BranchTableImm():
					log_info("br_table", hex(addr))
					pass
				case CallImm():
					function = wasm_obj.functions[imm.callee]
					token_type, func_name = self.get_function_name_text(function.start_addr)
					tokens.append(InstructionTextToken(token_type, func_name, function.start_addr))
				case IndirectCallImm():
					tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(imm.signature)))
				case LocalVarImm():
					if 'local' in instr.mnemonic:
						tokens.append(InstructionTextToken(InstructionTextTokenType.LocalVariableToken, "var{}".format(imm.id), imm.id | 0x100000000))
					elif 'global' in instr.mnemonic:
						global_var = "global{}".format(imm.id)
						tokens.append(InstructionTextToken(InstructionTextTokenType.DataSymbolToken, global_var, wasm_obj.globals[imm.id].start_addr))
				case MemoryImm():
					tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, str(imm.offset)))
				case CurMemoryImm():
					tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(imm.reserved)))
				case I32ConstImm() | I64ConstImm() | F32ConstImm() | F64ConstImm():
					tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(imm.value)))

		return tokens, instr.size

	def lift_function_preamble(self, data: bytes, addr: int, il: LowLevelILFunction):
		wasm_obj: Wasm = Architecture['WASM'].wasm_obj
		function = [func for func in wasm_obj.functions if func.start_addr == addr][0]
		log_info("LIFTING {}".format(function.name))
		# TODO: Create a register class to allowed
		# rbp.push()
		# rbp.set(rsp)
		# rsp.add(0x41)
		# while it assumes a default size
		il.append(il.push(self.address_size, il.reg(self.address_size, 'rbp')))
		il.append(il.set_reg(self.address_size, 'rbp', il.reg(self.address_size, 'rsp')))
		sz = sum([var.count*var.type.get_size() for var in function.locals])
		il.append(il.set_reg(self.address_size, 'rsp', il.add(self.address_size, il.reg(self.address_size, 'rsp'), il.const(self.address_size, sz))))


	def get_instruction_low_level_il(self, data, addr, il):
		instr = disasm(BytesIO(data))
		wasm_obj: Wasm = Architecture['WASM'].wasm_obj
		if instr.size == 0:
			return 0

		if addr in [func.start_addr for func in wasm_obj.functions]:
			self.lift_function_preamble(data, addr, il)

		match instr.mnemonic:
			case 'nop':
				il.append(il.nop())
			case 'i32.const' | 'i64.const' | 'f32.const' | 'f64.const':
				sz = instr.immediates.size
				val = instr.immediates.value
				if instr.mnemonic == 'f32.const':
					il.append(il.push(sz, il.float_const_single(val)))
				elif instr.mnemonic == 'f64.const':
					il.append(il.push(sz, il.float_const_single(val)))
				else:
					il.append(il.push(sz, il.const(sz, val)))
			case 'call':
				function = wasm_obj.functions[instr.immediates.callee]
				il.append(il.call(il.const_pointer(self.address_size, function.start_addr)))

			case 'global.get' | 'global.set':
				glob = wasm_obj.globals[instr.immediates.id]
				sz = glob.get_init_size()
				if instr.mnemonic == 'global.get':
					il.append(il.push(sz, il.load(sz, il.const_pointer(self.address_size, glob.start_addr))))
				else:
					il.append(il.store(sz, il.const_pointer(self.address_size, glob.start_addr), il.pop(sz)))
					# il.reg_stack_top_relative()
			case 'end' if addr not in wasm_obj.function_ends:
				il.append(il.nop())
			case 'return' | 'end':
				il.append(il.set_reg(self.address_size, 'rsp', il.reg(self.address_size, 'rbp')))
				il.append(il.set_reg(self.address_size, 'rbp', il.pop(self.address_size)))
				il.append(il.ret(il.pop(self.address_size)))
			case _:
				il.append(il.unimplemented())
		return instr.size


WASM.register()