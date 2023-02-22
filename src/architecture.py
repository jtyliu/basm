from binaryninja import *
from .section import Wasm, Import, FunctionBody
from .disasm import *
from io import BytesIO


class WASM(Architecture):
	name = 'WASM'
	address_size = 4 # 4 byte addresses???
	default_int_size = 4 # 4 byte integers
	instr_alignment = 1	# No instruction alignment
	max_instr_length = 100

	regs = {
		'SP': RegisterInfo('SP', 8),
	}

	stack_pointer = "SP"

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
				# log_info("WTF {}".format(hex(addr)))
				# for addr in wasm_obj.depth_addr_mapping[addr]:
				# 	print(hex(addr))
				# 	result.add_branch(BranchType.UnresolvedBranch, addr)
				pass
			case "end":
				if addr in wasm_obj.function_ends:
				# 	log_info("STOP YES {}".format(hex(addr)))
				# 	# Quick hack to stop disassembler from going past the "end" instruction
					result.add_branch(BranchType.FunctionReturn)
				# else:
				# 	log_info("STOP BRANCHING {} {} {}".format(addr, hex(addr) if addr else "???", wasm_obj.function_ends))
				
		return result
	
	def get_function_name_text(self, addr):

		for function in Architecture['WASM'].wasm_obj.functions:
			if function.start_addr == addr:
				if isinstance(function, Import):
					return InstructionTextTokenType.ExternalSymbolToken, function.export_name
				elif isinstance(function, FunctionBody):
					return InstructionTextTokenType.CodeSymbolToken, function.name

	def get_instruction_text(self, data, addr):
		# log_info("Get text: "+str(data), hex(addr))
		try:
			instr = disasm(BytesIO(data))
		except Exception:
			return [], 0
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

	def get_instruction_low_level_il(self, data, addr, il):
		instr = disasm(BytesIO(data))
		wasm_obj: Wasm = Architecture['WASM'].wasm_obj
		if instr.size == 0:
			return 0
		match instr.mnemonic:
			case 'nop':
				il.append(il.nop())
			# case _:
			# 	il.append(il.unimplemented())
			# case 'i32.const' | 'i64.const' | 'f32.const' | 'f64.const':
			# 	sz = instr.immediates.size
			# 	il.append(il.push(sz, il.const(sz, instr.immediates.value)))
			# case 'global.get' | 'global.set':
			# 	glob = wasm_obj.globals[instr.immediates.id]
			# 	instr_val = glob.init[0]
			# 	sz = instr_val.immediates.size
			# 	if instr.mnemonic == 'global.get':
			# 		il.append(il.push(sz, il.load(sz, il.const_pointer(self.address_size, glob.start_addr))))
			# 	else:
			# 		il.append(il.store(sz, il.const_pointer(self.address_size, glob.start_addr), il.pop(sz)))
			# 		il.reg_stack_top_relative()
			# case _:
			# 	il.append(il.unimplemented())
		return instr.size


WASM.register()