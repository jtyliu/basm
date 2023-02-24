from binaryninja import *
from .section import Wasm, Import, FunctionBody
from .disasm import *
from .callingConvention import WasmCallingConvention
from io import BytesIO


class WASM(Architecture):
	name = 'WASM'
	address_size = 8 # 4 byte addresses???
	default_int_size = 8 # 4 byte integers
	instr_alignment = 1	# No instruction alignment
	max_instr_length = 100

	regs = {
		'rsp': RegisterInfo('rsp', address_size),
		'rbp': RegisterInfo('rbp', address_size),
		'rax': RegisterInfo('rax', 8),
		'eax': RegisterInfo('eax', 4),
		'rbx': RegisterInfo('rbx', 8),
		'ebx': RegisterInfo('ebx', 4),
		'rcx': RegisterInfo('rcx', 8),
		'ecx': RegisterInfo('ecx', 4),
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
						tokens.append(InstructionTextToken(InstructionTextTokenType.LocalVariableToken, "var{}".format(imm.id)))
					elif 'global' in instr.mnemonic:
						global_var = "global{}".format(imm.id)
						tokens.append(InstructionTextToken(InstructionTextTokenType.DataSymbolToken, global_var, wasm_obj.globals[imm.id].start_addr))
				# case MemoryImm():
				# 	tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, str(imm.offset)))
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
		sz = sum([var.count*self.address_size for var in function.locals])
		il.append(il.set_reg(self.address_size, 'rsp', il.sub(self.address_size, il.reg(self.address_size, 'rsp'), il.const(self.address_size, sz))))


	def get_instruction_low_level_il(self, data, addr, il):
		instr = disasm(BytesIO(data))
		wasm_obj: Wasm = Architecture['WASM'].wasm_obj
		if instr.size == 0:
			return 0

		if addr in [func.start_addr for func in wasm_obj.functions]:
			self.lift_function_preamble(data, addr, il)
		
		cur_function = wasm_obj.get_function(addr) # Note: This is scuffed
		if cur_function is None:
			log_error("No function found at {}, will attempt to lift regardless".format(hex(addr)))

		def lift_math(sz, operator, only_regs=False):
			bx = 'ebx' if sz == 4 else 'rbx'
			cx = 'ecx' if sz == 4 else 'rcx'
			il.append(il.set_reg(sz, bx, il.pop(self.address_size)))
			il.append(il.set_reg(sz, cx, il.pop(self.address_size)))
			if not only_regs:
				il.append(il.push(self.address_size, operator(sz, il.reg(sz, bx), il.reg(sz, cx))))

		match instr.mnemonic:
			case 'nop':
				il.append(il.nop())
			case 'i32.add':
				lift_math(4, il.add)
			case 'i32.sub':
				lift_math(4, il.sub)
			case 'i32.store':
				imm = instr.immediates
				sz = 4
				lift_math(sz, il.store, only_regs=True)
				il.append(il.store(sz, il.add(sz, il.reg(sz, 'ecx'), il.const(sz, imm.offset)), il.reg(sz, 'ebx')))
			case 'i64.store':
				imm = instr.immediates
				sz = 8
				lift_math(sz, il.store, only_regs=True)
				il.append(il.store(sz, il.add(sz, il.reg(sz, 'rcx'), il.const(sz, imm.offset)), il.reg(sz, 'rbx')))
			case 'i64.load' | 'i32.load':
				imm = instr.immediates
				if instr.mnemonic == 'i64.load':
					sz = 8
				else:
					sz = 4
				il.append(il.push(self.address_size, il.load(sz, il.add(sz, il.pop(self.address_size), il.const(sz, imm.offset)))))
			case 'i32.const' | 'i64.const' | 'f32.const' | 'f64.const':
				sz = instr.immediates.size
				val = instr.immediates.value
				if instr.mnemonic == 'f32.const':
					il.append(il.push(self.address_size, il.float_const_single(val)))
				elif instr.mnemonic == 'f64.const':
					il.append(il.push(self.address_size, il.float_const_single(val)))
				else:
					il.append(il.push(self.address_size, il.const(sz, val)))
			case 'call':
				function: FunctionBody = wasm_obj.functions[instr.immediates.callee]
				ret_val = function.get_return_val()
				if ret_val:
					il.append(il.call(il.const_pointer(self.address_size, function.start_addr)))
					il.append(il.push(self.address_size, il.reg(ret_val.get_size(), 'rax')))
				else:
					il.append(il.call(il.const_pointer(self.address_size, function.start_addr)))
			case 'local.get' | 'local.set':
				id = instr.immediates.id
				var = cur_function.get_var(id)
				is_param, offset = cur_function.get_offset(id) 
				sz = var.get_size()
				if is_param:
					var_offset = il.add(self.address_size, il.reg(self.address_size, 'rbp'), il.const(self.address_size, offset + 0x10))
				else:
					var_offset = il.sub(self.address_size, il.reg(self.address_size, 'rbp'), il.const(self.address_size, offset + 0x8)) # so we're not overwriting saved_rbp
				# We can straight up use size cause wasm will throw an error if it tries to pop a i64 into i32 or any other case
				# throwing a type mismatch
				if instr.mnemonic == 'local.get':
					il.append(il.push(self.address_size, il.load(sz, var_offset)))
				else:
					il.append(il.store(sz, var_offset, il.pop(self.address_size)))
			case 'drop':
				il.append(il.pop(self.address_size))
			case 'global.get' | 'global.set':
				glob = wasm_obj.globals[instr.immediates.id]
				sz = glob.get_init_size()
				if instr.mnemonic == 'global.get':
					il.append(il.push(self.address_size, il.load(sz, il.const_pointer(self.address_size, glob.start_addr))))
				else:
					il.append(il.store(sz, il.const_pointer(self.address_size, glob.start_addr), il.pop(self.address_size)))
					# il.reg_stack_top_relative()
			case 'end' if addr not in wasm_obj.function_ends:
				il.append(il.nop())
			case 'block':
				il.append(il.nop())
			case 'return' | 'end':
				il.append(il.set_reg(self.address_size, 'rax', il.pop(self.address_size)))
				il.append(il.set_reg(self.address_size, 'rsp', il.reg(self.address_size, 'rbp')))
				il.append(il.set_reg(self.address_size, 'rbp', il.pop(self.address_size)))
				il.append(il.ret(il.pop(self.address_size)))
			case _:
				il.append(il.unimplemented())
		return instr.size


WASM.register()
Architecture['WASM'].register_calling_convention(WasmCallingConvention(Architecture['WASM'],'default'))
Architecture['WASM'].standalone_platform.default_calling_convention = Architecture['WASM'].calling_conventions["default"]
