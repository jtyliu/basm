from binaryninja import *
from .section import Wasm, Import, FunctionBody
from .disasm import *
from .callingConvention import WasmCallingConvention
from io import BytesIO

def lift_function_preamble(data: bytes, addr: int, il: LowLevelILFunction, address_size: int):
    wasm_obj: Wasm = Architecture['WASM'].wasm_obj
    function = [func for func in wasm_obj.functions if func.start_addr == addr][0]
    # TODO: Create a register class to allowed
    # rbp.push()
    # rbp.set(rsp)
    # rsp.add(0x41)
    # while it assumes a default size
    il.append(il.push(address_size, il.reg(address_size, 'rbp')))
    il.append(il.set_reg(address_size, 'rbp', il.reg(address_size, 'rsp')))
    sz = sum([var.count*address_size for var in function.locals])
    il.append(il.set_reg(address_size, 'rsp', il.sub(address_size, il.reg(address_size, 'rsp'), il.const(address_size, sz))))

def lift(data: bytes, addr: int, il: LowLevelILFunction, address_size: int):
    instr = disasm(BytesIO(data))
    wasm_obj: Wasm = Architecture['WASM'].wasm_obj
    if instr.size == 0:
        return 0

    if addr in [func.start_addr for func in wasm_obj.functions]:
        lift_function_preamble(data, addr, il, address_size)
    
    cur_function = wasm_obj.get_function(addr) # Note: This is scuffed
    if cur_function is None:
        log_error("No function found at {}, will attempt to lift regardless".format(hex(addr)))

    def arith_pop_two(sz, operator=None):
        bx = 'ebx' if sz == 4 else 'rbx'
        cx = 'ecx' if sz == 4 else 'rcx'
        il.append(il.set_reg(sz, bx, il.pop(address_size)))
        il.append(il.set_reg(sz, cx, il.pop(address_size)))
        if operator:
            il.append(il.push(address_size, operator(sz, il.reg(sz, bx), il.reg(sz, cx))))

    log_debug(instr)
    match instr:
        case Instruction('nop', _, _, _):
            il.append(il.nop())
        case Instruction('block', _, _, _):
            il.append(il.nop())
        case Instruction('loop', _, _, _):
            il.append(il.nop())
        case Instruction('br', _, _, _):
            dest = wasm_obj.depth_addr_mapping[addr]
            label = il.get_label_for_address(Architecture['WASM'], dest)
            if label:
                il.append(il.goto(label))
            else:
                il.append(il.jump(il.const_pointer(address_size, dest)))
        case Instruction('br_if', _, _, _):
            true = wasm_obj.depth_addr_mapping[addr]
            false = addr + instr.size
            t = il.get_label_for_address(Architecture['WASM'], true)
            f = il.get_label_for_address(Architecture['WASM'], false)
            tl = LowLevelILLabel()
            fl = LowLevelILLabel()
            if t is not None and f is not None:
                il.append(il.if_expr(il.compare_equal(address_size, il.pop(address_size), il.const(address_size, 1)), t, f))
            elif t is not None:
                il.append(il.if_expr(il.compare_equal(address_size, il.pop(address_size), il.const(address_size, 1)), t, fl))
                il.mark_label(fl)
                il.append(il.jump(il.const_pointer(address_size, false)))
            elif f is not None:
                il.append(il.if_expr(il.compare_equal(address_size, il.pop(address_size), il.const(address_size, 1)), tl, f))
                il.mark_label(tl)
                il.append(il.jump(il.const_pointer(address_size, true)))
            else:
                il.append(il.if_expr(il.compare_equal(address_size, il.pop(address_size), il.const(address_size, 1)), tl, fl))
                il.mark_label(tl)
                il.append(il.jump(il.const_pointer(address_size, true)))
                il.mark_label(fl)
                il.append(il.jump(il.const_pointer(address_size, false)))


        case Instruction('end', _, _, _) if addr not in wasm_obj.function_ends:
            il.append(il.nop())
        case Instruction('return' | 'end', _, _, _):
            il.append(il.set_reg(address_size, 'rax', il.pop(address_size)))
            il.append(il.set_reg(address_size, 'rsp', il.reg(address_size, 'rbp')))
            il.append(il.set_reg(address_size, 'rbp', il.pop(address_size)))
            il.append(il.ret(il.pop(address_size)))
        case Instruction('call', _, CallImm(callee), _):
            function: FunctionBody = wasm_obj.functions[callee]
            ret_val = function.get_return_val()
            if ret_val:
                il.append(il.call(il.const_pointer(address_size, function.start_addr)))
                il.append(il.push(address_size, il.reg(ret_val.get_size(), 'rax')))
            else:
                il.append(il.call(il.const_pointer(address_size, function.start_addr)))
        case Instruction('drop', _, _, _):
            il.append(il.pop(address_size))
        case Instruction('local.get' | 'local.set' | 'local.tee', _, LocalVarImm(id), _):
            var = cur_function.get_var(id)
            is_param, offset = cur_function.get_offset(id) 
            sz = var.get_size()
            if is_param:
                var_offset = il.add(address_size, il.reg(address_size, 'rbp'), il.const(address_size, offset + 0x10))
            else:
                var_offset = il.sub(address_size, il.reg(address_size, 'rbp'), il.const(address_size, offset + 0x8)) # so we're not overwriting saved_rbp
            # We can straight up use size cause wasm will throw an error if it tries to pop a i64 into i32 or any other case
            # throwing a type mismatch
            if instr.mnemonic == 'local.set' or instr.mnemonic == 'local.tee':
                il.append(il.store(sz, var_offset, il.pop(address_size)))
            if instr.mnemonic == 'local.get' or instr.mnemonic == 'local.tee':
                il.append(il.push(address_size, il.load(sz, var_offset)))
        case Instruction('global.get' | 'global.set', _, LocalVarImm(id), _):
            glob = wasm_obj.globals[id]
            sz = glob.get_init_size()
            if instr.mnemonic == 'global.get':
                il.append(il.push(address_size, il.load(sz, il.const_pointer(address_size, glob.start_addr))))
            else:
                il.append(il.store(sz, il.const_pointer(address_size, glob.start_addr), il.pop(address_size)))
        case Instruction('i32.store' | 'i64.store' | 'i64.load' | 'i32.load' | 'f32.load' | 'f32.store' | 'f64.load' | 'f64.store', _, MemoryImm(_, offset), _):
            if '32' in instr.mnemonic:
                sz, bx, cx = 4, 'ebx', 'ecx'
            else:
                sz, bx, cx = 8, 'rbx', 'rcx'
            if 'load' in instr.mnemonic:
                il.append(il.push(address_size, il.load(sz, il.add(sz, il.pop(address_size), il.const(sz, offset)))))
            else:
                arith_pop_two(sz)
                il.append(il.store(sz, il.add(sz, il.reg(sz, cx), il.const(sz, offset)), il.reg(sz, bx)))
        case Instruction('i32.const' | 'i64.const' | 'f32.const' | 'f64.const', _, ConstImm(val, sz), _):
            if instr.mnemonic == 'f32.const':
                il.append(il.push(address_size, il.float_const_single(val)))
            elif instr.mnemonic == 'f64.const':
                il.append(il.push(address_size, il.float_const_single(val)))
            else:
                il.append(il.push(address_size, il.const(sz, val)))
        case _:
            mnemonic = instr.mnemonic
            if '32' in mnemonic:
                sz = 4
            elif '64' in mnemonic:
                sz = 8
            else:
                sz = None
            match mnemonic:
                case 'i32.add' | 'i64.add':
                    arith_pop_two(sz, il.add)
                case 'i32.sub' | 'i64.sub':
                    arith_pop_two(sz, il.sub)
                case 'i32.mul' | 'i64.mul':
                    arith_pop_two(sz, il.mult)
                case 'i32.div_s' | 'i64.div_s':
                    arith_pop_two(sz, il.div_signed)
                case 'i32.div_u' | 'i64.div_u':
                    arith_pop_two(sz, il.div_unsigned)
                case 'i32.rem_s' | 'i64.rem_s':
                    arith_pop_two(sz, il.mod_signed)
                case 'i32.rem_u' | 'i64.rem_u':
                    arith_pop_two(sz, il.mod_unsigned)
                case 'i32.rem_u' | 'i64.rem_u':
                    arith_pop_two(sz, il.mod_unsigned)
                case 'i32.and' | 'i64.and':
                    arith_pop_two(sz, il.and_expr)
                case 'i32.or' | 'i64.or':
                    arith_pop_two(sz, il.or_expr)
                case 'i32.xor' | 'i64.xor':
                    arith_pop_two(sz, il.xor_expr)
                case 'i32.shl' | 'i64.shl':
                    arith_pop_two(sz, il.shift_left)
                case 'i32.shr_s' | 'i64.shr_s':
                    arith_pop_two(sz, il.arith_shift_right)
                case 'i32.shr_u' | 'i64.shr_u':
                    arith_pop_two(sz, il.logical_shift_right)
                case 'i32.rotl' | 'i64.rotl':
                    arith_pop_two(sz, il.rotate_left)
                case 'i32.rotr' | 'i64.rotr':
                    arith_pop_two(sz, il.rotate_right)
                case 'i32.eqz' | 'i64.eqz':
                    t = LowLevelILLabel()
                    f = LowLevelILLabel()
                    end = LowLevelILLabel()
                    il.append(il.if_expr(il.compare_equal(address_size, il.pop(address_size), il.const(address_size, 0)), t, f))
                    il.mark_label(t)
                    il.append(il.push(address_size, il.const(address_size, 1)))
                    il.append(il.goto(end))
                    il.mark_label(f)
                    il.append(il.push(address_size, il.const(address_size, 0)))
                    il.mark_label(end)
                case _:
                    il.append(il.unimplemented())
    return instr.size