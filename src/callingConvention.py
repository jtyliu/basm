from binaryninja import CallingConvention

class WasmCallingConvention(CallingConvention):
    name = "wasm_cc"
    int_return_reg = 'rax'
    int_arg_regs = [] # Indicate it's stack based
    callee_saved_regs = ['rbp']
    caller_saved_regs = ['rax']
    stack_adjusted_on_return = True # ???
