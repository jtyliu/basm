from binaryninja import *

def function_arg_cc(analysis_context):
    # Reverse the parameters inside all function calls
    function = Function(handle=core.BNAnalysisContextGetFunction(analysis_context))
    bv = function.view
    if bv.arch == Architecture['WASM']: # Yeah, i dont think this is the best way of doing this
        for idx in range(function.mlil[-1].instr_index):
            il = function.mlil[idx]
            if isinstance(il, Call):
                assert il.operation == MediumLevelILOperation.MLIL_CALL
                output_len, output_expr, dest, params_len, _ = il.instr.operands
                # Get the params_expr list and reverse it
                param_expr = function.mlil.add_operand_list(il._get_int_list(3)[::-1])
                function.mlil.replace_expr(il, function.mlil.expr(MediumLevelILOperation.MLIL_CALL, output_len, output_expr, dest, params_len, param_expr))
    function.mlil.generate_ssa_form()

FunctionArgsWorkflow = Workflow().clone("WasmFunctionArgsWorkflow")
FunctionArgsWorkflow.register_activity(Activity("WasmFunctionArg",action=function_arg_cc))
FunctionArgsWorkflow.insert('core.function.analyzeTailCalls',['WasmFunctionArg'])
FunctionArgsWorkflow.register()