from .src.architecture import *
from .src.binaryview import *
from .src.workflow import *

WASM.register()
Architecture['WASM'].register_calling_convention(WasmCallingConvention(Architecture['WASM'],'default'))
Architecture['WASM'].standalone_platform.default_calling_convention = Architecture['WASM'].calling_conventions["default"]

WasmView.register()

FunctionArgsWorkflow = Workflow().clone("WasmFunctionArgsWorkflow")
FunctionArgsWorkflow.register_activity(Activity("WasmFunctionArg",action=function_arg_cc))
FunctionArgsWorkflow.insert('core.function.analyzeTailCalls',['WasmFunctionArg'])
FunctionArgsWorkflow.register()