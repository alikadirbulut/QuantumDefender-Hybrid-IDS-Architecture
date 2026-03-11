# ===============================================================
# QuantumDefender — Dummy ONNX Model (Fully Compatible vFinal)
# ===============================================================
# ✅ IR v11, Opset v13, Correct MatMul dimensions
# ✅ No external dependencies, works on any ONNXRuntime
# ===============================================================

import numpy as np
import onnx
from onnx import helper, TensorProto

# ---- Define input/output ----
input_tensor = helper.make_tensor_value_info("float_input", TensorProto.FLOAT, [None, 4])
output_tensor = helper.make_tensor_value_info("output", TensorProto.FLOAT, [None, 2])

# ---- Define weights & bias ----
# NOTE: Transposed to shape [4, 2] so MatMul([N,4],[4,2]) -> [N,2]
W = np.array([
    [0.6, -0.6],
    [0.3, -0.3],
    [0.1, -0.1],
    [-0.2, 0.2]
], dtype=np.float32)
b = np.array([0.1, -0.1], dtype=np.float32)

# ---- Nodes ----
matmul = helper.make_node("MatMul", ["float_input", "W"], ["matmul_out"])
add = helper.make_node("Add", ["matmul_out", "b"], ["add_out"])
softmax = helper.make_node("Softmax", ["add_out"], ["output"], axis=1)

# ---- Graph ----
graph = helper.make_graph(
    [matmul, add, softmax],
    "QuantumDefenderDummyModel",
    [input_tensor],
    [output_tensor],
    initializer=[
        helper.make_tensor("W", TensorProto.FLOAT, W.shape, W.flatten()),
        helper.make_tensor("b", TensorProto.FLOAT, b.shape, b.flatten()),
    ]
)

# ---- Model metadata ----
opset_imports = [helper.make_operatorsetid("", 13)]
model = helper.make_model(
    graph,
    producer_name="QuantumDefender-DummyGen",
    ir_version=11,
    opset_imports=opset_imports
)

onnx.save(model, "lite_model.onnx")
print("✅ Dummy ONNX model (IR=11, opset=13, fixed MatMul) created successfully.")
