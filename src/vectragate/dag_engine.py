"""Layer 1 Kahn topological validator and branchless logic-gate DAG evaluator."""

from __future__ import annotations

from collections.abc import Sequence

from vectragate.models import (
    MAX_DAG_NODES,
    MAX_REGISTERS,
    DagNode,
    NodeOp,
)


def _eval_comparator(op: NodeOp, reg_val: int, threshold: int) -> int:
    """Evaluate a register comparator node into bit 0 or 1."""
    assert isinstance(op, NodeOp)
    assert type(reg_val) is int
    if op == NodeOp.CMP_GT:
        return 1 if reg_val > threshold else 0
    if op == NodeOp.CMP_GE:
        return 1 if reg_val >= threshold else 0
    if op == NodeOp.CMP_LT:
        return 1 if reg_val < threshold else 0
    if op == NodeOp.CMP_LE:
        return 1 if reg_val <= threshold else 0
    if op == NodeOp.CMP_EQ:
        return 1 if reg_val == threshold else 0
    return 1 if reg_val != threshold else 0


def _eval_gate(op: NodeOp, inputs: tuple[int, ...], outputs: dict[int, int]) -> int:
    """Evaluate a combinational bitwise logic gate over upstream bits."""
    assert len(inputs) >= 1
    assert isinstance(outputs, dict)
    if op == NodeOp.NOT:
        return (outputs[inputs[0]] ^ 1) & 1
    if op in (NodeOp.AND, NodeOp.NAND):
        acc = 1
        for inp in inputs:
            acc &= outputs[inp] & 1
        return (acc ^ 1) & 1 if op == NodeOp.NAND else acc
    if op in (NodeOp.OR, NodeOp.NOR):
        acc = 0
        for inp in inputs:
            acc |= outputs[inp] & 1
        return (acc ^ 1) & 1 if op == NodeOp.NOR else acc
    parity = 0
    for inp in inputs:
        parity ^= outputs[inp] & 1
    return parity


def _eval_single_node(
    node: DagNode,
    outputs: dict[int, int],
    registers: Sequence[int],
) -> int:
    """Evaluate one comparator or combinational gate node."""
    assert isinstance(node, DagNode)
    assert len(registers) == MAX_REGISTERS
    if node.op in (
        NodeOp.CMP_GT,
        NodeOp.CMP_GE,
        NodeOp.CMP_LT,
        NodeOp.CMP_LE,
        NodeOp.CMP_EQ,
        NodeOp.CMP_NE,
    ):
        return _eval_comparator(node.op, registers[node.target_reg], node.threshold)
    return _eval_gate(node.op, node.inputs, outputs)


def _build_dag_graph(
    nodes: Sequence[DagNode],
) -> tuple[dict[int, DagNode], dict[int, int], dict[int, list[int]]]:
    """Validate unique node IDs and input references, returning graph tables."""
    assert nodes is not None
    assert len(nodes) <= MAX_DAG_NODES
    nodes_by_id: dict[int, DagNode] = {}
    for node in nodes:
        if node.node_id in nodes_by_id:
            raise ValueError(f"Duplicate node_id: {node.node_id}")
        nodes_by_id[node.node_id] = node
    in_degree: dict[int, int] = {nid: len(n.inputs) for nid, n in nodes_by_id.items()}
    children: dict[int, list[int]] = {nid: [] for nid in nodes_by_id}
    for nid, node in nodes_by_id.items():
        for inp in node.inputs:
            if inp not in nodes_by_id:
                raise ValueError(f"Node {nid} references unknown input {inp}")
            children[inp].append(nid)
    return nodes_by_id, in_degree, children


def validate_and_sort_dag(nodes: Sequence[DagNode]) -> tuple[int, ...]:
    """Run Kahn's iterative topological sort with ascending node_id tie-breaking."""
    if len(nodes) > MAX_DAG_NODES:
        raise ValueError(f"DAG node count {len(nodes)} exceeds {MAX_DAG_NODES}")
    nodes_by_id, in_degree, children = _build_dag_graph(nodes)
    assert len(nodes_by_id) == len(nodes)
    assert len(in_degree) == len(nodes)
    ready: list[int] = sorted(nid for nid, deg in in_degree.items() if deg == 0)
    topo: list[int] = []
    while ready:
        curr = ready.pop(0)
        topo.append(curr)
        for child in children[curr]:
            in_degree[child] -= 1
            if in_degree[child] == 0:
                ready.append(child)
        ready.sort()
    if len(topo) != len(nodes_by_id):
        raise ValueError("Cyclic DAG detected")
    return tuple(topo)


def evaluate_dag(
    nodes_by_id: dict[int, DagNode],
    topo_order: Sequence[int],
    registers: Sequence[int],
) -> tuple[bool, int, tuple[int, ...]]:
    """Evaluate acyclic interlock DAG in topological order against registers."""
    assert len(topo_order) == len(nodes_by_id)
    assert len(registers) == MAX_REGISTERS
    outputs: dict[int, int] = {}
    ordered_bits: list[int] = []
    tripped_id = -1
    for nid in topo_order:
        node = nodes_by_id[nid]
        bit = _eval_single_node(node, outputs, registers) & 1
        outputs[nid] = bit
        ordered_bits.append(bit)
        if node.is_hazard_output and bit == 1 and (tripped_id == -1 or nid < tripped_id):
            tripped_id = nid
    return tripped_id != -1, tripped_id, tuple(ordered_bits)
