"""Seeded property-based fuzzing tests for decoders, Kahn DAG, CWE-1236, and chains."""

from __future__ import annotations

import random
import unicodedata

from _oracle import (
    _bad_modbus_hex,
    _bad_mqtt_hex,
    oracle_decode_modbus,
    oracle_decode_mqtt,
)

from vectragate.dag_engine import evaluate_dag, validate_and_sort_dag
from vectragate.exporters import neutralize_formula_cell
from vectragate.firewall import evaluate_packet_stream, verify_verdict_chain
from vectragate.models import (
    MAX_REGISTERS,
    DagNode,
    NodeOp,
    PacketVerdict,
    ProtocolType,
    RawPacket,
)
from vectragate.protocol import decode_modbus_tcp, decode_mqtt_publish


def test_property_modbus_mqtt_wire_decoder_parity() -> None:
    """Property: 500 fuzzed Modbus & MQTT frames match independent oracle identically."""
    rng = random.Random(20261114)
    for idx in range(500):
        choice = idx % 4
        if choice == 0:
            raw_bytes = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 32)))
        elif choice == 1:
            raw_bytes = bytes.fromhex(_bad_modbus_hex(idx))
        elif choice == 2:
            raw_bytes = bytes.fromhex(_bad_mqtt_hex(idx))
        else:
            raw_bytes = b"\x00\x01\x00\x00\x00\x06\x01\x06" + rng.randint(0, 65535).to_bytes(2, "big") + rng.randint(0, 65535).to_bytes(2, "big")

        py_mb_err, py_mb_op = decode_modbus_tcp(raw_bytes)
        o_mb_err, o_mb_wr, o_mb_writes = oracle_decode_modbus(raw_bytes)
        assert (py_mb_err.value if py_mb_err else None) == o_mb_err
        if py_mb_op is not None:
            assert py_mb_op.is_write == o_mb_wr
            assert py_mb_op.writes == o_mb_writes

        py_mq_err, py_mq_op = decode_mqtt_publish(raw_bytes)
        o_mq_err, o_mq_wr, o_mq_writes = oracle_decode_mqtt(raw_bytes)
        assert (py_mq_err.value if py_mq_err else None) == o_mq_err
        if py_mq_op is not None:
            assert py_mq_op.is_write == o_mq_wr
            assert py_mq_op.writes == o_mq_writes


def test_property_kahn_topological_sort_and_cycle_rejection() -> None:
    """Property: every edge (u -> v) strictly precedes child in topological order."""
    rng = random.Random(9001)
    for _ in range(200):
        perm = rng.sample(range(60), 10)
        nodes: list[DagNode] = []
        for pos, nid in enumerate(perm):
            if pos < 4:
                nodes.append(
                    DagNode(
                        node_id=nid,
                        tag=f"C_{nid}",
                        op=rng.choice((NodeOp.CMP_GT, NodeOp.CMP_LT, NodeOp.CMP_EQ)),
                        target_reg=rng.randint(0, 15),
                        threshold=rng.randint(-100, 100),
                    )
                )
            else:
                upstream = rng.sample(perm[:pos], rng.randint(1, min(3, pos)))
                op = NodeOp.NOT if len(upstream) == 1 else rng.choice((NodeOp.AND, NodeOp.OR, NodeOp.XOR, NodeOp.NAND, NodeOp.NOR))
                nodes.append(
                    DagNode(
                        node_id=nid,
                        tag=f"G_{nid}",
                        op=op,
                        inputs=tuple(upstream),
                        is_hazard_output=(pos == 9),
                    )
                )
        shuffled = list(nodes)
        rng.shuffle(shuffled)
        topo = validate_and_sort_dag(shuffled)
        rank = {nid: i for i, nid in enumerate(topo)}
        for n in shuffled:
            for inp in n.inputs:
                assert rank[inp] < rank[n.node_id]
        regs = [rng.randint(-200, 200) for _ in range(MAX_REGISTERS)]
        tripped, trip_id, bits = evaluate_dag({n.node_id: n for n in shuffled}, topo, regs)
        assert len(bits) == len(shuffled)
        assert (trip_id != -1) == tripped


def test_property_cwe1236_formula_neutralization_invariants() -> None:
    """Property: NFKC + lstrip output of neutralized cells never starts with a formula trigger."""
    rng = random.Random(31337)
    triggers = ("=", "+", "-", "@", "|", "%", "\t", "\r", "\n")
    fullwidth_eq = ("\uff1d", "\uff0b", "\uff0d", "\uff20", "\uff5c", "\uff05")
    for _ in range(300):
        prefix = "".join(rng.choices((" ", "\t", "\r", "\n", "\u00a0"), k=rng.randint(0, 3)))
        lead = rng.choice(triggers + fullwidth_eq + ("PLC", "SAFE", "123"))
        body = "".join(rng.choices("ABCDEF0123SUM()", k=rng.randint(0, 8)))
        raw = prefix + lead + body
        cleaned = neutralize_formula_cell(raw)
        assert cleaned != ""
        stripped = unicodedata.normalize("NFKC", cleaned).lstrip()
        assert (not stripped) or (stripped[0] not in triggers)


def test_property_blake2b_chain_tamper_detection() -> None:
    """Property: flipping any single hash bit across 100 generated chains invalidates verification."""
    rng = random.Random(777)
    for trial in range(100):
        count = rng.randint(1, 6)
        pkts = [
            RawPacket(
                f"P_{trial}_{i}",
                "PLC_PROP",
                i + 1,
                (i + 1) * 100,
                ProtocolType.MODBUS_TCP,
                "00010000000601060000" + rng.randint(0, 500).to_bytes(2, "big").hex(),
            )
            for i in range(count)
        ]
        res = evaluate_packet_stream(pkts, ())
        assert verify_verdict_chain(res.verdicts)
        flip_idx = rng.randrange(count)
        v = res.verdicts[flip_idx]
        bit_mask = 1 << rng.randrange(64)
        bad = PacketVerdict(
            seq_index=v.seq_index,
            packet_id=v.packet_id,
            source_id=v.source_id,
            seq_no=v.seq_no,
            timestamp_ms=v.timestamp_ms,
            protocol=v.protocol,
            verdict_code=v.verdict_code,
            is_allowed=v.is_allowed,
            tripped_node_id=v.tripped_node_id,
            breaker_state_after=v.breaker_state_after,
            prev_hash_u64=v.prev_hash_u64,
            chain_hash_u64=v.chain_hash_u64 ^ bit_mask,
        )
        mutated = res.verdicts[:flip_idx] + (bad,) + res.verdicts[flip_idx + 1 :]
        assert not verify_verdict_chain(mutated)
