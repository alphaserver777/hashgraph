from mdrj.consensus import ConsensusEngine, MembershipEntry
from mdrj.models import Envelope, Event, EventClass


def make_event(
    *,
    source: str,
    ts_local: float,
    parents: list[str],
    path_nodes: list[tuple[str, float]],
) -> Envelope:
    event = Event.create(
        cls_name=EventClass.A,
        source=source,
        creator=source,
        ts_local=ts_local,
        vclock={source: int(ts_local)},
        parents=parents,
        self_parent_id=parents[0] if parents else None,
        other_parent_id=parents[1] if len(parents) > 1 else None,
        payload={"title": source},
    )
    return Envelope(
        event=event,
        path_meta=[{"node": node, "ts": ts} for node, ts in path_nodes],
    )


def test_rounds_and_round_received_for_simple_three_node_cluster():
    engine = ConsensusEngine("node-a")
    membership = [
        MembershipEntry(node_id="node-a", address="self:node-a", is_self=True),
        MembershipEntry(node_id="node-b", address="node-b:9002"),
        MembershipEntry(node_id="node-c", address="node-c:9003"),
    ]

    e1 = make_event(source="node-a", ts_local=1.0, parents=[], path_nodes=[("node-a", 1.0), ("node-b", 1.2), ("node-c", 1.4)])
    e2 = make_event(source="node-b", ts_local=2.0, parents=[e1.event.id], path_nodes=[("node-b", 2.0), ("node-a", 2.2), ("node-c", 2.4)])
    e3 = make_event(source="node-c", ts_local=3.0, parents=[e1.event.id, e2.event.id], path_nodes=[("node-c", 3.0), ("node-a", 3.1), ("node-b", 3.2)])

    states = engine.recompute(
        [e1.event, e2.event, e3.event],
        membership,
        {
            e1.event.id: e1.path_meta,
            e2.event.id: e2.path_meta,
            e3.event.id: e3.path_meta,
        },
    )
    by_id = {state.event_id: state for state in states}

    assert by_id[e1.event.id].round == 0
    assert by_id[e1.event.id].is_witness is True
    assert by_id[e1.event.id].round_received == 0
    assert by_id[e1.event.id].consensus_ts == 1.2

    assert by_id[e2.event.id].round == 0
    assert by_id[e2.event.id].is_witness is True
    assert by_id[e2.event.id].round_received is None
    assert by_id[e2.event.id].consensus_ts is None

    assert by_id[e3.event.id].round == 0
    assert by_id[e3.event.id].is_witness is True


def test_total_order_uses_round_received_then_consensus_ts_then_id():
    engine = ConsensusEngine("node-a")
    first = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=1.0,
        vclock={"node-a": 1},
        parents=[],
        payload={"title": "first"},
    )
    second = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=1.0,
        vclock={"node-b": 1},
        parents=[],
        payload={"title": "second"},
    )
    first.round_received = 1
    second.round_received = 1
    first.consensus_ts = 5.0
    second.consensus_ts = 6.0

    ordered = engine.total_order([second, first])
    assert [event.id for event in ordered] == [first.id, second.id]


def test_simultaneous_roots_converge_to_same_total_order_after_additional_witnesses():
    engine = ConsensusEngine("node-a")
    membership = [
        MembershipEntry(node_id="node-a", address="self:node-a", is_self=True),
        MembershipEntry(node_id="node-b", address="node-b:9002"),
        MembershipEntry(node_id="node-c", address="node-c:9003"),
    ]

    root_a = make_event(
        source="node-a",
        ts_local=1.0,
        parents=[],
        path_nodes=[("node-a", 1.0), ("node-b", 1.2), ("node-c", 1.4)],
    )
    root_b = make_event(
        source="node-b",
        ts_local=1.1,
        parents=[],
        path_nodes=[("node-a", 1.3), ("node-b", 1.1), ("node-c", 1.5)],
    )
    root_c = make_event(
        source="node-c",
        ts_local=1.2,
        parents=[],
        path_nodes=[("node-a", 1.4), ("node-b", 1.6), ("node-c", 1.2)],
    )
    a1 = make_event(
        source="node-a",
        ts_local=2.0,
        parents=[root_a.event.id, root_b.event.id],
        path_nodes=[("node-a", 2.0), ("node-b", 2.2), ("node-c", 2.3)],
    )
    b1 = make_event(
        source="node-b",
        ts_local=2.1,
        parents=[root_b.event.id, root_c.event.id],
        path_nodes=[("node-a", 2.4), ("node-b", 2.1), ("node-c", 2.5)],
    )
    c1 = make_event(
        source="node-c",
        ts_local=2.2,
        parents=[root_c.event.id, root_a.event.id],
        path_nodes=[("node-a", 2.6), ("node-b", 2.7), ("node-c", 2.2)],
    )
    a2 = make_event(
        source="node-a",
        ts_local=3.0,
        parents=[a1.event.id, b1.event.id],
        path_nodes=[("node-a", 3.0), ("node-b", 3.2), ("node-c", 3.3)],
    )
    b2 = make_event(
        source="node-b",
        ts_local=3.1,
        parents=[b1.event.id, c1.event.id],
        path_nodes=[("node-a", 3.4), ("node-b", 3.1), ("node-c", 3.5)],
    )
    c2 = make_event(
        source="node-c",
        ts_local=3.2,
        parents=[c1.event.id, a1.event.id],
        path_nodes=[("node-a", 3.6), ("node-b", 3.7), ("node-c", 3.2)],
    )

    envelopes = [root_a, root_b, root_c, a1, b1, c1, a2, b2, c2]
    path_meta = {envelope.event.id: envelope.path_meta for envelope in envelopes}

    states_forward = engine.recompute([envelope.event for envelope in envelopes], membership, path_meta)
    states_reverse = engine.recompute([envelope.event for envelope in reversed(envelopes)], membership, path_meta)

    ordered_forward = [event.id for event in engine.total_order([envelope.event for envelope in envelopes], states_forward)]
    ordered_reverse = [event.id for event in engine.total_order([envelope.event for envelope in reversed(envelopes)], states_reverse)]

    assert ordered_forward == ordered_reverse

    by_id = {state.event_id: state for state in states_forward}
    assert by_id[root_a.event.id].round_received == 1
    assert by_id[root_b.event.id].round_received == 1
    assert by_id[root_c.event.id].round_received == 1
    assert by_id[root_a.event.id].is_famous_witness is True
    assert by_id[root_b.event.id].is_famous_witness is True
    assert by_id[root_c.event.id].is_famous_witness is True
    assert by_id[root_a.event.id].fame_decided is True
    assert by_id[root_b.event.id].fame_decided is True
    assert by_id[root_c.event.id].fame_decided is True
    assert by_id[root_a.event.id].fame_decision_kind == "vote"
    assert by_id[root_b.event.id].fame_decision_kind == "vote"
    assert by_id[root_c.event.id].fame_decision_kind == "vote"
    assert by_id[root_a.event.id].fame_decision_round == 1
    assert by_id[root_b.event.id].fame_decision_round == 1
    assert by_id[root_c.event.id].fame_decision_round == 1
    assert by_id[root_a.event.id].fame_vote_round == 1
    assert by_id[root_b.event.id].fame_vote_round == 1
    assert by_id[root_c.event.id].fame_vote_round == 1
    assert by_id[root_a.event.id].fame_vote_yes == 3
    assert by_id[root_b.event.id].fame_vote_yes == 3
    assert by_id[root_c.event.id].fame_vote_yes == 3
    assert by_id[root_a.event.id].fame_vote_no == 0
    assert by_id[root_b.event.id].fame_vote_no == 0
    assert by_id[root_c.event.id].fame_vote_no == 0
    assert by_id[root_a.event.id].consensus_ts == 1.2
    assert by_id[root_b.event.id].consensus_ts == 1.3
    assert by_id[root_c.event.id].consensus_ts == 1.4


def test_consensus_timestamp_ignores_observations_outside_active_membership_snapshot():
    engine = ConsensusEngine("node-a")
    membership = [
        MembershipEntry(node_id="node-a", address="self:node-a", is_self=True),
        MembershipEntry(node_id="node-b", address="node-b:9002"),
    ]

    first = make_event(
        source="node-a",
        ts_local=1.0,
        parents=[],
        path_nodes=[("node-a", 1.0), ("node-b", 1.4), ("rogue-node", 99.0)],
    )
    second = make_event(
        source="node-b",
        ts_local=2.0,
        parents=[first.event.id],
        path_nodes=[("node-a", 2.2), ("node-b", 2.0), ("rogue-node", 100.0)],
    )

    states = engine.recompute(
        [first.event, second.event],
        membership,
        {
            first.event.id: first.path_meta,
            second.event.id: second.path_meta,
        },
    )
    by_id = {state.event_id: state for state in states}
    assert by_id[first.event.id].round_received == 0
    assert by_id[first.event.id].consensus_ts == 1.2


def test_famous_witness_resolution_can_use_later_rounds_not_only_next_round():
    engine = ConsensusEngine("node-a")
    membership_ids = ["node-a", "node-b"]

    root_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=1.0,
        vclock={"node-a": 1},
        parents=[],
        payload={"title": "root-a"},
    )
    root_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=1.1,
        vclock={"node-b": 1},
        parents=[],
        payload={"title": "root-b"},
    )
    round1_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=2.0,
        vclock={"node-a": 2},
        parents=[root_a.id],
        payload={"title": "round1-a"},
    )
    round2_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=3.0,
        vclock={"node-a": 3},
        parents=[round1_a.id],
        payload={"title": "round2-a"},
    )
    round2_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=3.1,
        vclock={"node-b": 3},
        parents=[root_b.id, round1_a.id],
        payload={"title": "round2-b"},
    )

    by_id = {
        root_a.id: root_a,
        root_b.id: root_b,
        round1_a.id: round1_a,
        round2_a.id: round2_a,
        round2_b.id: round2_b,
    }
    ancestor_cache = {}
    witnesses_by_round = {
        0: {"node-a": root_a.id, "node-b": root_b.id},
        1: {"node-a": round1_a.id},
        2: {"node-a": round2_a.id, "node-b": round2_b.id},
    }

    fame = engine._fame_decisions_by_round(
        witnesses_by_round,
        ancestor_cache,
        by_id,
        membership_ids,
    )

    assert fame[0][root_a.id]["famous"] is True
    assert fame[0][root_a.id]["decided"] is True
    assert fame[0][root_a.id]["decision_kind"] == "vote"
    assert fame[0][root_a.id]["decision_round"] == 2
    assert fame[0][root_a.id]["vote_round"] == 2
    assert fame[0][root_a.id]["vote_yes"] == 2
    assert fame[0][root_a.id]["vote_no"] == 0
    assert fame[0][root_b.id]["famous"] is False
    assert fame[0][root_b.id]["decided"] is False
    assert fame[0][root_b.id]["vote_round"] == 2
    assert fame[0][root_b.id]["vote_yes"] == 1
    assert fame[0][root_b.id]["vote_no"] == 1


def test_round_received_skips_partially_resolved_round_and_waits_for_later_quorum():
    engine = ConsensusEngine("node-a")
    membership_ids = ["node-a", "node-b"]

    genesis = Event.create(
        cls_name=EventClass.C,
        source="genesis",
        creator="genesis",
        ts_local=0.5,
        vclock={},
        parents=[],
        payload={"title": "genesis"},
    )
    root_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=1.0,
        vclock={"node-a": 1},
        parents=[genesis.id],
        payload={"title": "root-a"},
    )
    root_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=1.1,
        vclock={"node-b": 1},
        parents=[genesis.id],
        payload={"title": "root-b"},
    )
    round1_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=2.0,
        vclock={"node-a": 2},
        parents=[root_a.id],
        payload={"title": "round1-a"},
    )
    round2_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=3.0,
        vclock={"node-a": 3},
        parents=[round1_a.id],
        payload={"title": "round2-a"},
    )
    round2_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=3.1,
        vclock={"node-b": 3},
        parents=[root_b.id, round1_a.id],
        payload={"title": "round2-b"},
    )

    by_id = {
        genesis.id: genesis,
        root_a.id: root_a,
        root_b.id: root_b,
        round1_a.id: round1_a,
        round2_a.id: round2_a,
        round2_b.id: round2_b,
    }
    ancestor_cache = {}
    witnesses_by_round = {
        0: {"node-a": root_a.id, "node-b": root_b.id},
        1: {"node-a": round1_a.id},
        2: {"node-a": round2_a.id, "node-b": round2_b.id},
    }
    fame = engine._fame_decisions_by_round(
        witnesses_by_round,
        ancestor_cache,
        by_id,
        membership_ids,
    )
    famous = {
        round_no: {
            creator: witness_id
            for creator, witness_id in witnesses.items()
            if fame.get(round_no, {}).get(witness_id, {}).get("decided")
            and fame.get(round_no, {}).get(witness_id, {}).get("famous")
        }
        for round_no, witnesses in witnesses_by_round.items()
    }

    round_received = engine._round_received(
        genesis,
        witnesses_by_round,
        famous,
        fame,
        ancestor_cache,
        by_id,
        membership_ids,
    )
    assert round_received == 2


def test_recompute_exposes_vote_trace_for_fame_resolution():
    engine = ConsensusEngine("node-a")
    membership = [
        MembershipEntry(node_id="node-a", address="self:node-a", is_self=True),
        MembershipEntry(node_id="node-b", address="node-b:9002"),
    ]

    root_a = make_event(
        source="node-a",
        ts_local=1.0,
        parents=[],
        path_nodes=[("node-a", 1.0), ("node-b", 1.1)],
    )
    root_b = make_event(
        source="node-b",
        ts_local=1.1,
        parents=[],
        path_nodes=[("node-a", 1.2), ("node-b", 1.1)],
    )
    round1_a = make_event(
        source="node-a",
        ts_local=2.0,
        parents=[root_a.event.id],
        path_nodes=[("node-a", 2.0), ("node-b", 2.2)],
    )
    round2_a = make_event(
        source="node-a",
        ts_local=3.0,
        parents=[round1_a.event.id],
        path_nodes=[("node-a", 3.0), ("node-b", 3.2)],
    )
    round2_b = make_event(
        source="node-b",
        ts_local=3.1,
        parents=[root_b.event.id, round1_a.event.id],
        path_nodes=[("node-a", 3.3), ("node-b", 3.1)],
    )

    envelopes = [root_a, root_b, round1_a, round2_a, round2_b]
    states = engine.recompute(
        [envelope.event for envelope in envelopes],
        membership,
        {envelope.event.id: envelope.path_meta for envelope in envelopes},
    )
    by_id = {state.event_id: state for state in states}

    assert by_id[root_a.event.id].is_famous_witness is True
    assert by_id[root_a.event.id].fame_decided is True
    assert by_id[root_a.event.id].fame_decision_kind == "vote"
    assert by_id[root_a.event.id].fame_decision_round == 2
    assert by_id[root_a.event.id].fame_coin_used is False
    assert by_id[root_a.event.id].fame_coin_round is None
    assert by_id[root_a.event.id].fame_vote_round == 2
    assert by_id[root_a.event.id].fame_vote_yes == 2
    assert by_id[root_a.event.id].fame_vote_no == 0

    expected_coin = engine._deterministic_coin_choice(root_b.event.id, 2)
    assert by_id[root_b.event.id].is_famous_witness is expected_coin
    assert by_id[root_b.event.id].fame_decided is True
    assert by_id[root_b.event.id].fame_decision_kind == "coin_surrogate"
    assert by_id[root_b.event.id].fame_decision_round == 2
    assert by_id[root_b.event.id].fame_needs_coin is False
    assert by_id[root_b.event.id].fame_coin_used is True
    assert by_id[root_b.event.id].fame_coin_round == 2
    assert by_id[root_b.event.id].fame_vote_round == 2
    assert by_id[root_b.event.id].fame_vote_yes == 1
    assert by_id[root_b.event.id].fame_vote_no == 1


def test_later_round_does_not_fallback_to_direct_visibility_when_prior_votes_are_inconclusive():
    engine = ConsensusEngine("node-a")
    membership_ids = ["node-a", "node-b", "node-c"]

    root_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=1.0,
        vclock={"node-a": 1},
        parents=[],
        payload={"title": "root-a"},
    )
    root_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=1.1,
        vclock={"node-b": 1},
        parents=[],
        payload={"title": "root-b"},
    )
    root_c = Event.create(
        cls_name=EventClass.A,
        source="node-c",
        creator="node-c",
        ts_local=1.2,
        vclock={"node-c": 1},
        parents=[],
        payload={"title": "root-c"},
    )
    round1_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=2.0,
        vclock={"node-a": 2},
        parents=[root_a.id],
        payload={"title": "round1-a"},
    )
    round1_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=2.1,
        vclock={"node-b": 2},
        parents=[root_b.id],
        payload={"title": "round1-b"},
    )
    round1_c = Event.create(
        cls_name=EventClass.A,
        source="node-c",
        creator="node-c",
        ts_local=2.2,
        vclock={"node-c": 2},
        parents=[root_c.id],
        payload={"title": "round1-c"},
    )
    round2_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=3.0,
        vclock={"node-a": 3},
        parents=[round1_a.id],
        payload={"title": "round2-a"},
    )
    round2_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=3.1,
        vclock={"node-b": 3},
        parents=[round1_b.id],
        payload={"title": "round2-b"},
    )
    round2_c = Event.create(
        cls_name=EventClass.A,
        source="node-c",
        creator="node-c",
        ts_local=3.2,
        vclock={"node-c": 3},
        parents=[round1_c.id],
        payload={"title": "round2-c"},
    )

    by_id = {
        root_a.id: root_a,
        root_b.id: root_b,
        root_c.id: root_c,
        round1_a.id: round1_a,
        round1_b.id: round1_b,
        round1_c.id: round1_c,
        round2_a.id: round2_a,
        round2_b.id: round2_b,
        round2_c.id: round2_c,
    }
    ancestor_cache = {}
    witnesses_by_round = {
        0: {"node-a": root_a.id, "node-b": root_b.id, "node-c": root_c.id},
        1: {"node-a": round1_a.id, "node-b": round1_b.id, "node-c": round1_c.id},
        2: {"node-a": round2_a.id, "node-b": round2_b.id, "node-c": round2_c.id},
    }

    fame = engine._fame_decisions_by_round(
        witnesses_by_round,
        ancestor_cache,
        by_id,
        membership_ids,
    )

    assert fame[0][root_a.id]["decided"] is True
    assert fame[0][root_a.id]["coin_used"] is True
    assert fame[0][root_a.id]["decision_kind"] == "coin_surrogate"
    assert fame[0][root_a.id]["coin_round"] == 2
    assert fame[0][root_a.id]["famous"] is engine._deterministic_coin_choice(root_a.id, 2)
    assert fame[0][root_a.id]["vote_round"] == 2
    assert fame[0][root_a.id]["vote_yes"] == 0
    assert fame[0][root_a.id]["vote_no"] == 0


def test_fame_vote_history_tracks_votes_by_round_for_each_target_witness():
    engine = ConsensusEngine("node-a")
    membership_ids = ["node-a", "node-b"]

    root_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=1.0,
        vclock={"node-a": 1},
        parents=[],
        payload={"title": "root-a"},
    )
    root_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=1.1,
        vclock={"node-b": 1},
        parents=[],
        payload={"title": "root-b"},
    )
    round1_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=2.0,
        vclock={"node-a": 2},
        parents=[root_a.id],
        payload={"title": "round1-a"},
    )
    round2_a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=3.0,
        vclock={"node-a": 3},
        parents=[round1_a.id],
        payload={"title": "round2-a"},
    )
    round2_b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=3.1,
        vclock={"node-b": 3},
        parents=[root_b.id, round1_a.id],
        payload={"title": "round2-b"},
    )

    by_id = {
        root_a.id: root_a,
        root_b.id: root_b,
        round1_a.id: round1_a,
        round2_a.id: round2_a,
        round2_b.id: round2_b,
    }
    ancestor_cache = {}
    witnesses_by_round = {
        0: {"node-a": root_a.id, "node-b": root_b.id},
        1: {"node-a": round1_a.id},
        2: {"node-a": round2_a.id, "node-b": round2_b.id},
    }

    vote_history, fame = engine._fame_vote_history_and_decisions(
        witnesses_by_round,
        ancestor_cache,
        by_id,
        membership_ids,
    )

    assert vote_history[0][root_a.id][1] == {"node-a": True}
    assert vote_history[0][root_a.id][2] == {"node-a": True, "node-b": True}
    assert fame[0][root_a.id]["famous"] is True
    assert fame[0][root_a.id]["decision_round"] == 2
    assert fame[0][root_a.id]["decision_kind"] == "vote"

    assert vote_history[0][root_b.id][1] == {"node-a": False}
    assert vote_history[0][root_b.id][2] == {"node-a": None, "node-b": None}
    assert fame[0][root_b.id]["decided"] is True
    assert fame[0][root_b.id]["coin_used"] is True
    assert fame[0][root_b.id]["decision_kind"] == "coin_surrogate"
    assert fame[0][root_b.id]["coin_round"] == 2
    assert fame[0][root_b.id]["famous"] is engine._deterministic_coin_choice(root_b.id, 2)


def test_fame_history_resolver_uses_earliest_decisive_round():
    engine = ConsensusEngine("node-a")
    decision = engine._resolve_fame_from_vote_history(
        "target-witness",
        {
            1: {"node-a": True, "node-b": None},
            2: {"node-a": True, "node-b": True},
            3: {"node-a": False, "node-b": False},
        },
        threshold=2,
    )

    assert decision["famous"] is True
    assert decision["decided"] is True
    assert decision["decision_round"] == 2
    assert decision["decision_kind"] == "vote"
    assert decision["coin_used"] is False
    assert decision["coin_round"] is None
    assert decision["vote_round"] == 2
    assert decision["vote_yes"] == 2
    assert decision["vote_no"] == 0


def test_fame_history_resolver_uses_deterministic_coin_surrogate_after_multiple_unresolved_rounds():
    engine = ConsensusEngine("node-a")
    decision = engine._resolve_fame_from_vote_history(
        "target-witness",
        {
            1: {"node-a": True, "node-b": None, "node-c": None},
            2: {"node-a": None, "node-b": False, "node-c": None},
        },
        threshold=3,
    )

    assert decision["famous"] is engine._deterministic_coin_choice("target-witness", 2)
    assert decision["decided"] is True
    assert decision["decision_round"] == 2
    assert decision["decision_kind"] == "coin_surrogate"
    assert decision["needs_coin"] is False
    assert decision["coin_used"] is True
    assert decision["coin_round"] == 2
    assert decision["vote_round"] == 2
    assert decision["vote_yes"] == 0
    assert decision["vote_no"] == 1


def test_fame_history_resolver_does_not_require_coin_after_only_initial_vote_round():
    engine = ConsensusEngine("node-a")
    decision = engine._resolve_fame_from_vote_history(
        "target-witness",
        {
            1: {"node-a": True, "node-b": None, "node-c": None},
        },
        threshold=3,
    )

    assert decision["decided"] is False
    assert decision["needs_coin"] is False
    assert decision["decision_kind"] == "pending"
    assert decision["coin_used"] is False
    assert decision["coin_round"] is None
    assert decision["vote_round"] == 1
    assert decision["vote_yes"] == 1
    assert decision["vote_no"] == 0


def test_round_received_skips_round_until_all_fame_decisions_in_that_round_are_resolved():
    engine = ConsensusEngine("node-a")
    membership_ids = ["node-a", "node-b", "node-c", "node-d"]

    target = Event.create(
        cls_name=EventClass.C,
        source="target",
        creator="target",
        ts_local=0.5,
        vclock={},
        parents=[],
        payload={"title": "target"},
    )
    w0a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=1.0,
        vclock={"node-a": 1},
        parents=[target.id],
        payload={"title": "w0a"},
    )
    w0b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=1.1,
        vclock={"node-b": 1},
        parents=[target.id],
        payload={"title": "w0b"},
    )
    w0c = Event.create(
        cls_name=EventClass.A,
        source="node-c",
        creator="node-c",
        ts_local=1.2,
        vclock={"node-c": 1},
        parents=[target.id],
        payload={"title": "w0c"},
    )
    w0d = Event.create(
        cls_name=EventClass.A,
        source="node-d",
        creator="node-d",
        ts_local=1.3,
        vclock={"node-d": 1},
        parents=[target.id],
        payload={"title": "w0d"},
    )
    w1a = Event.create(
        cls_name=EventClass.A,
        source="node-a",
        creator="node-a",
        ts_local=2.0,
        vclock={"node-a": 2},
        parents=[w0a.id, target.id],
        payload={"title": "w1a"},
    )
    w1b = Event.create(
        cls_name=EventClass.A,
        source="node-b",
        creator="node-b",
        ts_local=2.1,
        vclock={"node-b": 2},
        parents=[w0b.id, target.id],
        payload={"title": "w1b"},
    )
    w1c = Event.create(
        cls_name=EventClass.A,
        source="node-c",
        creator="node-c",
        ts_local=2.2,
        vclock={"node-c": 2},
        parents=[w0c.id, target.id],
        payload={"title": "w1c"},
    )
    w1d = Event.create(
        cls_name=EventClass.A,
        source="node-d",
        creator="node-d",
        ts_local=2.3,
        vclock={"node-d": 2},
        parents=[w0d.id, target.id],
        payload={"title": "w1d"},
    )

    by_id = {
        target.id: target,
        w0a.id: w0a,
        w0b.id: w0b,
        w0c.id: w0c,
        w0d.id: w0d,
        w1a.id: w1a,
        w1b.id: w1b,
        w1c.id: w1c,
        w1d.id: w1d,
    }
    ancestor_cache = {}
    witnesses_by_round = {
        0: {"node-a": w0a.id, "node-b": w0b.id, "node-c": w0c.id, "node-d": w0d.id},
        1: {"node-a": w1a.id, "node-b": w1b.id, "node-c": w1c.id, "node-d": w1d.id},
    }
    famous_witnesses_by_round = {
        0: {"node-a": w0a.id, "node-b": w0b.id, "node-c": w0c.id},
    }
    fame_by_round = {
        0: {
            w0a.id: {"famous": True, "decided": True},
            w0b.id: {"famous": True, "decided": True},
            w0c.id: {"famous": True, "decided": True},
            w0d.id: {"famous": False, "decided": False},
        },
        1: {},
    }

    round_received = engine._round_received(
        target,
        witnesses_by_round,
        famous_witnesses_by_round,
        fame_by_round,
        ancestor_cache,
        by_id,
        membership_ids,
    )

    assert round_received == 1
