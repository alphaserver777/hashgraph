from mdrj.consensus import ConsensusEngine
from mdrj.models import Event, EventClass


def test_total_order_uses_stable_index_tiebreaker_for_duplicate_empty_ids():
    first = Event(
        id="",
        cls=EventClass.C,
        source="legacy",
        creator="legacy",
        ts_local=0.0,
        vclock={},
        parents=[],
        self_parent_id=None,
        other_parent_id=None,
        payload={},
    )
    second = Event(
        id="",
        cls=EventClass.C,
        source="legacy",
        creator="legacy",
        ts_local=0.0,
        vclock={},
        parents=[],
        self_parent_id=None,
        other_parent_id=None,
        payload={},
    )

    assert ConsensusEngine("node").total_order([first, second]) == [first, second]
