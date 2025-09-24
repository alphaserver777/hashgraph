from mdrj.consensus import ConsensusEngine
from mdrj.models import Envelope, Event, EventClass


def test_consensus_median_timestamp():
    event = Event.create(
        cls_name=EventClass.A,
        source="node-1",
        ts_local=1.0,
        vclock={"node-1": 1},
        parents=["p1", "p2"],
        payload={},
    )
    envelope = Envelope(event=event, path_meta=[{"node": "node-2", "ts": 3.0}, {"node": "node-3", "ts": 5.0}])
    engine = ConsensusEngine("node-1")
    result = engine.compute_timestamp(envelope, arrival_ts=7.0)
    assert result.consensus_ts == 5.0
    assert result.contributors == 3

