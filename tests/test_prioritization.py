from mdrj.config import GossipConfig, PrioritizationConfig
from mdrj.models import Envelope, Event, EventClass, NodeProfile
from mdrj.prioritization import Prioritizer
from mdrj.utils import utc_timestamp


def make_event(cls: EventClass, idx: int) -> Envelope:
    event = Event.create(
        cls_name=cls,
        source="node-1",
        ts_local=utc_timestamp(),
        vclock={"node-1": idx},
        parents=[f"p-{idx}", f"q-{idx}"],
        payload={"idx": idx},
    )
    return Envelope(event=event, path_meta=[])


def test_prioritizer_respects_classes():
    profile = NodeProfile(memory_mb=64, bw_kbps=128, cpu_quota=0.5, role="light", threat_level="LOW")
    prioritizer = Prioritizer(profile, GossipConfig(period_sec=1.0, fan_out=2), PrioritizationConfig(level_threshold_B="HIGH", max_batch_bytes=4096))

    env_a = make_event(EventClass.A, 1)
    env_b = make_event(EventClass.B, 2)
    env_c = make_event(EventClass.C, 3)

    plan = prioritizer.plan_batch([env_a, env_b, env_c])
    ids = {env.event.id for env in plan.envelopes}
    assert env_a.event.id in ids
    assert env_b.event.id not in ids
    assert env_c.event.id not in ids

    prioritizer_high = Prioritizer(
        NodeProfile(memory_mb=64, bw_kbps=512, cpu_quota=0.5, role="relay", threat_level="HIGH"),
        GossipConfig(period_sec=1.0, fan_out=2),
        PrioritizationConfig(level_threshold_B="ELEV", max_batch_bytes=4096),
    )
    plan2 = prioritizer_high.plan_batch([env_a, env_b, env_c])
    ids2 = {env.event.id for env in plan2.envelopes}
    assert env_b.event.id in ids2

    plan3 = prioritizer.plan_batch([env_c], required_events={env_c.event.id})
    assert plan3.envelopes
