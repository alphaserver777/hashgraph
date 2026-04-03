from mdrj.event_catalog import EVENT_CATALOG, event_class_for
from mdrj.models import EventClass
from mdrj.simulation import DEMO_SCENARIOS, SCENARIOS


def test_event_catalog_classes_are_centralized():
    assert event_class_for("virus") == EventClass.A
    assert event_class_for("admin_login") == EventClass.B
    assert event_class_for("admin_ssh_login_success") == EventClass.A
    assert event_class_for("heartbeat") == EventClass.C


def test_simulation_scenarios_follow_event_catalog():
    assert set(SCENARIOS) == set(DEMO_SCENARIOS)
    for key in DEMO_SCENARIOS:
        entry = EVENT_CATALOG[key]
        assert SCENARIOS[key]["class"] == entry["class"]
        assert SCENARIOS[key]["payload"] == entry["payload"]
