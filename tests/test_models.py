from mdrj.models import Event, EventClass


def test_event_from_legacy_record_tolerates_null_json_fields():
    event = Event.from_record(
        {
            "id": "legacy-event",
            "cls": "C",
            "source": "legacy-node",
            "creator": None,
            "ts_local": 1.0,
            "vclock": None,
            "parents": None,
            "self_parent_id": None,
            "other_parent_id": None,
            "payload": None,
            "sig": None,
        }
    )

    assert event.id == "legacy-event"
    assert event.cls == EventClass.C
    assert event.vclock == {}
    assert event.parents == []
    assert event.payload == {}
