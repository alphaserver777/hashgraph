from mdrj.vectorclock import VectorClock, VectorRelation, merge_all


def test_vector_clock_increment_and_merge():
    clock = VectorClock()
    clock = clock.increment("node-1")
    assert clock.clock["node-1"] == 1
    other = VectorClock({"node-1": 2, "node-2": 1})
    merged = clock.merge(other.clock)
    assert merged.clock["node-1"] == 2
    assert merged.clock["node-2"] == 1


def test_vector_clock_relations():
    a = VectorClock({"A": 1, "B": 2})
    b = VectorClock({"A": 2, "B": 2})
    assert a.relation(b.clock) == VectorRelation.BEFORE
    assert b.relation(a.clock) == VectorRelation.AFTER
    c = VectorClock({"A": 1, "B": 3})
    assert a.relation(c.clock) == VectorRelation.CONCURRENT
    assert c.relation(a.clock) == VectorRelation.CONCURRENT


def test_merge_all_collects_maximum():
    clocks = [
        {"A": 1, "B": 2},
        {"A": 3, "C": 1},
        {"B": 1, "C": 4},
    ]
    merged = merge_all(clocks)
    assert merged.clock == {"A": 3, "B": 2, "C": 4}
