"""Consensus helpers for round-based deterministic ordering."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

from .models import Event
from .utils import median


@dataclass(frozen=True)
class MembershipEntry:
    node_id: str
    address: str
    role: str = "node"
    is_self: bool = False


@dataclass
class ConsensusState:
    event_id: str
    creator: str
    self_parent_id: Optional[str]
    other_parent_id: Optional[str]
    round: int
    round_received: Optional[int]
    is_witness: bool
    is_famous_witness: bool
    fame_decided: bool
    fame_decision_round: Optional[int]
    fame_decision_kind: str
    fame_needs_coin: bool
    fame_coin_used: bool
    fame_coin_round: Optional[int]
    fame_vote_round: Optional[int]
    fame_vote_yes: int
    fame_vote_no: int
    consensus_ts: Optional[float]


class ConsensusEngine:
    def __init__(self, node_id: str):
        self.node_id = node_id

    def recompute(
        self,
        events: Sequence[Event],
        membership: Sequence[MembershipEntry],
        path_meta_by_event: Optional[Mapping[str, Sequence[Mapping[str, object]]]] = None,
    ) -> List[ConsensusState]:
        if not events:
            return []

        membership_ids = self._normalize_membership(membership)
        topo = list(events)
        by_id = {event.id: event for event in topo}
        ancestor_cache: Dict[str, set[str]] = {}
        rounds: Dict[str, int] = {}
        witness_flags: Dict[str, bool] = {}
        witnesses_by_round: Dict[int, Dict[str, str]] = {}

        for event in topo:
            creator = event.creator or event.source
            parent_rounds = [rounds[parent_id] for parent_id in event.parents if parent_id in rounds]
            base_round = max(parent_rounds, default=0)
            witness_ids = tuple(witnesses_by_round.get(base_round, {}).values())
            event_round = base_round
            if witness_ids and self._sees_supermajority(event.id, witness_ids, membership_ids, ancestor_cache, by_id):
                event_round = base_round + 1

            rounds[event.id] = event_round
            creator_witnesses = witnesses_by_round.setdefault(event_round, {})
            is_witness = creator not in creator_witnesses
            if is_witness:
                creator_witnesses[creator] = event.id
            witness_flags[event.id] = is_witness

        _, fame_by_round = self._fame_vote_history_and_decisions(
            witnesses_by_round,
            ancestor_cache,
            by_id,
            membership_ids,
        )
        famous_witnesses_by_round = {
            round_no: {
                creator: witness_id
                for creator, witness_id in witnesses.items()
                if fame_by_round.get(round_no, {}).get(witness_id, {}).get("decided")
                and fame_by_round.get(round_no, {}).get(witness_id, {}).get("famous")
            }
            for round_no, witnesses in witnesses_by_round.items()
        }

        states: List[ConsensusState] = []
        quorum = self._supermajority_threshold(len(membership_ids))
        ordered = self.total_order(
            topo,
            {
                event.id: (
                    self._round_received(
                        event,
                        witnesses_by_round,
                        famous_witnesses_by_round,
                        fame_by_round,
                        ancestor_cache,
                        by_id,
                        membership_ids,
                    ),
                    self._consensus_timestamp(
                        event.id,
                        membership_ids,
                        quorum,
                        path_meta_by_event or {},
                    ),
                )
                for event in topo
            },
        )
        ordering_map = {event.id: index for index, event in enumerate(ordered)}

        for event in sorted(topo, key=lambda item: ordering_map[item.id]):
            round_received = self._round_received(
                event,
                witnesses_by_round,
                famous_witnesses_by_round,
                fame_by_round,
                ancestor_cache,
                by_id,
                membership_ids,
            )
            consensus_ts = self._consensus_timestamp(
                event.id,
                membership_ids,
                quorum,
                path_meta_by_event or {},
            )
            states.append(
                ConsensusState(
                    event_id=event.id,
                    creator=event.creator or event.source,
                    self_parent_id=event.self_parent_id,
                    other_parent_id=event.other_parent_id,
                    round=rounds[event.id],
                    round_received=round_received,
                    is_witness=witness_flags[event.id],
                    is_famous_witness=fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("famous", False),
                    fame_decided=fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("decided", False),
                    fame_decision_round=fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("decision_round"),
                    fame_decision_kind=str(fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("decision_kind", "pending")),
                    fame_needs_coin=bool(fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("needs_coin", False)),
                    fame_coin_used=bool(fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("coin_used", False)),
                    fame_coin_round=fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("coin_round"),
                    fame_vote_round=fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("vote_round"),
                    fame_vote_yes=int(fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("vote_yes", 0) or 0),
                    fame_vote_no=int(fame_by_round.get(rounds[event.id], {}).get(event.id, {}).get("vote_no", 0) or 0),
                    consensus_ts=consensus_ts if round_received is not None else None,
                )
            )
        return states

    def total_order(
        self,
        events: Sequence[Event],
        resolved: Optional[Mapping[str, tuple[Optional[int], Optional[float]]]] = None,
    ) -> List[Event]:
        decorated = []
        for index, event in enumerate(events):
            round_received = event.round_received
            consensus_ts = event.consensus_ts
            if resolved and event.id in resolved:
                round_received, consensus_ts = resolved[event.id]
            rr_key = round_received if round_received is not None else float("inf")
            ts_key = consensus_ts if consensus_ts is not None else float("inf")
            decorated.append((rr_key, ts_key, str(event.id or ""), index, event))
        decorated.sort()
        return [event for _, _, _, _, event in decorated]

    def membership_snapshot(
        self,
        epoch: int,
        members: Sequence[MembershipEntry],
    ) -> Dict[str, object]:
        normalized = [
            {
                "node_id": entry.node_id,
                "address": entry.address,
                "role": entry.role,
                "is_self": bool(entry.is_self),
            }
            for entry in sorted(members, key=lambda item: item.node_id)
        ]
        joined = "::".join(member["node_id"] for member in normalized)
        fingerprint = hashlib.sha256(joined.encode("utf-8")).hexdigest()
        return {
            "epoch": epoch,
            "members": normalized,
            "membership_snapshot_hash": fingerprint,
            "membership_size": len(normalized),
        }

    def _normalize_membership(self, membership: Sequence[MembershipEntry]) -> List[str]:
        seen = set()
        normalized: List[str] = []
        for entry in membership:
            node_id = str(entry.node_id or "").strip()
            if not node_id or node_id in seen:
                continue
            seen.add(node_id)
            normalized.append(node_id)
        if self.node_id not in seen:
            normalized.append(self.node_id)
        return normalized

    def _supermajority_threshold(self, members: int) -> int:
        return max(1, (2 * members) // 3 + 1)

    def _ancestor_ids(
        self,
        event_id: str,
        by_id: Mapping[str, Event],
        cache: Dict[str, set[str]],
    ) -> set[str]:
        if event_id in cache:
            return cache[event_id]
        event = by_id.get(event_id)
        if not event:
            cache[event_id] = set()
            return cache[event_id]
        seen: set[str] = set()
        for parent_id in event.parents:
            seen.add(parent_id)
            seen.update(self._ancestor_ids(parent_id, by_id, cache))
        cache[event_id] = seen
        return seen

    def _can_see(
        self,
        observer_id: str,
        target_id: str,
        ancestor_cache: Dict[str, set[str]],
        by_id: Mapping[str, Event],
    ) -> bool:
        return observer_id == target_id or target_id in self._ancestor_ids(observer_id, by_id, ancestor_cache)

    def _sees_supermajority(
        self,
        event_id: str,
        witness_ids: Sequence[str],
        membership_ids: Sequence[str],
        ancestor_cache: Dict[str, set[str]],
        by_id: Mapping[str, Event],
    ) -> bool:
        seen_creators = {
            by_id[witness_id].creator or by_id[witness_id].source
            for witness_id in witness_ids
            if witness_id in by_id and self._can_see(event_id, witness_id, ancestor_cache, by_id)
        }
        return len(seen_creators.intersection(membership_ids)) >= self._supermajority_threshold(len(membership_ids))

    def _round_received(
        self,
        event: Event,
        witnesses_by_round: Mapping[int, Mapping[str, str]],
        famous_witnesses_by_round: Mapping[int, Mapping[str, str]],
        fame_by_round: Mapping[int, Mapping[str, Mapping[str, object]]],
        ancestor_cache: Dict[str, set[str]],
        by_id: Mapping[str, Event],
        membership_ids: Sequence[str],
    ) -> Optional[int]:
        threshold = self._supermajority_threshold(len(membership_ids))
        for round_no in sorted(witnesses_by_round):
            fame_state = fame_by_round.get(round_no, {})
            if fame_state and all(entry.get("decided") for entry in fame_state.values()):
                witnesses = famous_witnesses_by_round.get(round_no, {})
            elif fame_state and any(entry.get("decided") for entry in fame_state.values()):
                continue
            else:
                witnesses = witnesses_by_round[round_no]
            seeing_creators = {
                creator
                for creator, witness_id in witnesses.items()
                if self._can_see(witness_id, event.id, ancestor_cache, by_id)
            }
            if len(seeing_creators.intersection(membership_ids)) >= threshold:
                return round_no
        return None

    def _fame_vote_history_and_decisions(
        self,
        witnesses_by_round: Mapping[int, Mapping[str, str]],
        ancestor_cache: Dict[str, set[str]],
        by_id: Mapping[str, Event],
        membership_ids: Sequence[str],
    ) -> tuple[
        Dict[int, Dict[str, Dict[int, Dict[str, Optional[bool]]]]],
        Dict[int, Dict[str, Dict[str, object]]],
    ]:
        threshold = self._supermajority_threshold(len(membership_ids))
        vote_history: Dict[int, Dict[str, Dict[int, Dict[str, Optional[bool]]]]] = {}
        fame: Dict[int, Dict[str, Dict[str, object]]] = {}
        ordered_rounds = sorted(witnesses_by_round)
        for round_no in ordered_rounds:
            witnesses = witnesses_by_round[round_no]
            round_history: Dict[str, Dict[int, Dict[str, Optional[bool]]]] = {}
            round_fame: Dict[str, Dict[str, object]] = {}
            next_round = round_no + 1
            next_witnesses = witnesses_by_round.get(next_round, {})
            for creator, witness_id in witnesses.items():
                witness_history: Dict[int, Dict[str, Optional[bool]]] = {}
                previous_votes: Dict[str, Optional[bool]] = {
                    next_creator: self._can_see(next_witness_id, witness_id, ancestor_cache, by_id)
                    for next_creator, next_witness_id in next_witnesses.items()
                    if next_creator in membership_ids
                }
                if previous_votes:
                    witness_history[next_round] = dict(previous_votes)
                for later_round in ordered_rounds:
                    if later_round <= round_no + 1:
                        continue
                    later_witnesses = witnesses_by_round.get(later_round, {})
                    current_votes: Dict[str, Optional[bool]] = {}
                    for later_creator, later_witness_id in later_witnesses.items():
                        if later_creator not in membership_ids:
                            continue
                        visible_votes = [
                            vote
                            for prev_creator, vote in previous_votes.items()
                            if prev_creator in membership_ids
                            and prev_creator in witnesses_by_round.get(later_round - 1, {})
                            and vote is not None
                            and self._can_see(
                                later_witness_id,
                                witnesses_by_round[later_round - 1][prev_creator],
                                ancestor_cache,
                                by_id,
                            )
                        ]
                        yes_votes = sum(1 for vote in visible_votes if vote is True)
                        no_votes = sum(1 for vote in visible_votes if vote is False)
                        if yes_votes >= threshold:
                            current_votes[later_creator] = True
                        elif no_votes >= threshold:
                            current_votes[later_creator] = False
                        else:
                            current_votes[later_creator] = None
                    if current_votes:
                        witness_history[later_round] = dict(current_votes)
                    previous_votes = current_votes
                round_history[witness_id] = witness_history
                round_fame[witness_id] = self._resolve_fame_from_vote_history(witness_id, witness_history, threshold)
            vote_history[round_no] = round_history
            fame[round_no] = round_fame
        return vote_history, fame

    def _resolve_fame_from_vote_history(
        self,
        witness_id: str,
        witness_history: Mapping[int, Mapping[str, Optional[bool]]],
        threshold: int,
    ) -> Dict[str, object]:
        decision: Dict[str, object] = {
            "famous": False,
            "decided": False,
            "decision_round": None,
            "decision_kind": "pending",
            "needs_coin": False,
            "coin_used": False,
            "coin_round": None,
            "vote_round": None,
            "vote_yes": 0,
            "vote_no": 0,
        }
        for vote_round in sorted(witness_history):
            votes = witness_history[vote_round]
            yes_total = sum(1 for vote in votes.values() if vote is True)
            no_total = sum(1 for vote in votes.values() if vote is False)
            decision["vote_round"] = vote_round
            decision["vote_yes"] = yes_total
            decision["vote_no"] = no_total
            if yes_total >= threshold:
                decision["famous"] = True
                decision["decided"] = True
                decision["decision_round"] = vote_round
                decision["decision_kind"] = "vote"
                decision["needs_coin"] = False
                decision["coin_used"] = False
                decision["coin_round"] = None
                return decision
            if no_total >= threshold:
                decision["famous"] = False
                decision["decided"] = True
                decision["decision_round"] = vote_round
                decision["decision_kind"] = "vote"
                decision["needs_coin"] = False
                decision["coin_used"] = False
                decision["coin_round"] = None
                return decision
        if len(witness_history) >= 2:
            coin_round = max(witness_history)
            decision["famous"] = self._deterministic_coin_choice(witness_id, coin_round)
            decision["decided"] = True
            decision["decision_round"] = coin_round
            decision["decision_kind"] = "coin_surrogate"
            decision["needs_coin"] = False
            decision["coin_used"] = True
            decision["coin_round"] = coin_round
        return decision

    def _deterministic_coin_choice(self, witness_id: str, vote_round: int) -> bool:
        digest = hashlib.sha256(f"{witness_id}:{vote_round}".encode("utf-8")).digest()
        return bool(digest[0] & 1)

    def _fame_decisions_by_round(
        self,
        witnesses_by_round: Mapping[int, Mapping[str, str]],
        ancestor_cache: Dict[str, set[str]],
        by_id: Mapping[str, Event],
        membership_ids: Sequence[str],
    ) -> Dict[int, Dict[str, Dict[str, object]]]:
        _, fame = self._fame_vote_history_and_decisions(
            witnesses_by_round,
            ancestor_cache,
            by_id,
            membership_ids,
        )
        return fame

    def _consensus_timestamp(
        self,
        event_id: str,
        membership_ids: Sequence[str],
        quorum: int,
        path_meta_by_event: Mapping[str, Sequence[Mapping[str, object]]],
    ) -> Optional[float]:
        observations: Dict[str, float] = {}
        for hop in path_meta_by_event.get(event_id, []) or []:
            node_id = str(hop.get("node") or "").strip()
            ts = hop.get("ts")
            if node_id not in membership_ids or ts is None:
                continue
            if node_id not in observations or float(ts) < observations[node_id]:
                observations[node_id] = float(ts)
        if len(observations) < quorum:
            return None
        return float(median(observations.values()))
