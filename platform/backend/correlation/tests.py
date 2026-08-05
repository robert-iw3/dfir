"""Correlation logic that can be decided without a database.

`band_for()` reads links and returns a judgment. That is pure logic over the record the
linkage pass already wrote, so it is provable here rather than only against a deployed stack —
and the truth table is worth stating explicitly, because every band is a sentence that will
appear in a report.

The banding truth table alone is not enough. It feeds links that ALREADY carry a
contradiction factor, so it proves what banding does with the finding and says nothing about
whether the finding is ever made. The two halves are tested separately —
`sets_compromise_baseline` decides what may set the baseline, `contradiction_for` compares
against it — because a discount that is correct and unreachable reads exactly like a clean
timeline.

Every case is a `SimpleTestCase` and touches no database. Run them through unittest, not
`manage.py test`: the Django runner creates a test database for every configured connection
before it looks at what the tests need, and the app role is not a Postgres superuser.

    python3 -m unittest correlation.tests -v      # inside the backend container

`uat_corpus.sh` runs this before its corpus assertions, so a branch that is wrong here is
reported as itself rather than inferred from the shape of a campaign.
"""
from datetime import datetime, timedelta, timezone as tz

from django.test import SimpleTestCase

from .confidence import CONFIRMED, INDETERMINATE, POSSIBLE, PROBABLE, band_for
from .engine import sets_compromise_baseline
from .fingerprint import _informative, build_fingerprint, convention_of
from .linkage import CONFIRMING_VERDICTS, CONTRADICTION_DISCOUNT, contradiction_for


class _Link:
    """A HostLink as `band_for` reads it."""

    def __init__(self, a, b, weight, kinds, linked=True, **top):
        self.host_a, self.host_b, self.weight, self.linked = a, b, weight, linked
        self.factors = {"top": top, "evidence_kinds": list(kinds)}


def _band(host, *links):
    return band_for(host, {(l.host_a, l.host_b): l for l in links})


class BandingTruthTable(SimpleTestCase):
    def test_strong_link_with_corroboration_is_confirmed(self):
        band, factors = _band("WS-007", _Link(
            "DC-01", "WS-007", 0.95, ["movement", "artifact"],
            kind="movement", temporal=0.9))
        self.assertEqual(band, CONFIRMED)
        self.assertEqual(factors["best_link"]["with"], "DC-01")
        self.assertEqual(factors["corroboration"], 2)

    def test_strong_link_alone_is_only_probable(self):
        """One strong link is one piece of evidence, however heavy it scores."""
        band, _ = _band("WS-007", _Link(
            "DC-01", "WS-007", 0.95, ["movement"], kind="movement", temporal=0.9))
        self.assertEqual(band, PROBABLE)

    def test_corroborated_weak_links_reach_probable(self):
        band, _ = _band("WS-007", _Link(
            "DC-01", "WS-007", 0.40, ["artifact", "account"],
            kind="artifact", temporal=0.9))
        self.assertEqual(band, PROBABLE)

    def test_one_weak_link_is_possible(self):
        band, factors = _band("WS-007", _Link(
            "DC-01", "WS-007", 0.36, ["account"], kind="account", temporal=0.9))
        self.assertEqual(band, POSSIBLE)
        self.assertIn("threshold", factors["why"])

    def test_a_timeline_that_argues_against_the_link_holds_it_back(self):
        """Two hosts whose first activity sits far apart are carried by the indicator alone."""
        band, factors = _band("WS-007", _Link(
            "DC-01", "WS-007", 0.95, ["movement", "artifact"],
            kind="movement", temporal=0.1))
        self.assertEqual(band, PROBABLE)
        self.assertIn("far apart", factors["why"])

    def test_repeated_evidence_of_one_kind_is_not_corroboration(self):
        """Forty sightings of one shared account are one kind of evidence, repeated."""
        links = [_Link("H%d" % i, "WS-007", 0.95, ["account"], kind="account", temporal=0.9)
                 for i in range(40)]
        band, factors = _band("WS-007", *links)
        self.assertEqual(factors["corroboration"], 1)
        self.assertEqual(band, PROBABLE)

    def test_contradiction_holds_the_band_below_confirmed(self):
        """Movement recorded before its source shows compromise cannot settle membership.

        Held one band down rather than dropped to the floor: corroboration is why the host
        is not merely `possible`, and the contradiction is why it is not settled.
        """
        band, factors = _band("SRV-FILE-101", _Link(
            "JUMP-101", "SRV-FILE-101", 0.90, ["movement", "artifact"],
            kind="movement", temporal=0.95, contradiction=0.35))
        self.assertEqual(band, PROBABLE)
        self.assertIn("contradict", factors["why"].lower())
        self.assertEqual(factors["contradiction"], 0.35)

    def test_contradiction_with_nothing_else_behind_it_is_possible(self):
        band, _ = _band("SRV-01", _Link(
            "JUMP-01", "SRV-01", 0.40, ["movement"],
            kind="movement", temporal=0.9, contradiction=0.35))
        self.assertEqual(band, POSSIBLE)

    def test_a_contradiction_on_a_weaker_link_is_not_hidden_by_the_strongest(self):
        """The defect this replaced: reading only the top link buried the contradiction.

        A host tied in by a clean artifact at 1.00 AND by a movement whose sequence cannot be
        right was banding `confirmed`, because the artifact outranked the discounted movement
        and the check never looked past it.
        """
        clean = _Link("DC-101", "SRV-FILE-101", 1.00, ["artifact"],
                      kind="artifact", temporal=0.9)
        bad = _Link("JUMP-101", "SRV-FILE-101", 0.35, ["movement"],
                    kind="movement", temporal=0.9, contradiction=0.35)
        band, factors = _band("SRV-FILE-101", clean, bad)
        self.assertEqual(band, PROBABLE)
        self.assertEqual(factors["contradiction"], 0.35)
        self.assertIn("JUMP-101", factors["why"])

    def test_a_contradiction_demoted_into_corroboration_is_still_read(self):
        """What the corpus caught: the discount hides the contradiction inside its own link.

        One PAIR carries both a movement and a shared artifact. Discounting the movement to
        0.35 drops it below the artifact at 0.47, so the artifact becomes the link's `top` and
        the contradicted contribution sorts into `corroboration`. The link then presents as an
        ordinary artifact link, and the host bands lower for a reason nobody stated —
        `probable` because evidence went missing, not because the timeline is contradicted.
        """
        link = _Link("JUMP-101", "SRV-FILE-101", 0.4663, ["artifact", "movement"],
                     kind="artifact", temporal=0.9)
        link.factors["corroboration"] = [
            {"kind": "movement", "contradiction": 0.35, "temporal": 0.9,
             "contradiction_basis": "movement at 07:30 precedes JUMP-101's first compromise "
                                    "evidence at 09:55"},
        ]
        band, factors = _band("SRV-FILE-101", link)
        self.assertEqual(band, PROBABLE)
        self.assertEqual(factors["contradiction"], 0.35)
        self.assertIn("contradict", factors["why"].lower())
        self.assertIn("07:30", factors["contradiction_basis"])

    def test_a_link_with_no_corroboration_key_is_not_a_crash(self):
        """Historical rows predate `corroboration`; correlation supersedes, never migrates."""
        link = _Link("DC-101", "WS-007", 0.95, ["movement"], kind="movement", temporal=0.9)
        link.factors.pop("corroboration", None)
        band, factors = _band("WS-007", link)
        self.assertEqual(band, PROBABLE)
        self.assertIsNone(factors["contradiction"])


class AbsenceOfEvidence(SimpleTestCase):
    """The band for "not measured" must not be the band for "measured and weak"."""

    def test_a_host_with_no_links_is_indeterminate(self):
        band, factors = _band("LONE-01")
        self.assertEqual(band, INDETERMINATE)
        self.assertIsNone(factors["best_link"])
        self.assertIn("none of that kind", factors["why"])

    def test_declined_links_do_not_count_as_measurement(self):
        """A pair the engine refused to merge is not membership evidence for either host."""
        band, _ = _band("LONE-01", _Link(
            "A", "LONE-01", 0.20, ["account"], linked=False, kind="account", temporal=0.9))
        self.assertEqual(band, INDETERMINATE)


class FactorsAreComplete(SimpleTestCase):
    """A label nobody can take apart is not evidence — the API contract for the band."""

    NAMED = {"band", "best_link", "evidence_kinds", "corroboration", "temporal",
             "contradiction", "why"}

    def test_every_outcome_names_the_same_factors(self):
        cases = [
            _band("WS-007", _Link("DC-01", "WS-007", 0.95, ["movement", "artifact"],
                                  kind="movement", temporal=0.9)),
            _band("WS-007", _Link("DC-01", "WS-007", 0.36, ["account"],
                                  kind="account", temporal=0.9)),
            _band("SRV-01", _Link("JUMP-01", "SRV-01", 0.90, ["movement"],
                                  kind="movement", temporal=0.9, contradiction=0.35)),
            _band("LONE-01"),
        ]
        for band, factors in cases:
            self.assertLessEqual(self.NAMED, set(factors), f"{band} is missing factors")
            self.assertEqual(factors["band"], band)
            self.assertTrue(factors["why"], f"{band} carries no stated reason")


DAY = datetime(2026, 7, 20, tzinfo=tz.utc)


def _t(hours, minutes=0, days=0):
    return DAY + timedelta(days=days, hours=hours, minutes=minutes)


class CompromiseBaseline(SimpleTestCase):
    """What may establish when a host first showed compromise."""

    def test_a_confirming_finding_sets_the_baseline(self):
        self.assertTrue(sets_compromise_baseline("C2 Beacon", "True Positive"))
        self.assertTrue(sets_compromise_baseline("Implant Dropped", "Likely True Positive"))

    def test_a_movement_record_cannot_set_it(self):
        """It is recorded on the source, so it would set the baseline it is compared to."""
        self.assertFalse(sets_compromise_baseline("Lateral Movement", "True Positive"))

    def test_ordinary_fleet_life_cannot_set_it(self):
        """The defect this rule exists for: benign noise sits on every host at every hour.

        An inventory scan at 01:00 and an agent install at 03:05 are on all 25 corpus
        endpoints. Counted as compromise evidence they date every host to the small hours,
        and no movement can precede them — which silently disarms the contradiction check
        for the whole fleet rather than failing anywhere visible.
        """
        for benign in ("Authentication", "Installed Agent", "Package Manager Transaction",
                       "Scheduled Task", "Autorun Entry", "Remote Execution"):
            self.assertFalse(sets_compromise_baseline(benign, "Indeterminate"), benign)

    def test_an_unadjudicated_finding_cannot_set_it(self):
        self.assertFalse(sets_compromise_baseline("C2 Beacon", ""))

    def test_confirming_verdicts_track_the_weight_ladder(self):
        """One vocabulary: confirming means ranked above Indeterminate, not a second list."""
        self.assertEqual(CONFIRMING_VERDICTS,
                         frozenset({"True Positive", "Likely True Positive"}))


class ContradictionDetection(SimpleTestCase):
    """Whether the discount is ever REACHED — the half a banding test cannot see."""

    def test_movement_before_the_source_shows_compromise_is_discounted(self):
        factor, basis = contradiction_for("JUMP-101", _t(7, 30), _t(9, 55))
        self.assertEqual(factor, CONTRADICTION_DISCOUNT)
        self.assertIn("precedes", basis)

    def test_movement_after_it_is_not(self):
        factor, basis = contradiction_for("WS-101", _t(9, 40), _t(9, 5))
        self.assertEqual(factor, 1.0)
        self.assertIn("consistent", basis)

    def test_a_missing_baseline_is_reported_as_unevaluated(self):
        """Cannot-verify is its own answer. Silence here would read as a clean timeline."""
        factor, basis = contradiction_for("SRV-01", _t(9, 40), None)
        self.assertEqual(factor, 1.0)
        self.assertIn("not evaluated", basis)

    def test_a_movement_with_no_timestamp_is_reported_as_unevaluated(self):
        factor, basis = contradiction_for("SRV-01", None, _t(9, 40))
        self.assertEqual(factor, 1.0)
        self.assertIn("not evaluated", basis)

    def test_the_basis_names_both_instants(self):
        """An analyst must be able to check the arithmetic without rerunning correlation."""
        _, basis = contradiction_for("JUMP-101", _t(7, 30, days=1), _t(9, 55, days=1))
        self.assertIn(_t(7, 30, days=1).isoformat(), basis)
        self.assertIn(_t(9, 55, days=1).isoformat(), basis)

    def test_the_corpus_contradiction_edge_is_detected_end_to_end(self):
        """The exact case the corpus plants, decided by the two rules together.

        JUMP-101 carries benign noise from 01:00 on day 0, a movement to SRV-FILE-101 at
        07:30 on day 1, and its first C2 beacon at 09:55 on day 1. Only the beacon may set
        the baseline, and against it the movement is out of sequence.
        """
        findings = [
            ("Authentication", "Indeterminate", _t(1, 12)),
            ("Installed Agent", "Indeterminate", _t(3, 5)),
            ("Lateral Movement", "True Positive", _t(7, 30, days=1)),
            ("C2 Beacon", "True Positive", _t(9, 55, days=1)),
            ("Scheduled Task Persistence", "True Positive", _t(10, 5, days=1)),
        ]
        baseline = min((at for kind, verdict, at in findings
                        if sets_compromise_baseline(kind, verdict)), default=None)
        self.assertEqual(baseline, _t(9, 55, days=1))
        factor, _ = contradiction_for("JUMP-101", _t(7, 30, days=1), baseline)
        self.assertEqual(factor, CONTRADICTION_DISCOUNT)

    def test_a_clean_chain_is_not_discounted_end_to_end(self):
        """The other half: WS-101 is phished at 09:05 and moves onward at 09:40."""
        findings = [
            ("Authentication", "Indeterminate", _t(1, 3)),
            ("Phishing Attachment", "True Positive", _t(9, 5, days=1)),
            ("Lateral Movement", "True Positive", _t(9, 40, days=1)),
        ]
        baseline = min((at for kind, verdict, at in findings
                        if sets_compromise_baseline(kind, verdict)), default=None)
        factor, _ = contradiction_for("WS-101", _t(9, 40, days=1), baseline)
        self.assertEqual(factor, 1.0)


class NameConventions(SimpleTestCase):
    """`convention_of` decides what tradecraft is legible, so its blind spots are platforms."""

    def test_systemd_unit_types_survive(self):
        """A length threshold kept `.timer` and abstracted `.service` — the most common
        Linux persistence artifact there is, dropped from every fingerprint."""
        for unit in ("syslog-collector.service", "nginx-worker.timer",
                     "dbus-proxy.socket", "cache-warm.target"):
            shape = convention_of(unit)
            self.assertTrue(shape.endswith(unit.rsplit(".", 1)[1]), shape)
            self.assertTrue(_informative(shape), f"{unit} -> {shape}")

    def test_archive_extensions_are_not_read_as_digits(self):
        self.assertEqual(convention_of("_archive.7z"), "_<name>.7z")

    def test_versioned_shared_objects_survive(self):
        self.assertTrue(convention_of("libnss_cache.so.2").endswith(".so.2"))

    def test_literal_text_still_carries_a_shape(self):
        self.assertEqual(convention_of("EF-2026-Q3"), "EF-<number>-Q<number>")
        self.assertTrue(_informative("EF-<number>-Q<number>"))

    def test_a_layout_of_three_segments_and_two_separators_is_a_habit(self):
        self.assertTrue(_informative("/<name>/<name>/.<name>/<name>_<name>"))

    def test_a_plain_path_of_generic_words_is_not(self):
        """One separator repeated is the platform's layout, not an operator's choice."""
        self.assertFalse(_informative("/<name>/<name>/<name>/<name>"))
        self.assertFalse(_informative("\\<name>\\<name>\\<name>"))

    def test_a_run_of_words_with_no_separator_is_not(self):
        self.assertFalse(_informative("<name><name><name>"))


class _Node:
    _next = [1]

    def __init__(self, value, subkind, host_count, kind="artifact"):
        self.id = _Node._next[0]; _Node._next[0] += 1
        self.value, self.subkind, self.host_count, self.kind = value, subkind, host_count, kind


class _Host:
    def __init__(self, hostname, techniques=(), first_activity=None):
        self.hostname, self.techniques, self.first_activity = (
            hostname, list(techniques), first_activity)


class FingerprintFloors(SimpleTestCase):
    """What may enter a fingerprint. Everything here is tradecraft an actor is said to carry."""

    HOSTS = [_Host(f"SRV-{i}", ["T1071.001", "T1053.005", "T1003.001"]) for i in range(4)]

    def _fp(self, nodes, confirmed=None):
        ids = {n.id for n in nodes} if confirmed is None else confirmed
        return build_fingerprint(self.HOSTS, [], nodes, confirmed_nodes=ids)

    def test_a_fleet_wide_artifact_is_not_tradecraft(self):
        """The defect: `OneDriveSetup.exe` sits on all 20 corpus endpoints, clean included,
        and was the TOP naming convention on both campaigns — and shared evidence between
        them. An artifact on more hosts than the campaign has is the environment."""
        fleet = _Node("OneDriveSetup.exe", "persistence_autorun", host_count=20)
        actor = _Node("EF-2026-Q3", "c2_campaign_id", host_count=4)
        fp = self._fp([fleet, actor])
        self.assertEqual(fp["artifact_conventions"], ["c2_campaign_id:EF-<number>-Q<number>"])

    def test_an_unadjudicated_artifact_is_not_tradecraft(self):
        """Linkage refuses to link on Indeterminate alone; a fingerprint that accepts it
        contradicts its own case's linkage decisions."""
        seen = _Node("svc_helper.exe", "persistence_service", host_count=2)
        fp = build_fingerprint(self.HOSTS, [], [seen], confirmed_nodes=set())
        self.assertEqual(fp["artifact_conventions"], [])

    def test_one_habit_recorded_twice_is_listed_once(self):
        """`campaign_id` from the hunt and `c2_campaign_id` from config extraction are one
        habit. Listing both pads the panel and double-counts it in the overlap score."""
        a = _Node("EF-2026-Q3", "campaign_id", host_count=4)
        b = _Node("EF-2026-Q3", "c2_campaign_id", host_count=4)
        fp = self._fp([a, b])
        self.assertEqual(len(fp["artifact_conventions"]), 1)

    def test_a_campaign_with_only_fleet_artifacts_reads_as_thin(self):
        """It must not read as an actor with little tradecraft — L5 declines below this.

        Three common techniques and no habit is not a fingerprint. T1071, T1053 and T1003
        are in nearly every intrusion, and they were clearing the gate on their own.
        """
        fp = self._fp([_Node("OneDriveSetup.exe", "persistence_autorun", host_count=20)])
        self.assertEqual(fp["artifact_conventions"], [])
        self.assertFalse(fp["basis"]["sufficient"])

    def test_a_rich_technique_profile_is_enough_without_any_habit(self):
        """An actor who names nothing distinctively is still comparable on how they work."""
        hosts = [_Host("SRV-0", ["T1566.001", "T1204.002", "T1071.001",
                                 "T1053.005", "T1003.001", "T1041"])]
        fp = build_fingerprint(hosts, [], [], confirmed_nodes=set())
        self.assertEqual(fp["artifact_conventions"], [])
        self.assertTrue(fp["basis"]["sufficient"])

    def test_every_convention_carries_the_value_it_came_from(self):
        fp = self._fp([_Node("EF-2026-Q3", "c2_campaign_id", host_count=4)])
        ex = fp["convention_examples"]["c2_campaign_id:EF-<number>-Q<number>"]
        self.assertEqual(ex["example"], "EF-2026-Q3")
        self.assertEqual(ex["hosts"], 4)


class BandVocabulary(SimpleTestCase):
    def test_bands_match_the_model_choices(self):
        """The engine cannot produce a band the column will not store."""
        from .models import CampaignHost
        declared = {value for value, _ in CampaignHost.BANDS}
        self.assertEqual(declared, {CONFIRMED, PROBABLE, POSSIBLE, INDETERMINATE})

    def test_indeterminate_matches_the_verdict_ladder(self):
        """Shared vocabulary with adjudication, so one scale does not contradict the other."""
        self.assertEqual(INDETERMINATE, "indeterminate")
        self.assertEqual(CONFIRMED, "confirmed")
