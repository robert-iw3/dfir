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
from .linkage import (CONFIRMED_RARITY_FLOOR, CONFIRMING_VERDICTS, CONTRADICTION_DISCOUNT,
                      LINK_THRESHOLD, TYPE_WEIGHT, VERDICT_WEIGHT, WINDOW_DAYS,
                      contradiction_for, movement_verdict_weight, rarity,
                      temporal_coherence)


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

    def test_a_contradiction_ranked_below_the_kept_corroboration_is_still_read(self):
        """The concealment's third form, and the one the rarity floor caused.

        A pair carries 19 contributions; the record keeps the top and five more. Discounting
        the movement pushes it down the order, and the confirmed-everywhere rarity floor
        lifted three artifacts above it, so it fell past the sixth and out of the stored
        factors entirely. The host still banded down and the reason it banded down was no
        longer in the record — the discount concealing itself, one level further out than
        before. `build_links` now retains any contradicted contribution regardless of rank.
        """
        link = _Link("JUMP-101", "SRV-FILE-101", 0.5705, ["artifact", "movement"],
                     kind="artifact", subkind="c2_campaign_id", temporal=1.0)
        link.factors["corroboration"] = [
            {"kind": "artifact", "subkind": "c2_sleep", "weight": 0.5705},
            {"kind": "artifact", "subkind": "campaign_id", "weight": 0.5705},
            {"kind": "indicator", "subkind": "ja3", "weight": 0.3691},
            {"kind": "indicator", "subkind": "mutex", "weight": 0.3691},
            {"kind": "indicator", "subkind": "pipe", "weight": 0.3691},
            # Ranked seventh, retained because it is contradicted.
            {"kind": "movement", "weight": 0.35, "contradiction": CONTRADICTION_DISCOUNT,
             "contradiction_basis": "movement at 07:30 precedes JUMP-101's first compromise "
                                    "evidence at 09:55"},
        ]
        band, factors = _band("SRV-FILE-101", link)
        self.assertEqual(band, PROBABLE)
        self.assertEqual(factors["contradiction"], CONTRADICTION_DISCOUNT)
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


# The Linux hunts' own vocabulary, from `playbooks/linux/threat_hunting/adjudicate.py`.
# These are the types a Linux collection actually produces, and the NAME each one carries is
# the tradecraft: an actor who rotates infrastructure between engagements keeps calling their
# unit `sysstat-collector.service`.
LINUX_ARTIFACT_TYPES = {
    "Webshell", "Systemd Persistence", "Systemd Unit", "Cron Persistence", "Cron Entry",
    "Shell Init Backdoor", "Library Preload Hijack", "Suspicious Kernel Module",
    "Hidden Kernel Module", "Memory-Only Executable (memfd)", "Execution From Writable Path",
}

# Corpus L's tradecraft, as the collector records it — full paths, because that is what a
# Linux hunt reports.
LTP_V = "Likely True Positive"
_T0 = datetime(2026, 7, 22, 9, 30, tzinfo=tz.utc)

UNIT_PATH = "/etc/systemd/system/sysstat-collector.service"
FLEET_UNIT_PATH = "/etc/systemd/system/node_exporter.service"
PRELOAD_TARGET = "/etc/ld.so.preload -> /usr/lib/x86_64-linux-gnu/libnss_cache.so.2"
PROFILE_PATH = "/etc/profile.d/00-locale-fix.sh"
PAYLOAD_PATH = "/dev/shm/.systemd-private/kdevtmpfsi"


class LinuxTradecraftReachesTheGraph(SimpleTestCase):
    """Corpus L is a Linux intrusion, and nothing it leaves behind is shaped like Windows.

    Every threshold in the engine was calibrated while a Windows corpus was the only dataset.
    These assert the parts that a second platform makes falsifiable.
    """

    def test_every_linux_artifact_type_contributes_an_artifact_node(self):
        """A finding type absent from EVENT_MAP contributes no artifact, so the name it
        carries never reaches linkage or the fingerprint. A Linux campaign whose persistence
        is invisible has to hold together on movement alone — and the hosts reached without
        a movement record are then unreachable by any path."""
        from .behavior import EVENT_MAP
        missing = sorted(t for t in LINUX_ARTIFACT_TYPES
                         if not (EVENT_MAP.get(t) or (None, None))[1])
        self.assertEqual(missing, [], f"no artifact node for: {missing}")

    def test_a_unit_is_named_by_its_unit_not_its_directory(self):
        """`/etc/systemd/system` is the platform's, not the actor's. Keeping it gives every
        actor on Linux the same leading shape and buries the part they chose."""
        from .behavior import artifact_value
        self.assertEqual(artifact_value("persistence_service", UNIT_PATH),
                         "sysstat-collector.service")
        self.assertEqual(artifact_value("persistence_cron", "/etc/cron.d/certbot-renew-helper"),
                         "certbot-renew-helper")
        self.assertEqual(artifact_value("persistence_shell_init", PROFILE_PATH),
                         "00-locale-fix.sh")
        self.assertEqual(artifact_value("persistence_preload", PRELOAD_TARGET),
                         "libnss_cache.so.2")

    def test_a_payload_keeps_the_directory_it_was_placed_in(self):
        """The opposite case: `/dev/shm/.systemd-private/` IS the choice. Where a payload is
        put is tradecraft in a way a unit's mandatory directory is not."""
        from .behavior import artifact_value
        self.assertEqual(artifact_value("payload_path", PAYLOAD_PATH), PAYLOAD_PATH)
        self.assertTrue(_informative(convention_of(PAYLOAD_PATH)))

    def test_the_separator_is_part_of_the_habit(self):
        """`node_exporter.service` and `sysstat-collector.service` are not the same shape.
        Underscore and hyphen are a choice, kept verbatim, so two units that differ only
        there stay distinguishable without needing any floor at all."""
        self.assertEqual(convention_of("sysstat-collector.service"), "<name>-<name>.service")
        self.assertEqual(convention_of("node_exporter.service"), "<name>_<name>.service")

    def test_a_fleet_unit_sharing_the_habit_is_separated_only_by_rarity(self):
        """`fwupd-refresh.service` ships with the distribution and reduces to the SAME shape
        as the actor's unit. Nothing about the name distinguishes them; the rarity floor is
        the whole of the difference, which is what makes it load-bearing."""
        hosts = [_Host(f"app-node-0{i}") for i in range(4)]
        fleet = _Node("fwupd-refresh.service", "persistence_service", host_count=22)
        actor = _Node("sysstat-collector.service", "persistence_service", host_count=4)
        self.assertEqual(convention_of(fleet.value), convention_of(actor.value))
        fp = build_fingerprint(hosts, [], [fleet, actor],
                               confirmed_nodes={fleet.id, actor.id})
        self.assertEqual(fp["artifact_conventions"],
                         ["persistence_service:<name>-<name>.service"])
        self.assertEqual(
            fp["convention_examples"]["persistence_service:<name>-<name>.service"]["example"],
            "sysstat-collector.service")


class LinuxVerdictCeiling(SimpleTestCase):
    """Linux adjudication never returns True Positive.

    `adjudicate.py` ALWAYS_TP — webshells, preload hijacks, rootkit modules — returns *Likely*
    True Positive, so every Linux link is multiplied by 0.75 where the Windows corpus supplies
    1.00. LINK_THRESHOLD was set against the corpus that reaches 1.00.
    """

    POPULATION = 22

    def _artifact_weight(self, host_count, verdict=LTP_V, population=None):
        return (TYPE_WEIGHT["artifact"]
                * rarity(host_count, population or self.POPULATION)
                * VERDICT_WEIGHT[verdict]
                * temporal_coherence(_T0, _T0))

    def test_a_rare_likely_true_positive_artifact_links(self):
        """Three hosts out of twenty-two: the preload library, and the cron entry."""
        self.assertGreaterEqual(self._artifact_weight(3), LINK_THRESHOLD)

    def test_the_same_artifact_on_more_hosts_stops_linking(self):
        """Four hosts out of twenty-two reaches 0.33 and is declined, while three reaches
        0.38 and is accepted. The campaign's MOST widespread habit is the one that fails, and
        the same evidence at True Positive would clear the bar at either count."""
        four = self._artifact_weight(4)
        self.assertLess(four, LINK_THRESHOLD)
        self.assertGreaterEqual(
            self._artifact_weight(4, verdict="True Positive"), LINK_THRESHOLD)

    def test_whether_it_links_depends_on_the_rest_of_the_deployment(self):
        """Same campaign, same evidence, a larger fleet around it: rarity is measured against
        the deployment, so hosts belonging to unrelated cases decide this one."""
        self.assertLess(self._artifact_weight(4, population=22), LINK_THRESHOLD)
        self.assertGreaterEqual(self._artifact_weight(4, population=47), LINK_THRESHOLD)

    def test_an_indeterminate_artifact_never_links_however_rare(self):
        """A planted authorized_keys entry is filed HUMAN_REVIEW — Indeterminate — so the
        strongest artifact a Linux intrusion leaves cannot carry a link. Asserted at the
        rarest possible count so this reads as a ceiling, not a close call."""
        self.assertLess(self._artifact_weight(2, verdict="Indeterminate"), LINK_THRESHOLD)

    def test_an_account_alone_cannot_link_two_hosts(self):
        """Even a rogue uid=0 account on exactly two hosts, adjudicated at the top of the
        ladder: 0.45 x 0.71 x 1.00. Accounts are corroboration by construction."""
        weight = (TYPE_WEIGHT["account"] * rarity(2, self.POPULATION)
                  * VERDICT_WEIGHT["True Positive"] * temporal_coherence(_T0, _T0))
        self.assertLess(weight, LINK_THRESHOLD)


class MovementCarriesItsVerdict(SimpleTestCase):
    """An SSH session between two hosts is routine on Linux, and a hunt that cannot tell an
    admin hop from an intrusion files it Indeterminate. Scoring every movement record at True
    Positive makes that record fuse whatever it touches."""

    def test_an_adjudicated_movement_record_keeps_its_own_weight(self):
        self.assertEqual(movement_verdict_weight("Likely True Positive"), 0.75)
        self.assertEqual(movement_verdict_weight("True Positive"), 1.0)

    def test_an_indeterminate_hop_cannot_link(self):
        """Corpus L's trap: the bastion is a campaign member and the workstation carries an
        unrelated compromise, joined by one routine admin session."""
        weight = (TYPE_WEIGHT["movement"] * movement_verdict_weight("Indeterminate")
                  * temporal_coherence(_T0, _T0))
        self.assertLess(weight, LINK_THRESHOLD)

    def test_an_unadjudicated_record_is_treated_as_indeterminate(self):
        """Same default as everywhere else on the ladder, rather than the benefit of doubt."""
        self.assertEqual(movement_verdict_weight(""), VERDICT_WEIGHT["Indeterminate"])


class TimelineCheckIsReportedEitherWay(SimpleTestCase):
    """Three outcomes, three records. A blank field meant all of them.

    `contradiction_for` words each case, and the band kept only the contradicted one — so a
    movement checked and found consistent, a movement that could not be checked because its
    source has no standalone confirming evidence, and a link with no movement at all were
    indistinguishable to the reader. On a host whose logs the actor cleared, "could not be
    checked" is the finding, not the absence of one.
    """

    def _factors(self, **top):
        _, factors = _band("SRV-FS-01", _Link(
            "DC-R1", "SRV-FS-01", 0.85, ["movement", "artifact"], kind="movement",
            temporal=1.0, **top))
        return factors

    def test_a_consistent_timeline_says_so(self):
        factors = self._factors(contradiction=1.0,
                                contradiction_basis="consistent — DC-R1 shows compromise from X")
        self.assertIsNone(factors["contradiction"])
        self.assertIn("consistent", factors["contradiction_basis"])

    def test_an_unevaluated_timeline_says_that_instead(self):
        factors = self._factors(
            contradiction=1.0,
            contradiction_basis="not evaluated — no standalone confirming evidence on DC-R1")
        self.assertIsNone(factors["contradiction"])
        self.assertIn("not evaluated", factors["contradiction_basis"])

    def test_a_contradicted_timeline_still_carries_its_multiplier(self):
        factors = self._factors(contradiction=CONTRADICTION_DISCOUNT,
                                contradiction_basis="movement at X precedes DC-R1's first")
        self.assertEqual(factors["contradiction"], CONTRADICTION_DISCOUNT)
        self.assertIn("precedes", factors["contradiction_basis"])

    def test_no_movement_at_all_reports_nothing_rather_than_a_verdict(self):
        """The one case where silence is right: there was no movement to test."""
        _, factors = _band("SRV-FS-01", _Link(
            "DC-R1", "SRV-FS-01", 0.85, ["artifact"], kind="artifact", temporal=1.0))
        self.assertIsNone(factors["contradiction"])
        self.assertIsNone(factors["contradiction_basis"])

    def test_the_basis_is_found_in_corroboration_too(self):
        """Same reason banding reads every contribution: the movement is often not the top."""
        link = _Link("DC-R1", "SRV-FS-01", 0.85, ["artifact", "movement"],
                     kind="artifact", temporal=1.0)
        link.factors["corroboration"] = [
            {"kind": "movement", "contradiction": 1.0,
             "contradiction_basis": "not evaluated — no standalone confirming evidence on DC-R1"}]
        _, factors = _band("SRV-FS-01", link)
        self.assertIn("not evaluated", factors["contradiction_basis"])


class MassImpactRarity(SimpleTestCase):
    """Rarity assumes that something on many hosts is the environment.

    That is a hypothesis about benign presence, and adjudication tests it on every carrier.
    A ransomware event refutes it everywhere at once: the note is on each host BECAUSE each
    host was encrypted, so the larger the event, the less its own signature argued that its
    victims were related. On a 24-host fleet the note on 12 of them scored 0.31 against a
    0.35 threshold, and one event was reported as fourteen unrelated incidents.
    """

    POPULATION = 54

    def _weight(self, kind, host_count, floored, verdict="True Positive"):
        r = rarity(host_count, self.POPULATION)
        if floored:
            r = max(r, CONFIRMED_RARITY_FLOOR)
        return TYPE_WEIGHT[kind] * r * VERDICT_WEIGHT[verdict] * temporal_coherence(_T0, _T0)

    def test_a_mass_impact_artifact_is_declined_on_rarity_alone(self):
        """The defect, stated: True Positive on all twelve carriers and still not a link."""
        self.assertLess(self._weight("artifact", 12, floored=False), LINK_THRESHOLD)

    def test_the_floor_lets_it_link(self):
        self.assertGreaterEqual(self._weight("artifact", 12, floored=True), LINK_THRESHOLD)

    def test_the_deployment_task_on_fifteen_hosts_links_too(self):
        """Scale must not be the thing that breaks it: more victims, same conclusion."""
        self.assertLess(self._weight("artifact", 15, floored=False), LINK_THRESHOLD)
        self.assertGreaterEqual(self._weight("artifact", 15, floored=True), LINK_THRESHOLD)

    def test_a_commodity_binary_still_cannot_merge_two_compromises(self):
        """The floor's residual risk, bounded by the type weight rather than by hope.

        A public file-transfer binary is adjudicated True Positive by both a ransomware
        operator staging exfiltration and an unrelated insider — confirmed on every carrier,
        distinctive of neither. It arrives as a bare INDICATOR, and at 0.55 the floor leaves
        it below the threshold.
        """
        self.assertLess(self._weight("indicator", 5, floored=True), LINK_THRESHOLD)

    def test_an_account_confirmed_everywhere_still_cannot_merge(self):
        """Accounts are corroboration by construction, floor or no floor."""
        self.assertLess(self._weight("account", 16, floored=True), LINK_THRESHOLD)

    def test_the_floor_never_lowers_a_rare_artifact(self):
        """It is a floor, not a replacement — an artifact on three hosts keeps its own value."""
        self.assertEqual(self._weight("artifact", 3, floored=True),
                         self._weight("artifact", 3, floored=False))


class DwellWindow(SimpleTestCase):
    """A targeted intrusion dwells for months, and the window said thirty days.

    Corpus S is one operator returning over eight months, adjacent hosts up to 56 days apart.
    At `WINDOW_DAYS = 30` every pair scored the 0.2 floor and the campaign never formed —
    which then read as no patient zero, no fingerprint and a technique sequence that stopped
    at the first host. The bound is two-sided, so both sides are asserted: wide enough to
    hold one slow campaign together, narrow enough to keep unrelated shadow IT apart.
    """

    POPULATION = 74
    CHAIN_GAP = 56          # widest gap between adjacent Glass Heron hosts
    SHADOW_GAP = 190        # two unsanctioned remote-access installs, different people

    def _artifact(self, host_count, days, verdict="True Positive"):
        return (TYPE_WEIGHT["artifact"]
                * max(rarity(host_count, self.POPULATION), CONFIRMED_RARITY_FLOOR)
                * VERDICT_WEIGHT[verdict]
                * temporal_coherence(_T0, _T0 + timedelta(days=days)))

    def test_a_campaign_hop_weeks_apart_links(self):
        self.assertGreaterEqual(self._artifact(7, self.CHAIN_GAP), LINK_THRESHOLD)

    def test_unrelated_shadow_it_months_apart_still_does_not(self):
        """The other side of the bound. Same tool, two people, half a year between them."""
        self.assertLess(
            self._artifact(2, self.SHADOW_GAP, verdict="Likely True Positive"), LINK_THRESHOLD)

    def test_coherence_still_discriminates_rather_than_saturating(self):
        """A window wide enough to hold a slow campaign must not make everything coherent."""
        near = temporal_coherence(_T0, _T0 + timedelta(days=self.CHAIN_GAP))
        far = temporal_coherence(_T0, _T0 + timedelta(days=self.SHADOW_GAP))
        self.assertGreater(near, far)
        self.assertLess(far, 1.0)

    def test_beyond_the_window_it_reaches_the_floor_and_stops(self):
        self.assertEqual(temporal_coherence(_T0, _T0 + timedelta(days=WINDOW_DAYS)), 0.2)
        self.assertEqual(temporal_coherence(_T0, _T0 + timedelta(days=WINDOW_DAYS * 3)), 0.2)

    def test_unknown_timing_neither_confirms_nor_refutes(self):
        self.assertEqual(temporal_coherence(None, _T0), 0.6)

    def test_the_window_covers_a_dwell_measured_in_months(self):
        """Stated as its own assertion: the constant is a claim about how intrusions behave,
        and shortening it silently is what broke corpus S."""
        self.assertGreaterEqual(WINDOW_DAYS, 254)
        self.assertLessEqual(WINDOW_DAYS, 644)


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
