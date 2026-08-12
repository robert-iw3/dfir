"""
ATT&CK tactics, in kill-chain order, and the techniques that belong to each.

The kill chain is a PROGRESSION: what an intrusion did first, next, and last. Ranking
techniques by how often they fired answers a different and much smaller question, and it
hides the one that matters — which stages carry NO evidence. A gap between Initial Access
and Lateral Movement is a finding about the investigation, not blank space.

The mapping is deliberately by BASE technique (the part before any sub-technique suffix):
sub-techniques inherit their parent's tactics, and carrying the full matrix here would be a
second copy of ATT&CK to keep current. A technique nobody mapped lands in `unmapped`, which
is a stage the UI renders like any other rather than dropping.

Techniques serving several tactics are listed under each — ATT&CK models it that way, and
collapsing them to one would silently under-report a stage.
"""

# Enterprise tactics in kill-chain order. Reconnaissance and Resource Development are
# omitted: they describe what happened before the estate was touched, so an endpoint
# collection cannot evidence them and an empty lane would read as a gap in the evidence
# rather than as a question this platform never asks.
TACTIC_ORDER = [
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

TECHNIQUE_TACTICS = {
    "T1566": ["initial-access"], "T1190": ["initial-access"],
    "T1133": ["initial-access", "persistence"], "T1200": ["initial-access"],
    "T1078": ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
    "T1091": ["initial-access", "lateral-movement"], "T1195": ["initial-access"],
    "T1189": ["initial-access"], "T1199": ["initial-access"],

    "T1059": ["execution"], "T1204": ["execution"], "T1106": ["execution"],
    "T1129": ["execution"], "T1203": ["execution"], "T1569": ["execution"],
    "T1047": ["execution"], "T1072": ["execution", "lateral-movement"],
    "T1053": ["execution", "persistence", "privilege-escalation"],

    "T1136": ["persistence"], "T1098": ["persistence"], "T1197": ["persistence", "defense-evasion"],
    "T1547": ["persistence", "privilege-escalation"], "T1037": ["persistence", "privilege-escalation"],
    "T1543": ["persistence", "privilege-escalation"], "T1546": ["persistence", "privilege-escalation"],
    "T1505": ["persistence"], "T1205": ["persistence", "defense-evasion", "command-and-control"],
    "T1176": ["persistence"], "T1554": ["persistence"], "T1137": ["persistence"],

    "T1548": ["privilege-escalation", "defense-evasion"], "T1134": ["privilege-escalation", "defense-evasion"],
    "T1068": ["privilege-escalation"], "T1055": ["privilege-escalation", "defense-evasion"],
    "T1484": ["privilege-escalation", "defense-evasion"],

    "T1140": ["defense-evasion"], "T1562": ["defense-evasion"], "T1070": ["defense-evasion"],
    "T1036": ["defense-evasion"], "T1112": ["defense-evasion"], "T1027": ["defense-evasion"],
    "T1218": ["defense-evasion"], "T1553": ["defense-evasion"], "T1497": ["defense-evasion", "discovery"],
    "T1564": ["defense-evasion"], "T1620": ["defense-evasion"], "T1211": ["defense-evasion"],

    "T1003": ["credential-access"], "T1110": ["credential-access"], "T1555": ["credential-access"],
    "T1056": ["credential-access", "collection"], "T1558": ["credential-access"],
    "T1552": ["credential-access"], "T1557": ["credential-access", "collection"],
    "T1212": ["credential-access"], "T1187": ["credential-access"],

    "T1087": ["discovery"], "T1010": ["discovery"], "T1217": ["discovery"], "T1580": ["discovery"],
    "T1482": ["discovery"], "T1083": ["discovery"], "T1046": ["discovery"], "T1135": ["discovery"],
    "T1040": ["discovery", "credential-access"], "T1201": ["discovery"], "T1120": ["discovery"],
    "T1057": ["discovery"], "T1012": ["discovery"], "T1018": ["discovery"], "T1518": ["discovery"],
    "T1082": ["discovery"], "T1614": ["discovery"], "T1016": ["discovery"], "T1049": ["discovery"],
    "T1033": ["discovery"], "T1007": ["discovery"], "T1124": ["discovery"],

    "T1210": ["lateral-movement"], "T1534": ["lateral-movement"], "T1570": ["lateral-movement"],
    "T1021": ["lateral-movement"], "T1080": ["lateral-movement"], "T1550": ["lateral-movement", "defense-evasion"],

    "T1560": ["collection"], "T1123": ["collection"], "T1119": ["collection"],
    "T1005": ["collection"], "T1039": ["collection"], "T1025": ["collection"],
    "T1074": ["collection"], "T1114": ["collection"], "T1113": ["collection"],
    "T1125": ["collection"], "T1213": ["collection"], "T1530": ["collection"],

    "T1071": ["command-and-control"], "T1092": ["command-and-control"], "T1132": ["command-and-control"],
    "T1001": ["command-and-control"], "T1568": ["command-and-control"], "T1573": ["command-and-control"],
    "T1008": ["command-and-control"], "T1105": ["command-and-control"], "T1104": ["command-and-control"],
    "T1095": ["command-and-control"], "T1571": ["command-and-control"], "T1572": ["command-and-control"],
    "T1090": ["command-and-control"], "T1219": ["command-and-control"], "T1102": ["command-and-control"],

    "T1020": ["exfiltration"], "T1030": ["exfiltration"], "T1048": ["exfiltration"],
    "T1041": ["exfiltration"], "T1011": ["exfiltration"], "T1052": ["exfiltration"],
    "T1567": ["exfiltration"], "T1029": ["exfiltration"], "T1537": ["exfiltration"],

    "T1485": ["impact"], "T1486": ["impact"], "T1565": ["impact"], "T1491": ["impact"],
    "T1561": ["impact"], "T1499": ["impact"], "T1495": ["impact"], "T1490": ["impact"],
    "T1498": ["impact"], "T1496": ["impact"], "T1489": ["impact"], "T1529": ["impact"],
    "T1531": ["impact"],
}

TACTIC_NAMES = dict(TACTIC_ORDER)


def base_technique(technique):
    """`T1021.002` -> `T1021`. Sub-techniques inherit their parent's tactics."""
    return str(technique or "").strip().split(".")[0].upper()


def tactics_for(technique):
    """Every tactic a technique serves; `["unmapped"]` when the mapping does not know it."""
    return TECHNIQUE_TACTICS.get(base_technique(technique)) or ["unmapped"]
