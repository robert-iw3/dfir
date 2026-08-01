"""
Named repairs an admin can ask for from the UI, and what each one means.

THE WEB TIER NEVER RUNS THESE. It records a request; the agent on the enclave host
(`troubleshooting/remediation-agent.sh`) polls, matches the ACTION NAME against its own
allow-list, and runs its own command. No command string, argument or path crosses the
boundary — a forged row can only name one of a fixed set of repairs.

This catalogue exists so the UI can describe the choices. It is NOT what gets executed: the
agent holds that, and the two are kept deliberately separate so that compromising the web tier
cannot change what runs.

Every action here comes from a failure this deployment actually hit and diagnosed. That is the
bar for adding one — a repair nobody has needed is a privileged command nobody has reviewed.
"""
from __future__ import annotations

# `disruptive` drives the UI's confirmation, and is honest about blast radius rather than
# reassuring: restarting the database proxy WILL sever an analysis part-way through.
CATALOG = {
    "mesh-reattach": {
        "title": "Re-attach orphaned mesh sidecars",
        "summary": "Recreate any Connect proxy that is no longer in its service's network "
                   "namespace, and re-register the mesh.",
        "when": "A service reports its database or object store unreachable while both are "
                "healthy. A recreated service leaves its proxy in a dead namespace, where it "
                "keeps running and serves nothing.",
        "disruptive": False,
    },
    "vault-unseal": {
        "title": "Unseal Vault",
        "summary": "Unseal the secrets store using the deployment's unseal key.",
        "when": "Vault restarted. It comes back sealed by design, and every credential the "
                "application tier needs is unavailable until it is unsealed.",
        "disruptive": False,
    },
    "rotate-app-credentials": {
        "title": "Rotate application database credentials",
        "summary": "Revoke the current dynamic database users, issue fresh ones, and restart "
                   "the application tier onto them.",
        "when": "A credential is suspected exposed, or on a scheduled rotation. Analysis in "
                "flight is interrupted — the worker restarts.",
        "disruptive": True,
    },
    "consul-converge-policy": {
        "title": "Re-apply mesh authorization policy",
        "summary": "Write the intentions in config-entries/ back to Consul.",
        "when": "The enforced policy has drifted from the file — a pair is denied that the "
                "file allows, or vice versa.",
        "disruptive": False,
    },
    "restart-worker": {
        "title": "Restart the analysis worker",
        "summary": "Restart the sandboxed worker and its proxy.",
        "when": "The worker is wedged: tasks queued and none progressing. Any analysis "
                "currently running is lost and must be re-queued.",
        "disruptive": True,
    },
    "reap-boundary-workers": {
        "title": "Reap stale Boundary worker registrations",
        "summary": "Remove registrations that no longer correspond to a running worker.",
        "when": "Analyst sessions authorize and then hang. A dead registration still "
                "advertises an address, and the controller keeps handing sessions to it — so "
                "some connect and some do not, which reads as an intermittent network fault.",
        "disruptive": False,
    },
}


def catalogue():
    """The actions, shaped for the UI."""
    return [{"action": name, **meta} for name, meta in sorted(CATALOG.items())]


def is_known(action: str) -> bool:
    return action in CATALOG
