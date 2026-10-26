#!/usr/bin/env python3
"""`ad-object-restore-lab`: offline audit of AD deleted objects and dMSA links.

Reads an `LDIF` export (from `ldifde` / `ldapsearch`, including deleted
objects) or a `JSON` list of AD objects, and reports, without touching a
live directory:

* tombstoned / deleted objects still in the `Deleted Objects` container,
  restorable (`isDeleted=TRUE`, `isRecycled` unset) vs recycled
  (`isRecycled=TRUE`, no longer restorable);
* delegated Managed Service Accounts (`dMSA`) carrying a
  `msDS-ManagedAccountPrecededByLink` to another account - the
  `BadSuccessor` pattern - and whether the link is one-sided or
  bidirectional (`msDS-ManagedAccountSucceededByLink` on the target).

Detection-only. It never connects to AD, never restores anything, never
sends a credential, and never writes to a directory. Feed it an export
you already took from a lab or a domain you administer.

Why both link shapes are flagged
---------------------------------
Sources disagree on what still works after the patch, so the tool
flags both and says which case each finding is:

* Pre-patch (Akamai, May 2025): a one-sided link plus
  `msDS-DelegatedMSAState=2` was enough for the KDC to issue the
  target's tickets. Patched as `CVE-2025-53779`.
* Post-patch: the KDC requires the bidirectional pair -
  `msDS-ManagedAccountPrecededByLink` on the `dMSA` AND
  `msDS-ManagedAccountSucceededByLink` on the target - before it
  issues `KERB-DMSA-KEY-PACKAGE` material.

So: bidirectional + state `2` + privileged target = `CRITICAL`
(effective even on a patched DC); one-sided + state `2` +
privileged target = `HIGH` (effective on an unpatched DC, and
still a misconfiguration anywhere). A link to a non-privileged
target, or a `dMSA` in migration-complete state with no
predecessor at all, is reported at lower severity, not hidden.

Privilege is judged from the target object in the same export:
membership of `Domain Admins` / `Enterprise Admins` / `Schema
Admins` / `Administrators`, or an `objectSid` ending in `-500`,
`-512`, `-518` or `-519`. If the target is not in the export,
privilege is reported as `unknown` and the finding is not
silently downgraded to clean.

Usage
-----
    python3 ad_object_restore_lab.py --input export.ldif
    python3 ad_object_restore_lab.py --input objects.json --format json --output report.json
"""

import argparse
import base64
import json
import sys

PRIVILEGED_GROUP_NAMES = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "dnsadmins",
)
PRIVILEGED_SID_SUFFIXES = ("-500", "-501", "-512", "-518", "-519", "-520")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _norm_dn(dn):
    """Lower-case a DN for matching, keeping the original for display."""
    return " ".join(dn.lower().split())


def parse_ldif(text):
    """Parse LDIF into a list of {dn, attrs} dicts.

    Handles folded lines (continuation starts with a single space),
    multi-valued attributes, and base64 (`attr:: value`) values.
    Comment lines and `changetype` / control lines are ignored.
    """
    objects = []
    entry = None

    def flush():
        nonlocal entry
        if entry is not None:
            objects.append(entry)
        entry = None

    lines = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    for line in lines:
        if not line.strip():
            flush()
            continue
        if line.startswith("#"):
            continue
        if ":" not in line:
            continue
        attr, _, value = line.partition(":")
        attr = attr.strip().lower()
        if attr in ("changetype", "control", "version"):
            continue
        if value.startswith(":"):
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", "replace")
            except Exception:
                value = value[1:].strip()
        else:
            value = value.strip()
        if attr == "dn":
            flush()
            entry = {"dn": value, "attrs": {}}
        elif entry is not None:
            entry["attrs"].setdefault(attr, []).append(value)
    flush()
    return objects


def parse_json(text):
    """Parse a JSON list of objects.

    Accepted shapes per object: {"dn": ..., "attributes": {...}} or
    {"distinguishedName": ..., ...flat attributes...}. Attribute
    values may be strings or lists of strings.
    """
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("objects", [])
    objects = []
    for item in data:
        if not isinstance(item, dict):
            continue
        dn = item.get("dn") or item.get("distinguishedName") or ""
        attrs_in = item.get("attributes") or {
            k: v for k, v in item.items() if k not in ("dn", "distinguishedName")
        }
        attrs = {}
        for key, value in attrs_in.items():
            if value is None:
                continue
            if isinstance(value, list):
                attrs[key.lower()] = [str(v) for v in value]
            else:
                attrs[key.lower()] = [str(value)]
        objects.append({"dn": dn, "attrs": attrs})
    return objects


def _first(obj, attr):
    values = obj["attrs"].get(attr.lower())
    return values[0] if values else None


def _all(obj, attr):
    return obj["attrs"].get(attr.lower(), [])


def _is_true(value):
    return value is not None and value.strip().lower() in ("true", "1", "yes")


def _object_classes(obj):
    return [c.lower() for c in _all(obj, "objectClass")]


def _is_dmsa(obj):
    classes = _object_classes(obj)
    return any("delegatedmanagedserviceaccount" in c for c in classes)


def _is_privileged(obj):
    """Decide privilege from data in the export, not from the DN name."""
    sid = _first(obj, "objectSid")
    if sid and any(sid.strip().endswith(s) for s in PRIVILEGED_SID_SUFFIXES):
        return True
    for group_dn in _all(obj, "memberOf"):
        # memberOf holds DNs; match on the first RDN component only.
        rdn = group_dn.split(",", 1)[0].strip().lower()
        if rdn.startswith("cn="):
            rdn = rdn[3:]
        if rdn in PRIVILEGED_GROUP_NAMES:
            return True
    return False


def _short_name(dn):
    return dn.split(",", 1)[0] if dn else ""


def audit(objects):
    """Return (findings, summary) for a parsed object list."""
    by_dn = {_norm_dn(o["dn"]): o for o in objects if o["dn"]}
    findings = []

    def add(severity, kind, dn, detail, recommendation):
        findings.append(
            {
                "severity": severity,
                "type": kind,
                "dn": dn,
                "detail": detail,
                "recommendation": recommendation,
            }
        )

    for obj in objects:
        dn = obj["dn"]
        deleted = _is_true(_first(obj, "isDeleted"))
        recycled = _is_true(_first(obj, "isRecycled"))
        in_deleted_container = "cn=deleted objects" in dn.lower()
        if deleted or in_deleted_container:
            classes = _all(obj, "objectClass") or ["unknown"]
            parent = _first(obj, "lastKnownParent") or "unknown (attribute stripped by tombstoning)"
            changed = _first(obj, "whenChanged") or "unknown"
            if recycled:
                add(
                    "INFO",
                    "recycled-object",
                    dn,
                    "Recycled object (%s): isDeleted=TRUE, isRecycled=TRUE. "
                    "Past the deleted-object lifetime; not restorable from "
                    "the Recycle Bin." % ", ".join(classes),
                    "Recover from backup only. Do not expect Restore-ADObject to work.",
                )
            else:
                add(
                    "INFO",
                    "deleted-object-restorable",
                    dn,
                    "Deleted object (%s), restorable while the deleted-object "
                    "lifetime lasts. Last known parent: %s. Last changed: %s."
                    % (", ".join(classes), parent, changed),
                    "Review before restoring: a restored object comes back "
                    "disabled, stripped of most attributes and group "
                    "membership, but keeps its original SID.",
                )

    for obj in objects:
        dn = obj["dn"]
        if not _is_dmsa(obj):
            continue
        links = _all(obj, "msDS-ManagedAccountPrecededByLink")
        state = _first(obj, "msDS-DelegatedMSAState")
        if not links and state == "2":
            add(
                "MEDIUM",
                "dmsa-migration-complete-no-predecessor",
                dn,
                "dMSA reports msDS-DelegatedMSAState=2 (migration complete) "
                "but has no msDS-ManagedAccountPrecededByLink in this export.",
                "Confirm this dMSA went through a real migrateADServiceAccount "
                "migration; a state-2 dMSA with no predecessor is not a normal "
                "end state.",
            )
        for link in links:
            target = by_dn.get(_norm_dn(link))
            if target is None:
                add(
                    "HIGH",
                    "dmsa-predecessor-link-target-absent",
                    dn,
                    "dMSA links to %s (msDS-DelegatedMSAState=%s), but that "
                    "object is not in this export, so its privilege cannot be "
                    "confirmed." % (link, state or "unknown"),
                    "Export the target object too and re-run; treat an "
                    "unresolved predecessor link as suspicious until checked.",
                )
                continue
            back_links = _all(target, "msDS-ManagedAccountSucceededByLink")
            bidirectional = any(_norm_dn(b) == _norm_dn(dn) for b in back_links)
            privileged = _is_privileged(target)
            if bidirectional and state == "2" and privileged:
                add(
                    "CRITICAL",
                    "badsuccessor-bidirectional-privileged",
                    dn,
                    "dMSA (state=2) points at privileged target %s and the "
                    "target points back (msDS-ManagedAccountSucceededByLink). "
                    "This pair satisfies the post-CVE-2025-53779 KDC check."
                    % link,
                    "Treat as compromise until proven a genuine migration: "
                    "disable the dMSA, audit who created it and who can write "
                    "these attributes, and check for tickets issued for it.",
                )
            elif state == "2" and privileged:
                add(
                    "HIGH",
                    "badsuccessor-one-sided-privileged",
                    dn,
                    "dMSA (state=2) points at privileged target %s with a "
                    "one-sided link (no SucceededByLink back). Pre-patch this "
                    "was the BadSuccessor shape; on a patched DC the KDC "
                    "should refuse it, but the configuration is still wrong."
                    % link,
                    "Remove the link or complete a genuine migration, and "
                    "confirm the DCs carry the CVE-2025-53779 KDC fix.",
                )
            elif state == "2":
                add(
                    "MEDIUM",
                    "dmsa-predecessor-link",
                    dn,
                    "dMSA (state=2) points at %s, which is not privileged in "
                    "this export. Still a successor link worth confirming."
                    % link,
                    "Confirm a genuine migration; if not, remove the link.",
                )
            else:
                add(
                    "LOW",
                    "dmsa-predecessor-link-incomplete",
                    dn,
                    "dMSA points at %s but msDS-DelegatedMSAState=%s, not 2, "
                    "so the migration is not marked complete."
                    % (link, state or "unset"),
                    "Watch it: a later state change to 2 would complete the "
                    "successor relationship.",
                )

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    summary = {
        "objects": len(objects),
        "findings": len(findings),
        "by_severity": {},
        "by_type": {},
    }
    for finding in findings:
        summary["by_severity"][finding["severity"]] = (
            summary["by_severity"].get(finding["severity"], 0) + 1
        )
        summary["by_type"][finding["type"]] = summary["by_type"].get(finding["type"], 0) + 1
    return findings, summary


def render_text(findings, summary):
    lines = [
        "ad-object-restore-lab: %d objects scanned, %d findings"
        % (summary["objects"], summary["findings"]),
        "by severity: %s" % (summary["by_severity"] or "none"),
        "",
    ]
    if not findings:
        lines.append("Clean on the checks above. That is not proof of a clean domain: "
                     "this tool only sees what is in the export.")
    for finding in findings:
        lines.append("[%s] %s" % (finding["severity"], finding["type"]))
        lines.append("  DN: %s" % finding["dn"])
        lines.append("  %s" % finding["detail"])
        lines.append("  -> %s" % finding["recommendation"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline audit of AD deleted objects and dMSA successor links."
    )
    parser.add_argument("--input", required=True, help="LDIF or JSON export file")
    parser.add_argument("--format", choices=["ldif", "json"], default="ldif")
    parser.add_argument("--output", help="Write JSON report to this path (default: stdout text)")
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    objects = parse_ldif(text) if args.format == "ldif" else parse_json(text)
    findings, summary = audit(objects)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump({"summary": summary, "findings": findings}, handle, indent=2)
            handle.write("\n")
    print(render_text(findings, summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
