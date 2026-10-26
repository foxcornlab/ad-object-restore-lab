# `ad-object-restore-lab`

Offline audit for the two AD corners that bite in the same attack chain:
deleted objects that can be restored, and delegated Managed Service
Accounts (`dMSA`) that succeed someone they should not.

This grew out of the `HTB Checkpoint - Windows` write-up: restore a
deleted AD object, phish in via a `.VSIX` file, then use `BadSuccessor`
to make a `dMSA` succeed a service account. The tool below does not
replay that chain. It audits an export you already have, so you can
find the same shapes on a domain you defend, before someone else does.

## `What it checks`

* `Deleted objects` - tombstoned objects in `CN=Deleted Objects`, split
  into restorable (`isDeleted=TRUE`) and recycled (`isRecycled=TRUE`,
  past the deleted-object lifetime, backup-only).
* `BadSuccessor dMSA links` - any `dMSA` with a
  `msDS-ManagedAccountPrecededByLink`, graded by shape:
  * `CRITICAL` - bidirectional link (`SucceededByLink` back on the
    target) + state `2` + privileged target. This pair satisfies the
    post-patch KDC check.
  * `HIGH` - one-sided link + state `2` + privileged target. The
    pre-patch `BadSuccessor` shape; still wrong on a patched DC.
  * `MEDIUM` / `LOW` - link to a non-privileged target, migration-
    complete state with no predecessor, or an incomplete migration.
* `Privilege, honestly` - judged from the target in the same export
  (`memberOf` privileged groups, or a `objectSid` ending `-500`,
  `-512`, `-518`, `-519`). A target missing from the export is
  reported as unresolved, not quietly cleared.

## `What it does NOT do`

No live AD connection. No restore, no write, no ticket request, no
credential handling. It reads a file and prints a report. If your
export does not contain an object, the tool cannot see it, and a
clean report is not proof of a clean domain.

## `Usage`

```sh
# LDIF export (ldifde / ldapsearch, deleted objects included)
python3 ad_object_restore_lab.py --input export.ldif

# JSON list of objects, with a machine-readable report
python3 ad_object_restore_lab.py --input objects.json --format json --output report.json
```

Try it on the synthetic sample first. Nothing in `samples/` is real:

```sh
python3 ad_object_restore_lab.py --input samples/sample.ldif
# 7 objects scanned, 4 findings: 1 CRITICAL, 1 HIGH, 2 INFO
```

## `Lab exercises`

1. `Run the sample` - confirm the `CRITICAL` bidirectional case and
   the `HIGH` one-sided case, and that the clean `dMSA` and clean
   user produce no findings.
2. `Break it on purpose` - change the sample `dMSA` state from `2`
   to `1` and re-run. The finding drops to `LOW`: the link exists,
   the migration is not marked complete.
3. `Take a real export` - from a lab DC you own, export deleted
   objects and `dMSA` objects, run the tool, and triage every
   `CRITICAL` / `HIGH` hit as a genuine migration or not. Genuine
   migrations come from `migrateADServiceAccount`; anything else
   needs an owner and a ticket, not a shrug.
4. `Check the patch story` - a one-sided link on a fully patched
   DC should not yield tickets, but it is still a misconfiguration
   to remove. Do not close a `HIGH` finding with "patched" alone.

## `Sources, and where they disagree`

* Akamai (`BadSuccessor`, Yuval Gordon, May 2025) - one-sided
  `PrecededByLink` + state `2` was enough for the KDC to issue the
  target's tickets; `91%` of reviewed environments had users able
  to create `dMSA`s in some OU.
* Microsoft (`CVE-2025-53779`) - KDC fix requiring the bidirectional
  pair before issuing `KERB-DMSA-KEY-PACKAGE` material.
* Microsoft Docs (`AD Recycle Bin`) - `isDeleted` / `isRecycled` /
  `msDS-deletedObjectLifetime` / `tombstoneLifetime` lifecycle used
  for the deleted-object checks.

This tool follows both: it flags one-sided and bidirectional links,
and labels which case each finding is, instead of picking one
source and hiding the other.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
# 6 tests: deleted / recycled, live-user clean, bidirectional
# CRITICAL, one-sided HIGH, clean dMSA, JSON input parity
```

## `Thanks to`

* Akamai research on `BadSuccessor`, and Microsoft's `CVE-2025-53779`
  write-up, for the attribute-level detail this audit is built on.
* The `NetExec` team, whose `tombstone` module made deleted-object
  enumeration a normal part of AD review.
* The `HTB Checkpoint` box, for the chain this lab is named after.

## `Disclaimer`

Educational and defensive use only. Run it on exports from domains
you own or are authorised to audit. A finding is a lead, not a
verdict: confirm a genuine migration before disabling anything.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
