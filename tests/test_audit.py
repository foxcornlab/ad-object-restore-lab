"""Tests for `ad_object_restore_lab`. Stdlib only: `python3 -m unittest discover -s tests -v`."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ad_object_restore_lab import audit, parse_json, parse_ldif  # noqa: E402


def _ldif_for(dn, *attr_lines):
    return "dn: %s\n%s\n" % (dn, "\n".join(attr_lines))


class TestDeletedObjects(unittest.TestCase):
    def test_restorable_and_recycled(self):
        text = (
            _ldif_for(
                "CN=a\\0ADEL:1,CN=Deleted Objects,DC=example,DC=com",
                "objectClass: user",
                "isDeleted: TRUE",
                "lastKnownParent: OU=Users,DC=example,DC=com",
            )
            + "\n"
            + _ldif_for(
                "CN=b\\0ADEL:2,CN=Deleted Objects,DC=example,DC=com",
                "objectClass: computer",
                "isDeleted: TRUE",
                "isRecycled: TRUE",
            )
        )
        findings, summary = audit(parse_ldif(text))
        types = [f["type"] for f in findings]
        self.assertIn("deleted-object-restorable", types)
        self.assertIn("recycled-object", types)
        self.assertEqual(summary["objects"], 2)

    def test_live_user_is_not_flagged_as_deleted(self):
        text = _ldif_for(
            "CN=normal,OU=Users,DC=example,DC=com",
            "objectClass: user",
            "sAMAccountName: normal",
        )
        findings, _ = audit(parse_ldif(text))
        self.assertEqual(findings, [])


class TestBadSuccessor(unittest.TestCase):
    def _target(self, extra=()):
        return _ldif_for(
            "CN=Domain Admins,CN=Users,DC=example,DC=com",
            "objectClass: group",
            "objectSid: S-1-5-21-100-200-300-512",
            *extra,
        )

    def _dmsa(self, name, state, link):
        lines = [
            "objectClass: msDS-DelegatedManagedServiceAccount",
        ]
        if state is not None:
            lines.append("msDS-DelegatedMSAState: %s" % state)
        if link is not None:
            lines.append("msDS-ManagedAccountPrecededByLink: %s" % link)
        return _ldif_for("CN=%s,OU=ServiceAccounts,DC=example,DC=com" % name, *lines)

    def test_bidirectional_privileged_is_critical(self):
        target_dn = "CN=Domain Admins,CN=Users,DC=example,DC=com"
        dmsa_dn = "CN=svc-bad,OU=ServiceAccounts,DC=example,DC=com"
        text = self._target(("msDS-ManagedAccountSucceededByLink: %s" % dmsa_dn,)) + "\n" + self._dmsa(
            "svc-bad", "2", target_dn
        )
        findings, _ = audit(parse_ldif(text))
        critical = [f for f in findings if f["type"] == "badsuccessor-bidirectional-privileged"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["severity"], "CRITICAL")

    def test_one_sided_privileged_is_high_not_critical(self):
        text = self._target() + "\n" + self._dmsa(
            "svc-one", "2", "CN=Domain Admins,CN=Users,DC=example,DC=com"
        )
        findings, _ = audit(parse_ldif(text))
        self.assertTrue(any(f["type"] == "badsuccessor-one-sided-privileged" for f in findings))
        self.assertFalse(any(f["severity"] == "CRITICAL" for f in findings))

    def test_clean_dmsa_and_missing_target(self):
        text = self._dmsa("svc-clean", "0", None) + "\n" + self._dmsa(
            "svc-ghost", "2", "CN=nobody,DC=example,DC=com"
        )
        findings, _ = audit(parse_ldif(text))
        types = [f["type"] for f in findings]
        self.assertIn("dmsa-predecessor-link-target-absent", types)
        self.assertEqual(len([f for f in findings if "svc-clean" in f["dn"]]), 0)

    def test_json_input_matches_ldif(self):
        data = [
            {
                "dn": "CN=Domain Admins,CN=Users,DC=example,DC=com",
                "attributes": {"objectClass": ["group"], "objectSid": "S-1-5-21-100-200-300-512"},
            },
            {
                "dn": "CN=svc-one,OU=ServiceAccounts,DC=example,DC=com",
                "attributes": {
                    "objectClass": ["msDS-DelegatedManagedServiceAccount"],
                    "msDS-DelegatedMSAState": "2",
                    "msDS-ManagedAccountPrecededByLink": "CN=Domain Admins,CN=Users,DC=example,DC=com",
                },
            },
        ]
        findings, _ = audit(parse_json(json.dumps(data)))
        self.assertTrue(any(f["type"] == "badsuccessor-one-sided-privileged" for f in findings))


if __name__ == "__main__":
    unittest.main()
