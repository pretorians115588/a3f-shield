# Threat model and limits

The design authenticates ciphertext contents and can reject an older document
generation when an independently trusted witness retains the current lineage.
The v6 prototype checks the authenticated log chain before issuing a receipt
and rejects a modified document-head index.

The design does not protect against a compromised user account, an administrator
or kernel attacker, plaintext already exposed in process memory, stolen keys,
complete rollback of both witness state and all independent checkpoints, or
metadata and traffic analysis. These are explicit non-goals, not security
claims.

