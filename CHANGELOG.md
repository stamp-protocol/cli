# Stamp CLI changelog

The ![fireeee](https://stamp-protocol.github.io/assets/images/fireanim.gif)hottest![fireeee](https://stamp-protocol.github.io/assets/images/fireanim.gif)
Stamp CLI changes *allowed by law*.

## v0.1.1 // 2024-02-08

Initial release (how do I do confetti emojis in md??)! Although unfinished, many features exist and
are wonderfully functional, including id generation, claims, stamping.

### Features

- IDs: create (random/vanity), list, import, export, publish, delete, view, fingerprint (try `stamp id fingerprint`, it's cool)
- Claims: create claims of almost any type (extension claims are not supported and might not be by CLI, we'll see).
- Stamps: Request stamps, create stamps, accept stamps. Stamps for everyone.
- Keychain: add/revoke/update/delete keys. Change identity master password. Create backup keyfile.
- Messages: create/open asym encrypted signed and anonymous.
- Config: update the one configuration value we use (default identity).
- Staging: list/view/sign/delete/apply staged transactions (ie, transactions requiring multiple sigs per the policy system).
- DAG: Interact with the DAG directly for a given identity. For now, can only list transactions or reset an identity to a
  specific transaction in the chain (ie, roll back time).
- Debug: some actions for me to help fix stuff when it breaks, probably ignore this.

### Missing

- Policy management. Currently only supports a simple god-mode default policy.
- Signatures. Used to be subkey-based, but I'm going to favor using the SignV1 transaction instead, which will
  engage the policy system to create much more official signatures.
- Agent. Will eventually run a p2p StampNet node, as well as act as the interface for other apps to request signatures or
  keys and stuff. Huge WIP.
- Trust calculations (ie, determining trust via networks of stamps in downloaded identities).

