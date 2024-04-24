# Stamp CLI changelog

The
<img style="display: inline-block; width: 0.75rem; height: 1rem; vertical-align: middle;" src="https://stamp-protocol.github.io/assets/images/fireanim.gif" alt="fireee">
hottest
<img style="display: inline-block; width: 0.75rem; height: 1rem; vertical-align: middle;" src="https://stamp-protocol.github.io/assets/images/fireanim.gif" alt="fireee">
Stamp CLI changes *allowed by law*.

## v0.1.4 // TBD

StampNet is born =]. The public Stamp identity storage network is taking shape. This allows storing
and retrieving *valid* identities in a p2p DHT. Currently the network has no validation for storing,
so anybody can come in off the street and publish and identity. Might need some form of rate limiting
eventually, but for now we can pretend it's gay space communism and kick that can down the road.

### Features

- StampNet v0.0.0.0.0.0.0.1!!!
  - Run a public DHT node (`stamp net node`)
  - Publish your identity (`stamp net publish`)
  - Get an identity (`stamp net get`)
  - Update default StampNet servers (`stamp config set-stampnet-servers`)
- `stamp id import` now accepts three input types:
  - A local path: `stamp id import /path/to/identity`. This was how the original command worked and is unchanged.
  - A url: `stamp id import https://martymalt.com/blumps.stamp`. You can now import identities direct from the
    world wide web. You can also use `file://` urls for local files.
  - A Stamp url: `stamp id import stamp://s0f__TtNxiUrNJ8yi14vVQteecP7xQYQzcohhPqOdt8A`. This is pretty much the
    exact same as `stamp net get <id>`.
- Changing signature verification messages to be more clear.
- Rename "Identity signature" to "Policy signature." I believe it's less ambiguous.

## v0.1.3 // 2024-02-19

Fixing subkey signatures, adding identity signatures, and updating staged transaction interface.

### Features

- Adding the ability to create `SignV1` signing transactions via the `sign` command. This allows creating
"official" identity-sanctioned signatures that follow the policy system.
- Adding `import` and `export` subcommands to the `stage` command. This allows exporting staged transactions
and moving them between identities for signing. This was mainly to support identity signatures, but is
also useful in general for staged transactions.

### Bugfixes

- Subkey signatures were broken because I renamed some stuff and never fixed it.

## v0.1.2 // 2024-02-18

New claim type, fixing claim listing bug, replace `Confidence::None` with `Confidence::Negative`.

### Features

- Phone number claims. These cannot be instantly verified, unfortunately, because they require telecommunications
infrastructure that most users don't own outright.
- Replacing `Confidence::None` with `Confidence::Negative` which allows marking a claim as **false** and
advertising this in your identity, which can serve as a warning to others who trust you.

### Bugfixes

- When doing `stamp claim list -p --id s0f` it would take `s0f` as the literal identity id, which
caused parsing errors in the core. This has been corrected.

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

### Bugfixes

- None, it's perfect in every way.

