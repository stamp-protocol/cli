# Stamp CLI

This is the command-line interface to the [stamp protocol](https://github.com/stamp-protocol/core).

## Getting started

Hi, it looks like you're trying to install a distributed cryptographic identity
system. Would you like help??

First, install rust 1.48+ and cargo. Then grab the core and the cli and build them:

```sh
mkdir stamp
cd stamp
git clone https://github.com/stamp-protocol/core.git
git clone https://github.com/stamp-protocol/aux.git
git clone https://github.com/stamp-protocol/cli.git
git clone https://github.com/stamp-protocol/net.git
cd cli
make
ln -s ./target/debug/cli stamp
```

Great, we're done!

## Usage

Let's walk through a usage example. First, let's create our first identity:

```sh
$ ./stamp id new
```

This command walks you through creating a new identity. It should have also set
your new identity as the default, so many of the following commands will "just
work."

Let's look at our identity!

```sh
$ ./stamp id list
```

This lists all of your identities and also any imported identities from others.
Now let's inspect the one your just created:

```sh
$ ./stamp id view <id>
```

This outputs your identity in human-readable format, giving you a big-picture
view of how your identity fits together and what it looks like.

That's it for our stupid tutorial. Feel free to explore the stamp cli:

```sh
$ ./stamp help
```

This will list all available commands, and allows you to explore what stamp
can do.

## What's next?

Check out the [Stamp core readme](https://github.com/stamp-protocol/core), which
gives a lot of background information on how the protocol works and how it can
be used.

