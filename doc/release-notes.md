*After branching off for a major version release of Bitcoin Core, use this
template to create the initial release notes draft.*

*The release notes draft is a temporary file that can be added to by anyone. See
[/doc/developer-notes.md#release-notes](/doc/developer-notes.md#release-notes)
for the process.*

*Create the draft, named* "*version* Release Notes Draft"
*(e.g. "0.20.0 Release Notes Draft"), as a collaborative wiki in:*

https://github.com/bitcoin-core/bitcoin-devwiki/wiki/

*Before the final release, move the notes back to this git repository.*

*version* Release Notes Draft
===============================

Bitcoin Core version 0.16.0 is now available from:

  <https://bitcoincore.org/bin/bitcoin-core-0.16.0/>

This release includes new features, various bug fixes and performance
improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoin/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoincore.org/en/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on Mac)
or `bitcoind`/`bitcoin-qt` (on Linux).

Upgrading directly from a version of Bitcoin Core that has reached its EOL is
possible, but it might take some time if the datadir needs to be migrated. Old
wallet versions of Bitcoin Core are generally supported.

Compatibility
==============

Bitcoin Core is supported and extensively tested on operating systems using
the Linux kernel, macOS 10.10+, and Windows 7 and newer. It is not recommended
to use Bitcoin Core on unsupported systems.

Bitcoin Core should also work on most other Unix-like systems but is not
as frequently tested on them.

From Bitcoin Core 0.17.0 onwards, macOS versions earlier than 10.10 are no
longer supported, as Bitcoin Core is now built using Qt 5.9.x which requires
macOS 10.10+. Additionally, Bitcoin Core does not yet change appearance when
macOS "dark mode" is activated.

In addition to previously supported CPU platforms, this release's pre-compiled
distribution provides binaries for the RISC-V platform.

Notable changes
===============

Build System
------------

- OpenSSL is no longer used by Bitcoin Core. The last usage of the library
was removed in #17265.

New RPCs
--------

New settings
------------

Updated settings
----------------

Updated RPCs
------------

Note: some low-level RPC changes mainly useful for testing are described in the
Low-level Changes section below.

GUI changes
-----------

Wallet
------

- The wallet now by default uses bech32 addresses when using RPC, and creates native segwit change outputs.
- The way that output trust was computed has been fixed in #16766, which impacts confirmed/unconfirmed balance status and coin selection.

Low-level changes
=================

Tests
-----

- `-fallbackfee` was 0 (disabled) by default for the main chain, but 0.0002 by default for the test chains. Now it is 0
  by default for all chains. Testnet and regtest users will have to add `fallbackfee=0.0002` to their configuration if
  they weren't setting it and they want it to keep working like before. (#16524)

Credits
=======

Thanks to everyone who directly contributed to this release:

- 251
- Aaron Clauson
- Aaron Golliver
- aaron-hanson
- Adam Langley
- Akio Nakamura
- Akira Takizawa
- Alejandro Avilés
- Alex Morcos
- Alin Rus
- Anditto Heristyo
- Andras Elso
- Andreas Schildbach
- Andrew Chow
- Anthony Towns
- azuchi
- Carl Dong
- Chris Moore
- Chris Stewart
- Christian Gentry
- Cory Fields
- Cristian Mircea Messel
- CryptAxe
- Dan Raviv
- Daniel Edgecumbe
- danra
- david60
- Donal O'Connor
- dongsamb
- Dusty Williams
- Eelis
- esneider
- Evan Klitzke
- fanquake
- Ferdinando M. Ametrano
- fivepiece
- flack
- Florian Schmaus
- gnuser
- Gregory Maxwell
- Gregory Sanders
- Henrik Jonsson
- Jack Grigg
- Jacky C
- James Evans
- James O'Beirne
- Jan Sarenik
- Jeff Rade
- Jeremiah Buddenhagen
- Jeremy Rubin
- Jim Posen
- jjz
- Joe Harvell
- Johannes Kanig
- John Newbery
- Johnson Lau
- Jonas Nick
- Jonas Schnelli
- João Barbosa
- Jorge Timón
- Karel Bílek
- Karl-Johan Alm
- klemens
- Kyuntae Ethan Kim
- laudaa
- Lawrence Nahum
- Lucas Betschart
- Luke Dashjr
- Luke Mlsna
- MarcoFalke
- Mark Friedenbach
- Marko Bencun
- Martin Ankerl
- Matt Corallo
- mruddy
- Murch
- NicolasDorier
- Pablo Fernandez
- Paul Berg
- Pedro Branco
- Pierre Rochard
- Pieter Wuille
- practicalswift
- Randolf Richardson
- Russell Yanofsky
- Samuel Dobson
- Sean Erle Johnson
- Shooter
- Sjors Provoost
- Suhas Daftuar
- Thomas Snider
- Thoragh
- Tim Shimmin
- Tomas van der Wansem
- Utsav Gupta
- Varunram Ganesh
- Vivek Ganesan
- Werner Lemberg
- William Casarin
- Willy Ko
- Wladimir J. van der Laan

As well as to everyone that helped with translations on
[Transifex](https://www.transifex.com/bitcoin/bitcoin/).
