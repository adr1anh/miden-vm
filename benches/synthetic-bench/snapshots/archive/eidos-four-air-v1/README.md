# Historical protocol capture

`bench-tx.json` and `provenance/bench-tx.json` preserve the byte-exact Eidos four-AIR
protocol capture from before the packed Library/Controller/AEAD cutover. They are
outside the ordinary benchmark's top-level snapshot discovery.

The data uses the retired kernel-ROM breakdown and does not describe current
LibraryTree transaction execution. The current strict loader intentionally rejects
this schema. Do not rename its fields or present these counts as a current capture.
The original protocol and VM revisions, command, and capture hash remain recorded
in the unchanged provenance file.
