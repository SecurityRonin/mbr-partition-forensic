# Test data — provenance

Real-world fixtures consumed by this repo's integration tests. Every entry below
records source, identity, hashes, redistribution status, and the test that reads
it, per the fleet Test-Data Provenance Standard. The fleet machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen); this
README is the co-located human-facing detail (cross-reference, do not duplicate).

## `dftt_mmls_1_mbr.dd`

The real 512-byte MBR sector (sector 0) of `imageformat_mmls_1`, a Brian-Carrier
**DFTT — Digital Forensics Tool Testing** corpus image.

- **Source:** DFTT corpus (`dftt.sourceforge.net`), authored by Brian Carrier;
  image created with FTK Imager. Distributed within the fleet as
  `imageformat_mmls_1.E01` (EWF v1, compressed, 405 KiB) under
  [`ewf-forensic/tests/data/`](https://github.com/SecurityRonin/ewf-forensic).
  The DFTT images are published as public test data.
- **Classification:** `REAL-ext` (third-party authored artifact + third-party
  oracle) — confidence `✓`.
- **Identity / contents:** DOS partition table, two primary NTFS partitions
  (type `0x07`); no extended/logical partitions.
- **Extraction (verbatim):** the parent E01 is ~57 MiB raw (too large to commit),
  so only the authentic MBR sector is committed. Its sector 0 is byte-identical
  to the parent image's sector 0:
  ```sh
  # parent E01 lives in the ewf-forensic repo's tests/data/
  img_cat imageformat_mmls_1.E01 | head -c 512 > dftt_mmls_1_mbr.dd
  ```
  `img_cat` (The Sleuth Kit) and `head` only copy bytes; they do not author the
  partition table.
- **Parent E01 MD5:** `bb6c6bec25d589e87a11af9129275cc9`
- **Fixture MD5:** `775574d985ad9aa94a6b18bbdc919f48`
- **Fixture SHA-256:** `5ddbb09a73ca1cf8e3e8a8bfc5176713e6ea8e7b663b9853befc207aa0331bc4`
- **Redistribution:** public DFTT test data; only the 512-byte boot sector
  (table + boot code, no file content) is committed here.
- **Consumed by:** [`forensic/tests/real_mbr_oracle.rs`](../../forensic/tests/real_mbr_oracle.rs).

### Independent oracle (the answer key)

Ground truth is produced by tools that share no code with this crate.

`mmls` (The Sleuth Kit 4.12.1), run on the authentic image (E01 directly, and on
a sparse raw image rebuilt from this fixture's sector 0 — identical output):

```text
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000127   0000000128   Unallocated
002:  000:000   0000000128   0000055423   0000055296   NTFS / exFAT (0x07)
003:  000:001   0000055424   0000116863   0000061440   NTFS / exFAT (0x07)
```

`fdisk` (macOS), used for the active/bootable flag (mmls has no such column):

```text
 #: id  cyl  hd sec -  cyl  hd sec [     start -       size]
 1: 07    0   2   3 -    3 114  47 [       128 -      55296] HPFS/QNX/AUX
 2: 07    3 114  48 -    6 254  63 [     55424 -      61440] HPFS/QNX/AUX
 3: 00 ...                                                   unused
 4: 00 ...                                                   unused
```

No `*` active marker on either partition → neither is bootable (both status
bytes are `0x00`). The test asserts this crate's parse of each entry's
start/end/length-LBA, type byte, and bootable flag against these values.
