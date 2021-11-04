# mkbtr

Generate Switch NCA updates using BKTR tables.

## Usage

To use the main mkbktr generation tool:
`$ mkbtr [original nca] [patched nca] [output nca] [/path/to/prod.keys]`

TODO: add guide for small utils

## Building

Building is the standard CMake process:
```
mkdir build
cd build
ccmake ../
make
```

Just use `make` to rebuild with any changes after the makefile is generated. Rerun `ccmake` if you make any changes to the CMakeLists.txt file.


## Generating an update NSP

In order to make a full installable NSP that contains a BKTR-based game update,
you will first need to re-pack a 'full' NCA of the program NCA archive that
contains any changes you wish to make to the base game. Once you have your new
exefs and romfs direcories, an example command to pack this new NCA might be:

```sh
hacpack -k ${KEYFILE} \
  --type nca \
  --titleid base_game_title_id \
  --ncatype program \
  --exefsdir program_exefs/ \
  --romfsdir program_romfs/ \
  --keyareakey 32_byte_encryption_key \
  -o output_nca_dir/
```

Once you have this new NCA, you can use `mkbktr` to generate a patch NCA that
contains the same exefs as the base NCA, but with section 1 (romfs) replaced by
a BKTR entry.

```sh
./mkbktr \
    /path/to/original/game/program.nca \
    /path/to/output_nca_dir/new_custom.nca \
    output_bktr.nca \
    ${KEYFILE}
```

On completion, you will have an NCA that can be loaded directly into some
emulators that will work as a patch. However, it is not that portable in that
it is missing some update context information. For a better experience, we can
pack that NCA into an NSP. The easiest way to do this is to acquire an official
update NSP for the same title as a baseline. If we have one of these and
extract it to `${BASEPATCH}`, we can make a few modifications and then use
`scripts/generate_nsp.py` to re-pack a custom NSP.

First, we need to edit the program info XML in the `${BASEPATCH}` dir to
change some properties of the `Program` and `Meta` NCAs to placeholder values
that our patch script can fill in:

```xml
<Content>
  <Type>Program</Type>
  <Id>PROGRAM_SHORT_HASH</Id>
  <Size>PROGRAM_SIZE</Size>
  <Hash>PROGRAM_LONG_HASH</Hash>
  <KeyGeneration>11</KeyGeneration>
  <IdOffset>0</IdOffset>
</Content>
<Content>
  <Type>Meta</Type>
  <Id>CNMT_SHORT_HASH</Id>
  <Size>CNMT_SIZE</Size>
  <Hash>CNMT_LONG_HASH</Hash>
  <KeyGeneration>11</KeyGeneration>
  <IdOffset>0</IdOffset>
</Content>
```

It is also necessary to extract the old `sha256.cnmt.nca` archive to retrieve
the raw binary CNMT file so that we may patch it later. This can be done with
hactool -
```sh
hactool \
    -k ${KEYFILE} \
    -x existing.cnmt.nca \
    --section0dir=existing_cnmt
```

Once this is done, and the placeholder vars at the top of
`scripts/generate_nsp.py` are up to date, we can just run it. What this script
will do is

- Open the new BKTR program NCA and calculate a SHA256 digest. These digests
are used to content-address NCAs in the NSP.
- Binary patch the old CNMT data for the update NSP to replace the SHA256sum of
the old program NCA with our new BKTR NCA
- Re-pack this patched CNMT into an NCA using `hacpack`
- SHA256sum this new NCA
- Update the XML version of the CNMT with the new SHA256sums of the program and
patched CNMT NCAs
- Copy in the old progam info descriptor XML and rename with new SHA256sum
- Pack the new NCA archives, along with any directly copied NCA archives, into
a new NSP
