#!/usr/bin/env python3
import hashlib
import os
import shutil
import subprocess
import sys

# Path to keystore for Switch encryption keys
KEYFILE = "/path/to/prod.keys"

# Folder containing the NCAs that should be used as source material for the new
# update NSP
BASEPATCH = "update_context"

# Temprary directory for files that will be packed into NSP
TMPDIR = "tmp_nsp"

# Temporary file for regenerating CNMT archive
CNMT_TMPDIR = "tmp_cnmt"

# In the BASEPATCH directory, there must be a programinfo template with the
# following placeholder terms:
PROGRAM_INFO = "xxx.programinfo.xml"

# Short SHA256 of the old progam NCA
OLD_PROGRAM_HASH = 'old_progam_sha256'

# Short SHA256 of the older CNMT archive
CNMT_HASH = "old_cnmt_sha256"

# SHA256 short hashes for other files that should be copied without
# alteration from BASEPATCH
AUX_HASHES = [
    "aux_sha256_0",
    "aux_sha256_1",
]

# Title ID of the base game
BASE_TITLEID = 'base_game_titleid'

# Update title ID
UPDATE_TITLEID = 'base_game_update_titleid'


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} [patch_nca]")
        return

    patch_nca_path = sys.argv[1]

    # Generate SHA256 of new program NCA
    ctx = hashlib.sha256()
    patch_size = 0
    print("Generating program SHA256...")
    with open(patch_nca_path, 'rb') as f:
        patch_data = f.read()
        patch_size = len(patch_data)
        ctx.update(patch_data)
    program_sha_hex = ctx.hexdigest()
    print(f"{patch_nca_path}: {program_sha_hex}")

    # Patch old CNMT binary
    try:
        shutil.rmtree(CNMT_TMPDIR)
    except FileNotFoundError:
        pass
    try:
        os.makedirs(CNMT_TMPDIR)
    except FileExistsError:
        pass
    patched_cnmt = os.path.join(CNMT_TMPDIR, f'Patch_{UPDATE_TITLEID}.cnmt')
    patch_cnmt_args = [
        'patch_cnmt',
        os.path.join(BASEPATCH, f'Patch_{UPDATE_TITLEID}.cnmt'),
        OLD_PROGRAM_HASH,
        patch_nca_path,
        patched_cnmt
    ]
    print(patch_cnmt_args)
    subprocess.run(patch_cnmt_args)

    # Pack new CNMT NCA
    cnmt_pack_args = [
        'hacpack',
        '-k', KEYFILE,
        '--type', 'nca',
        '--titleid', UPDATE_TITLEID,
        '--ncatype', 'meta',
        '--titletype', 'patch',
        '--cnmt', patched_cnmt,
        '-o', CNMT_TMPDIR
    ]
    print(cnmt_pack_args)
    subprocess.run(cnmt_pack_args)

    # Get the hash of the new CNMT
    new_cnmt_filename = None
    new_cnmt_filepath = None
    for entry in os.scandir(CNMT_TMPDIR):
        if entry.name.endswith(".cnmt.nca"):
            new_cnmt_filename = entry.name
            new_cnmt_filepath = entry.path
    if not new_cnmt_filename:
        print("Failed to get name of new CNMT file")
        return

    # Generate SHA256 of new program NCA
    ctx = hashlib.sha256()
    print("Generating CNMT SHA256...")
    cnmt_size = 0
    with open(new_cnmt_filepath, 'rb') as f:
        cnmt_data = f.read()
        cnmt_size = len(cnmt_data)
        ctx.update(cnmt_data)
    new_cnmt_sha = ctx.hexdigest()
    print(f"{new_cnmt_filename:}: {new_cnmt_sha}")

    # Open our template cnmt XML
    cnmt_xml = None
    cnmt_src_xml = os.path.join(BASEPATCH, f"{CNMT_HASH}.cnmt.xml")
    with open(cnmt_src_xml, 'rb') as f:
        info_raw = f.read().decode('utf-8')

        # Substitute parameters for new NCA, don't bother doing full XML parse
        cnmt_xml = \
            info_raw.replace('PROGRAM_SHORT_HASH', program_sha_hex[0:32]) \
            .replace('PROGRAM_SIZE', str(patch_size)) \
            .replace('PROGRAM_LONG_HASH', program_sha_hex) \
            .replace('CNMT_SHORT_HASH', new_cnmt_sha[0:32]) \
            .replace('CNMT_SIZE', str(cnmt_size)) \
            .replace('CNMT_LONG_HASH', new_cnmt_sha)

    # Ensure output dir
    try:
        shutil.rmtree(TMPDIR)
    except FileNotFoundError:
        pass
    try:
        os.makedirs(TMPDIR)
    except FileExistsError:
        pass

    # Copy in any aux files in the src dir
    for entry in os.scandir(BASEPATCH):
        for sha in AUX_HASHES:
            if entry.name.startswith(sha):
                shutil.copyfile(entry.path, os.path.join(TMPDIR, entry.name))

    # Copy in new CNMT binary
    print(
        f"Copy {new_cnmt_filepath} -> "
        f"{os.path.join(TMPDIR, new_cnmt_filename)}")
    shutil.copyfile(new_cnmt_filepath, os.path.join(TMPDIR, new_cnmt_filename))

    # Write new cnmt info XML to patch dir
    cnmt_dst_xml = os.path.join(TMPDIR, f"{new_cnmt_sha[0:32]}.cnmt.xml")
    with open(cnmt_dst_xml, 'wb') as f:
        f.write(cnmt_xml.encode('utf-8'))

    # Copy in program info with appropriate hash
    shutil.copyfile(
        os.path.join(BASEPATCH, PROGRAM_INFO),
        os.path.join(TMPDIR, f"{program_sha_hex[0:32]}.programinfo.xml"))

    # Copy in program data itself
    shutil.copyfile(
        patch_nca_path,
        os.path.join(TMPDIR, f"{program_sha_hex[0:32]}.nca"))

    subprocess.run([
        'hacpack',
        '-k', KEYFILE,
        '--type', 'nsp',
        '--titleid', BASE_TITLEID,
        '--ncadir', TMPDIR,
        '-o', 'output_nsp'
    ])


if __name__ == '__main__':
    main()
