import argparse
from io import BytesIO
import io
import string
import sys
import hashlib
import tarfile
import json
import os
import random
import getpass
from typing import IO
import tempfile
import platform
from pathlib import Path

from .decrypted_stream import DecryptedStream

class FailureError(Exception):
    """Indicates a failure with a user readable message attached"""
    
    def __init__(self, message: str) -> None:
        """Initialize failure error."""
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        """Return string representation of failure error."""
        return self.message


def size_to_str(size: int) -> str:
    """Convert a size in bytes to a human readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def overwrite(line: str):
    sys.stdout.write(f"\r{line.encode('utf-8', 'replace').decode()}\033[K")

def print_red(text: str):
    print(f"\033[91m{text}\033[0m")

def readTarMembers(tar: tarfile.TarFile):
    while(True):
        member = tar.next()
        if member is None:
            break
        else:
            yield member

class Backup:
    def __init__(self, tarfile: tarfile.TarFile):
        self._tarfile = tarfile
        self._configMember = None
        self._items: list[BackupItem] = []
        for member in self._tarfile.getmembers():
            # Note: Very old backups use 'snapshot.json' instead of 'backup.json'
            if member.name.endswith("snapshot.json") or member.name.endswith("backup.json"):
                self._configMember = member
            elif member.isreg():
                self._items.append(BackupItem(member, self))
        
        if not self._configMember:
            raise FailureError("Backup doesn't contain a 'backup.json' metadata file.  Ensure this is a Home Assistant Backup.")
        json_file = self._tarfile.extractfile(self._configMember)
        if not json_file:
            raise FailureError("Backup doesn't contain a 'backup.json' metadata file.  Ensure this is a Home Assistant Backup.'")
        self._config = json.loads(json_file.read())
        json_file.close()

    @property
    def encrypted(self):
        return self._config.get('protected', False)

    @property
    def items(self):
        return self._items

    @property
    def version(self):
        return self._config.get('version')

    def create_slug(self) -> str:
        key = ''.join(random.choice(string.ascii_uppercase) for _ in range(50)).encode()
        return hashlib.sha1(key).hexdigest()[:8]

    def addModifiedConfig(self, tarfile: tarfile.TarFile):
        clear = self._config.copy()
        clear['crypto'] = None
        clear['protected'] = False
        clear['slug'] = self.create_slug()
        clear['name'] = "Decrypted " + clear['name']
        bytes = json.dumps(clear, indent=2).encode('utf-8')
        file = BytesIO(bytes)
        self._configMember.size = len(bytes)
        tarfile.addfile(self._configMember, file)


class BackupItem:
    def __init__(self, tarinfo: tarfile.TarInfo, backup: Backup):
        self._info = tarinfo
        self._backup = backup

    @property
    def info(self) -> tarfile.TarInfo:
        return self._info
    
    @property
    def name(self):
        return self.info.name

    @property
    def size(self):
        return self.info.size - 16

    def addTo(self, output: tarfile.TarFile, password: str):
        progress_text = f"  {self.name}"
        overwrite(progress_text)
        source = self._backup._tarfile.extractfile(self.info)
        decrypted = DecryptedStream(source, password=password, expected_size=self.size, progress_text=progress_text)
        new_info = tarfile.TarInfo(name=self.info.name)
        new_info.size = self.size
        output.addfile(new_info, decrypted)
        overwrite(f"  ✅ {self.name} ({size_to_str(self.size)})")
        print()


def main():
    parser = argparse.ArgumentParser(description="Decrypts an encrypted Home Assistant backup file", prog="decrypt_ha_backup")
    parser.add_argument("backup_file", help='The backup file that should be decrypted')
    parser.add_argument("--output_file", "-o", help='The name of decrypted backup file to be created.  If not specified, it will be chosen based on the backup name.')
    parser.add_argument("--password", "-p", "--pass", help="The password for the backup.  If not specified, you will be prompted for it.")
    parser.add_argument("--overwite", action="store_true", default=False, help="Overwite output file without confirmation")
    args = parser.parse_args()

    if not os.path.exists(args.backup_file):
        print_red(f"Backup file {args.backup_file} backup file couldn't be found")
        exit()

    if args.output_file is None:
        parts = list(Path(args.backup_file).parts)
        parts[-1] = "Decrypted " + parts[-1]
        args.output_file = os.path.join(*parts)

    if os.path.exists(args.output_file) and not args.overwite:
        resp = input(f"The output file '{args.output_file}' already exists, do you want to overwrite it [y/n]?")
        if not resp.startswith("y"):
            print_red("Aborted")
            exit(1)

    if args.password is None:
        # ask for password
        print("Please provide the password used to create this backup.  The password is called 'Encryption Key' in the Home Assistant UI.  Providing the wrong password will result in a corrupted decrypted backup.")
        args.password = getpass.getpass("Backup Password:")

    try:
        with tarfile.open(Path(args.backup_file), "r:") as backup_file:
            backup = Backup(backup_file)
            if not backup.encrypted:
                print("This backup file isn't encrypted")
                return
            if backup.version != 2:
                print(f"Only backup format 'Version 2' is supported, this backup is 'Version {backup.version}'")
                return

            print(f"Decrypting {args.backup_file} to {args.output_file}")

            with tarfile.open(args.output_file, "w:") as output:
                for archive in backup.items:
                    archive.addTo(output, args.password)

                # Add the modified backup config
                backup.addModifiedConfig(output)
        
        # Read the output file, anything with a tar.gz extension should be readable as a tarfile.
        print(f"Validating files in {args.output_file}")
        broken = []
        with tarfile.open(args.output_file, "r:") as output:
            for member in readTarMembers(output):
                if member.name.endswith(".tar.gz"):
                    try:
                        overwrite(f"  Checking {member.name}")
                        with tarfile.open(fileobj=output.extractfile(member), mode="r:gz") as embedded:
                            for _ in readTarMembers(embedded):
                                # Do nothing, if its parseable as a tar thats good enough
                                pass
                        overwrite(f"  ✅ {member.name}")
                    except tarfile.ReadError:
                        broken.append(member.name)
                        overwrite(f"  ❌ {member.name}")
                    finally:
                        print()
        if broken:
            print_red(f"{len(broken)} file(s) from the backups couldn't be validated as compressed tar files.  This means that either the provided password was wrong or the original backup is corrupted.")
        else:
            print(f"Created dectypted backup '{args.output_file}'")
    except tarfile.ReadError as e:
        if "not a gzip file" in str(e):
            print_red("The file could not be read as a gzip file.  Please ensure your password is correct and his is a home assistant backup.")
        else:
            raise
    except KeyboardInterrupt:
        print()
        print_red("Cancelled")
        exit(1)
    except FailureError as e:
        print_red(e)
        exit(1)


if __name__ == '__main__':
    if platform.system() == 'Windows':
        from ctypes import windll
        windll.kernel32.SetConsoleMode(windll.kernel32.GetStdHandle(-11), 7)
    main()