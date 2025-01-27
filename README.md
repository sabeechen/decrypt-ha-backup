## What is this?
This is a command-line python module that allows you to turn an encrypted Home Assistant backup (aka "Password Protected") into a non-encrypted backup.  You might find this useful in situations such as:
- Your backup has been corrupted and you're just trying to get what you can out of it.
- You're trying to get just one or two files out of a backup without having to restore the whole thing.

Home Assistant backups are just compressed tar files but to encrypt them with a password it uses a non-standard encryption scheme.  To the author's knowledge there is no way to decrypt these with standard compression/decompression tools which is why he wrote this little utility.

## A note on reliability and expectations
This tool isn't sanctioned by the developers of Home Assistant and isn't updated in response to changes Home Assistant makes to the format of its backup files.  This tool hacks apart a backup and then builds it back up, which makes it very sensitive to any changes the Home Assistant developers make to the backup file format.  

It has been tested on backups created by Home Assistant version 2025.01.X. If you encounter an error using this tool please consider creating an issue for it on GitHub to notify the maintainer, you'll probably be helping many other users if you bring attention to an issue.

## Installation
Make sure you have python 3.10 (or higher) and pip installed on your system.  Search around on Google for how to install them on your operating system.  Then from the command line: 
```bash
pip install decrypt-ha-backup
```

## Usage
Download your backup from Home Assistant.  Ensure you ahve at least twice the size of your backup available on your hard drive, and run:
```bash
python3 -m decrypt-ha-backup /path/to/your/backup.tar
```

You will be asked for the backup's password, after being processed the decrypted backup will be placed at ```/path/to/your/Decrypted backup.tar```.

### Optional Arguments
- <kbd>--password secret_password</kbd> Specify the the password instead of being asked
- <kbd>--output_filename /path/to/output.tar</kbd> Specify the output decrypted backup file name 
