#!/bin/sh

pip install -q --upgrade setupext-janitor twine build
python3 setup.py clean
python3 -m build
keyring --disable
python3 -m twine upload dist/*