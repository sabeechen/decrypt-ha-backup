from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='decrypt-ha-backup',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
    ],
    packages=find_packages(),
    version='2023.10.28.1',
    description='Decryption utility for Home Assistant backups',
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=["cryptography"],
    author="Stephen Beechen",
    author_email="stephen@beechens.com",
    python_requires=">=3.9",
)