import pathlib

from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
    name="masky",
    version="0.2.0",
    description="Python library with CLI allowing to remotely dump domain user credentials via an ADCS",
    long_description=README,
    long_description_content_type="text/markdown",
    license="MIT",
    author="Zak",
    python_requires=">=3.6",
    packages=find_packages(exclude=["assets"]),
    install_requires=[
        "colorama",
        "impacket",
        "cryptography>=3.5",
        "pyasn1",
        "asn1crypto",
    ],
    entry_points={
        "console_scripts": [
            "masky = masky.ui.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
