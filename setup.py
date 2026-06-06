from setuptools import setup

setup(
    name="kezmo",
    version="1.0.0",
    description="Forensic / Steganography / CTF Analysis Toolkit for Kali Linux",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="SAIF",
    url="https://github.com/seko2077/KEZMO",
    license="MIT",
    py_modules=["kezmo"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "kezmo=kezmo:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: Utilities",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
    ],
    keywords="forensics steganography ctf kali linux security dfir",
)
