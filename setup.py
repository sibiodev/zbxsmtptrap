import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="smtpToZbxTrap",
    version="0.0.1",
    author="Raynald de Lahondes",
    author_email="lahondes@sibio.fr",
    description="A system to create Zabbix events with emails",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sibiodev/zbxsmtptrap",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=2.7',
)