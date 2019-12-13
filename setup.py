from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="truffleHog",
    version="3.0.0",
    description="Searches through git repositories for high entropy strings, digging deep into commit history.",
    url="https://github.com/sortigoza/truffleHog",
    author="Dylan Ayrey",
    author_email="dxa4481@rit.edu",
    license="GNU",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={"console_scripts": ["trufflehog = truffleHog.interface:main"]},
)
