from setuptools import setup, find_packages

setup(
    name='truffleHog',
    version='2.1.13',
    description='Searches through git repositories for high entropy strings, digging deep into commit history.',
    url='https://github.com/dxa4481/truffleHog',
    author='Dylan Ayrey',
    author_email='dxa4481@rit.edu',
    license='GNU',
    packages = ['truffleHog'],
    install_requires=[
        'GitPython == 3.0.6',
        'truffleHogRegexes == 0.0.7'
    ],
    entry_points = {
      'console_scripts': ['trufflehog = truffleHog.truffleHog:main'],
    },
)
