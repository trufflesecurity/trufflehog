from setuptools import setup

setup(
    name='truffleHog',
    version='1.0.0',
    description='Searches through git repositories for high entropy strings, digging deep into commit history.',
    url='https://github.com/dxa4481/truffleHog',
    author='Dylan Ayrey',
    author_email='dxa4481@rit.edu',
    license='GNU',
    packages =['truffleHog'],
    install_requires=[
        'GitPython == 2.1.1'
    ],
    entry_points = {
      'console_scripts': ['trufflehog = truffleHog.truffleHog:main'],
    },
)
