from setuptools import setup, find_packages

__version__ = '0.1.0'


setup(
    name='trufflehog',
    version=__version__,
    description='Used to look for secrets in source code ',
    url='https://www.github.com/lyft/trufflehog',
    maintainer='Lyft',
    maintainer_email='dev@lyft.com',
    packages=find_packages(exclude=['tests*']),
    dependency_links=[],
    install_requires=[
        'GitPython>= 2.0, <3.0',
        'truffleHogRegexes<=1.0'
        # Packages in here should rarely be pinned. This is because these
        # packages (at the specified version) are required for project
        # consuming this library. By pinning to a specific version you are the
        # number of projects that can consume this or forcing them to
        # upgrade/downgrade any dependencies pinned here in their project.
        #
        # Generally packages listed here are pinned to a major version range.
        #
        # e.g.
        # Python FooBar package for foobaring
        # pyfoobar>=1.0, <2.0
        #
        # This will allow for any consuming projects to use this library as
        # long as they have a version of pyfoobar equal to or greater than 1.x
        # and less than 2.x installed.
    ],
    extras_require={
        ':python_version=="2.7"': ['typing>=3.6'],  # allow typehinting PY2
    },
)
