from setuptools import setup

setup(
    entry_points = {
        'console_scripts': ['specter=specter.specter:main'],
    }
)
