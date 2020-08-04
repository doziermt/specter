from setuptools import setup

setup(
    name = 'specter',
    packages = ['specter'],
    version = '0.1',
    license='MIT',
    description = 'Specter Linux Kali scanning tool',
    author = 'Mike Dozier',
    author_email = 'doziermt@gmail.com',
    url = 'https://github.com/doziermt/specter',
    keywords = ['Linux', 'Security', 'Python'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],
    entry_points = {
        'console_scripts': ['specter=specter.specter:main'],
    }
)
