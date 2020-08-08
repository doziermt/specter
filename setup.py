import setuptools

from specter import __version__

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(name='specter',
                 version=__version__,
                 license='MIT',
                 author='Mike Dozier',
                 author_email='doziermt@gmail.com',
                 description='Specter KALI Linux scanning tool',
                 long_description=long_description,
                 long_description_content_type='text/markdown',
                 url='https://github.com/doziermt/specter',
                 keywords=['Linux', 'Security', 'Python'],
                 packages=setuptools.find_packages(),
                 include_package_data=True,
                 classifiers=[
                     'Development Status :: 3 - Alpha',
                     'Intended Audience :: Developers',
                     'License :: OSI Approved :: MIT License',
                     'Operating System :: POSIX :: Linux',
                     'Programming Language :: Python :: 3',
                     'Programming Language :: Python :: 3.5',
                     'Programming Language :: Python :: 3.6',
                     'Programming Language :: Python :: 3.7',
                     'Programming Language :: Python :: 3.8'
                 ],
                 python_requires='>=3.5',
                 entry_points={
                     'console_scripts': ['specter=specter.specter:main'],
                 })
