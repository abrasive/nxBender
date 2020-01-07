from setuptools import setup

setup(name='nxBender',
      version='0.3.0',
      packages=['nxbender'],
      entry_points={
          'console_scripts': [
              'nxBender = nxbender:main'
          ]
      },
      install_requires=[
          'ConfigArgParse',
          'ipaddress',
          'pyroute2',
          'requests',
          'colorlog',
      ],
     )
