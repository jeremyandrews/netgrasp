#!/usr/bin/env python2

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name="NetGrasp",
      version="0.9.0",
      author="Jeremy Andrews",
      author_email="jeremy@tag1consulting.com",
      maintainer="Jeremy Andrews",
      maintainer_email="jeremy@tag1consulting.com",
      url="https://github.com/jeremyandrews/netgrasp",
      packages=["netgrasp", "netgrasp.config", "netgrasp.database", "netgrasp.notify", "netgrasp.test", "netgrasp.update", "netgrasp.utils"],
      license="2-clause BSD",
      description="A passive network scanner",
      long_description=open("README.txt").read(),
      scripts=["bin/netgrasp"],
      download_url = "https://github.com/jeremyandrews/netgrasp/archive/v0.9.0-beta.tar.gz",
      include_package_data=True,
      install_requires=["pypcap>=1.1.6", "dpkt>=1.8.0", "daemonize>=2.4.7"],
      # @TODO Require sqlite3 if not on FreeBSD
      extras_require = {
          "email": ["pyzmail"],
          "notification": ["notify"],
      },
     )
