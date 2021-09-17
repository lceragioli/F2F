 
from distutils.core import setup

setup(name = "f2fcont",
    version = "1.0",
    description = "Firewall-2-Firewall: Check portability between firewall systems",
    packages = ['fwsynthesizer', 'fwsynthesizer.parsers', 'fwsynthesizer.frontends', 'fwsynthesizer.expressivity'],
    package_data = {'fwsynthesizer' : ["diagrams/*"] },
    scripts = ["f2fcont"],
) 
