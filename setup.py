 
from distutils.core import setup

setup(name = "fwp",
    version = "1.0",
    description = "FireWall Sinthesizer: Language-independent Synthesis of Firewall Policies",
    packages = ['fwsynthesizer', 'fwsynthesizer.parsers', 'fwsynthesizer.frontends', 'fwsynthesizer.expressivity'],
    package_data = {'fwsynthesizer' : ["diagrams/*"] },
    scripts = ["fwp"],
) 
