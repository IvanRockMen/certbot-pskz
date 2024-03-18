from setuptools import setup
from setuptools import find_packages

from certbot_pskz import __version__

install_requires = [
    'acme>=2.9.0',
    'certbot>=2.9.0',
    'requests>=2.31.0',
    'mock',
    'setuptools',
    'zope.interface',
    'build',
]

data_files = [
    ('/etc/letsencrypt', ['pskz.ini'])
]

with open('README.md') as f:
    long_description = f.read()

setup(
    name="certbot-pskz",
    version=__version__,
    description="Ps.kz DNS authenticator plugin for Certbot",
    long_description=long_description,
    url="https://github.com/IvanRockMen/cerbot-pskz/",
    author="Ivan Bartenev",
    author_email="bartenev.ivan.a@gmail.com",
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires='>=3.8',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    install_requires=install_requires,
    data_files=data_files,
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "certbot.plugins": [
            "pskz_dns = certbot_pskz.dns:Authenticator",
        ],
    },
    test_suite="certbot_pskz"
)
