from setuptools import setup, find_packages

setup(
    name="semillero_seguridadssl",
    version="0.1",
    packages=find_packages(
        exclude=[
            ".click_hs",
            "*.tests",
            "*.tests.*",
            "tests.*",
            "tests",
            "htmlscov",
        ]
    ),

    # Project uses these requirements, so ensure that they get installed or upgraded
    install_requires=[
        'click>=6.7',
        'click-shell>=1.0',
        'openvas-lib>=1.1.3',
        'pymetasploit>=1.1',
        'python-nmap>=0.6.1',
        'pyvas>=0.4.0',
        # 'mock>=2.0.0',
    ],

    entry_points={
        'console_scripts': [
            'semillero_seguridadssl = semillero_seguridadssl.main:main'
        ]
    },
)
