from setuptools import setup, find_packages

setup(
    name='peekapp',
    version='0.1',
    py_modules='peekapp.py',
    packages=find_packages(),
    install_requires=[
        'Click',
        'Scapy'
    ],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'peekapp = peekapp:run'
        ]
    },
)
