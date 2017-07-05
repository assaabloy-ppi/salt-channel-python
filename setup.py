from setuptools import setup, find_packages
from setuptools import Command
from tests.saltlib import test_saltlib

class BenchSaltLibCmd(Command):

    description = 'Estimate saltlib performance with different crypto APIs'
    user_options = [
    ]

    def initialize_options(self):
        self.suite = test_saltlib.BenchSaltLib()
        pass

    def finalize_options(self):
        pass

    def run(self):
        print("Benchmarking....\n")
        self.suite.run_bench_suite()

setup(
    name='salt-channel-python',
    version='0.0.1',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    #python_requires='>=3.4',
    #package_dir={'': 'saltchannel'},
    url='https://github.com/assaabloy-ppi/salt-channel-python',
    license='MIT',
    author='Alexander Reshniuk',
    author_email='alex.reshniuk@gmail.com',
    description='Python 3 implementation of Salt Channel v2.',
    classifiers=[
            # How mature is this project? Common values are
            #   3 - Alpha
            #   4 - Beta
            #   5 - Production/Stable
            'Development Status :: 3 - Alpha',

            # Indicate who your project is intended for
            'Intended Audience :: Developers',
            'Topic :: Software Development :: Build Tools',

            # Pick your license as you wish (should match "license" above)
            'License :: OSI Approved :: MIT License',

            # Specify the Python versions you support here. In particular, ensure
            # that you indicate whether you support Python 2, Python 3 or both.
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
    ],
    # What does your project relate to?
    #keywords='sample setuptools development',
    cmdclass={
        'benchmark_saltlib': BenchSaltLibCmd,
    },
    install_requires=[
        'pynacl',
        'tweetnacl'
    ],
    dependency_links=[
        'git+https://github.com/ppmag/python-tweetnacl.git#egg=tweetnacl'
    ]
)
