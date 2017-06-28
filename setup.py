#from distutils.core import setup
from setuptools import setup
from setuptools import Command
from tests.saltlib import test_saltlib

class BenchSaltLibCmd(Command):
    """ Run my command.
    """
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
    packages=['saltchannel', 'saltchannel/saltlib'],
    #python_requires='>=3.4',
    #package_dir={'': 'saltchannel'},
    url='https://github.com/assaabloy-ppi/salt-channel-python',
    license='MIT',
    author='Alexander Reshniuk',
    author_email='alex.reshniuk@gmail.com',
    description='Python 3 implementation of Salt Channel v2.',
    cmdclass={
        'benchmark_saltlib': BenchSaltLibCmd,
    },
 #   install_requires=[
 #       'pynacl',
 #       'python_tweetnacl'
 #   ],
 #   dependency_links=[
 #       'https://github.com/warner/python-tweetnacl.git#egg=python_tweetnacl'
 #   ]
)
