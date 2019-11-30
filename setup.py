import re
import ast
from setuptools import setup, find_packages

_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('al_aws_access_analyzer_collector/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

setup(
    name='al_aws_access_analyzer_collector',
    version=version,
    url='https://github.com/alertlogic/al-aws-access-analyzer-collector',
    license='MIT',
    author='Alert Logic Inc.',
    author_email='support@alertlogic.com',
    description='The Alert Logic ActiveWatch Integration with AWS IAM Access Analyzer.',
    scripts=[],
    packages=find_packages(exclude=['contrib', 'docs', 'tests*', 'troubleshooting']),
    include_package_data=True,
    zip_safe=True,
    platforms='any',
    python_requires='>=3.7',
    lambda_function='al_aws_access_analyzer_collector.collector:handler',
    lambda_module='al_aws_access_analyzer_collector',
    setup_requires=[
        'lambda_setuptools'
    ],
    install_requires=[
        'activewatch>=1.0.2'
    ],
    extras_require={
        'dev': [
            'pytest>=3',
            'mock>=2.0.0',
            'httpretty>=0.8.14',
            'pycodestyle>=2.3.1'
        ],
    },
    keywords=['activewatch', 'alertlogic', 'aws', 'aws_access_analyzer', 'al_aws_access_analyzer_collector']
)
