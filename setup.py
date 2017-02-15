from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

requirements = [
'pandas>=0.17.1',
'scikit-learn>=0.18.1',
'scipy>=0.17.0',
'oletools>=0.50'
]

setup(
    name='mmbot',
    version='1.0.5',
    description='Malicious Macro Bot: Python module to classify and cluster Microsoft office documents.  Uses machine learning techniques to determine if VBA code is malicious or benign and groups similar documents together.',
    url='https://github.com/egaus/mmbot',
    author='Evan Gaustad',
    author_email='evan.gaustad@gmail.com',
    license='MIT',
    packages=find_packages(exclude=('tests')),
    scripts=['cli/mmbot'],
    install_requires=requirements,
    keywords='mmbot malicious macro bot office document security cyber malware',
    #include_package_data=True,
    package_data={'mmbot' : ['model/modeldata.pickle', 'model/vocab.txt']},
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
    ],
)
# 'Programming Language :: Python :: 3.5', # package dependency unfortunately broke with python 3.5

