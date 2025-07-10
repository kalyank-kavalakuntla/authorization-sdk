from setuptools import setup, find_packages

setup(
    name="multitenancy-sdk",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "python-jose>=3.3.0",
        "functools32>=3.2.3;python_version<'3.0'",
    ],
    author="Covasant",
    author_email="support@covasant.com",
    description="Python SDK for Multitenancy Authorization Service",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/covasant/multitenancy-sdk",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
