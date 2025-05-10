from setuptools import setup, find_packages

setup(
    name="duo_flask_auth",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Flask>=2.0.0",
        "Flask-Login>=0.5.0",
        "duo-universal>=1.0.0",
        "pymongo>=4.0.0",
        "certifi>=2021.10.8",
        "Werkzeug>=2.0.0",
    ],
    author="Aaron Davis",
    author_email="aarodavi@cisco.com",
    description="Flask authentication library with Duo MFA support",
    keywords="flask, authentication, duo, mfa",
    url="https://github.com/yourusername/duo-flask-auth",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
)