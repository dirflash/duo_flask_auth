from setuptools import setup, find_packages

setup(
    name="duo_flask_auth",
    version="0.2.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Flask>=2.0.0",
        "Flask-Login>=0.5.0",
        "Flask-WTF>=1.0.0",   # Added for CSRF protection
        "duo-universal>=1.0.0",
        "pymongo>=4.0.0",
        "certifi>=2021.10.8",
        "Werkzeug>=2.0.0",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="Flask authentication library with Duo MFA support and enhanced security features",
    keywords="flask, authentication, duo, mfa, security",
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
        "Topic :: Security",  # Added security topic
    ],
    python_requires=">=3.7",
    package_data={
        "duo_flask_auth": ["templates/*.html"],
    },
)