from setuptools import setup, find_packages

setup(
    name="xss-detector",
    version="1.0.0",
    description="AI-powered XSS Vulnerability Scanner",
    long_description="An enterprise-grade XSS detection tool combining traditional scanning with machine learning for comprehensive web application security testing.",
    author="Security Research Team",
    packages=find_packages(),
    install_requires=[
        'tensorflow>=2.6.0',
        'gensim>=4.0.0',
        'requests>=2.26.0',
        'beautifulsoup4>=4.10.0',
        'numpy>=1.21.0'
    ],
    entry_points={
        'console_scripts': [
            'xss-detector=xss_detector.cli:main'
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
    include_package_data=True,
    package_data={
        'xss_detector': ['models/*', 'payloads.txt']
    }
)
