# PhantomRavenDetect

[![python](https://img.shields.io/badge/Python-3.9-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

PhantomRaven is the latest attempt to poison software infrastructure and infiltrate organizations via supply chain attack, in particular via NPM packages. Software extensions and packages are considered to be the weak links in software inventory. They can all be very hard to discover when spread across filesystems and projects without tools that are part of your pipeline. The best way to fight this is to use an Software Bill of Materials (SBOM) in your projects. An SBOM is a nested inventory of ingredients—components, libraries, and modules—that make up software, acting as a crucial document for software supply chain transparency. Used primarily for security risk management, SBOMs help identify, track, and patch vulnerabilities in proprietary and open-source software, ensuring compliance and reducing security risks.

This project is a Python script to detect whether the packages listed at [https://www.endorlabs.com/learn/return-of-phantomraven](https://www.endorlabs.com/learn/return-of-phantomraven) are present on your system, 

✅ The script checks for global packages as well as those in the current project directory. It also checks for packages installed using bun and Homebrew. 

🔄 Planned is the use of SBOM formats like CycloneDX and SPDX for listing files to be scanned.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

This project is possible thanks to the hard work of Endor Labs.

---

**Note**: This project is vibe coded using Claude.
