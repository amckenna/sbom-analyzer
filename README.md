# SBOM Analyzer

This is simple python tool for analyzing an SBOM for vulnerable dependencies.

Currently, SBOM Analyzer targets an SPDX formatted SBOM file, like the one from GitHub's dependency graph "Export SBOM" feature. SBOM Analyzer will enumerate the dependencies, use the Open Source Vulnerabilities Database API (https://google.github.io/osv.dev/) to determine if a dependency contains one or more vulnerabilities. If a vulnerability is found, information on that vulnerability will be gathered from the GitHub Advisory Database (https://github.com/github/advisory-database).

Note, for this tool to work, you must clone the GitHub Advisory Database repository, which contains a directory structure of JSON files, each containing information on a GitHub Advisory. Using this datasource reduces further dependencies on APIs and removes the need for any API access tokens or accounts for this tool to work. Warning - the GitHub Advisory Database repository is around 2.5 Gb.

Analysis output is a CSV file. The dependencies in most (all?) SBOMs do not specify the dependency's location within the codebase so the analysis will not contain file paths to where the dependencies are used. 

To install:
```bash
git clone https://github.com/github/advisory-database.git
git clone https://github.com/amckenna/sbom-analyzer.git
cd sbom-analyzer
pip install -r requirements.txt
```

If your pip and python are out of sync you may need to run: `python3 -m pip install -r requirements.txt`

To use:
- before each use, be sure to run `git pull` in your local advisory-database repo/directory.

```bash
$ python3 sbom-analyzer.py --help
Usage: sbom-analyzer.py [OPTIONS]

Options:
  --input TEXT   SPDX file to analyze  [required]
  --output TEXT  output CSV filename  [required]
  --index TEXT   full path to the github issue advisory repo  [required]
  -v, --verbose  verbose output
  --help         Show this message and exit.
```
Example:

```bash
python3 sbom-analyzer.py \
	--index '/repos/advisory-database' \
	--input teleport_gravitational.json \
	--output teleport_gravitational_results.csv \
```