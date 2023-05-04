import click
import glob
import json
import pandas as pd
import requests

from concurrent.futures import ThreadPoolExecutor, as_completed


def query_osv(package_name, package_version):
	osv_api_url = 'https://api.osv.dev/v1/query'
	osv_request_obj = {'package': {'name': package_name}, 'version': package_version}
	try:
		r = requests.post(osv_api_url, json=osv_request_obj, timeout=10)
		if r.status_code == 200:
			return True, package_name, package_version, r.json()
		else:
			return False, package_name, package_version, {}
	except:
		return False, package_name, package_version, {}

def parse_osv_response(json_response):
	vulns = {}
	for vuln in json_response['vulns']:
		if vuln['id'] not in vulns and 'GHSA' in vuln['id']: vulns[vuln['id']] = ''
	return dict.fromkeys(vulns.keys(),'')

def build_advisory_index(base_path):
	advisories = glob.glob('{}/**/*.json'.format(base_path), recursive=True)
	advisory_index = {}

	for advisory in advisories:
	    advisory_id = advisory.split('/')[-1].split('.')[0]
	    advisory_index[advisory_id] = advisory

	return advisory_index

@click.command()
@click.option('--input', required=True, help='SPDX file to analyze')
@click.option('--output', required=True, help='output CSV filename')
@click.option('--advisory-index-dir', required=True, help='directory path for the github issue advisory repo (full or relative)')
def analyze_sbom(input, output, advisory_index_dir):
	f = open(input, 'r')
	blob = json.load(f)

	print('detected {} packages'.format(len(blob['packages'][1:])))

	threads = 50
	task_results = []
	print('querying OSV for vulnerable packages with {} threads...'.format(threads))
	with ThreadPoolExecutor(max_workers=threads) as executor:
		for p in blob['packages'][1:]:
			ecosystem = p['name'].split(':')[0]
			package_name = p['name'].split(':')[1]
			package_version = p['versionInfo']
			
			task_results.append(executor.submit(query_osv, package_name, package_version))

	package_lookups = 0
	lookup_failures = 0
	vulnerable_pkgs = 0
	failed_lookups = []
	vulnerable_packages = []

	for task in as_completed(task_results):
		success, package_name, package_version, json_response = task.result()
		
		if success:
			package_lookups += 1
			if bool(json_response):
				vulnerable_pkgs += 1
				vulnerable_packages.append({'package_name': package_name, 
											'package_version': package_version, 
											'json_response': json_response})
		else:
			failed_lookups.append({'package_name': package_name,'package_version': package_version})
			lookup_failures += 1

	print('completed query of OSV')
	print('note, a package is a unique package name + version.')
	print('there may be multiple vulnerabilities per package.')
	print('further details will be in the csv output.')
	print(' - package lookups: {}'.format(package_lookups))
	print(' - lookup failures: {}'.format(lookup_failures))
	print(' - vulnerable pkgs: {}'.format(vulnerable_pkgs))

	print('building advisory index...')
	advisory_index = build_advisory_index(advisory_index_dir)

	print('parsing and extracting vulnerable dependency data...')
	vulnerable_packages_details = []
	

	for package in vulnerable_packages:
		missing_vulns = []
		vpd = {}
		vpd['package_name']    = package['package_name']
		vpd['package_version'] = package['package_version']
		vpd['vulnerabilities'] = parse_osv_response(package['json_response'])
		if vpd['vulnerabilities']:
			for vuln in vpd['vulnerabilities'].keys():
				if vuln in advisory_index:
					f = open(advisory_index[vuln],'r')
					vpd['vulnerabilities'][vuln] = json.load(f)
					f.close()
				else:
					missing_vulns.append(vuln)
					print('vuln ({}) not found in advisory index! that probably means you need to refresh the advisory repo'.format(vuln))
		for vuln in missing_vulns:
			del vpd['vulnerabilities'][vuln]

		vulnerable_packages_details.append(vpd)

	print('building csv output...')
	columns = ['package_name','package_version','vulnerability_id','vulnerability_link','vulnerability_severity','vulnerability_summary','vulnerability_details']
	ghsa_base_url = 'https://github.com/advisories?query={}'

	df = pd.DataFrame(columns=columns)

	for package in vulnerable_packages_details:
		for vuln in package['vulnerabilities'].keys():
			vuln_id = package['vulnerabilities'][vuln]['id']
			temp = package['vulnerabilities'][vuln]['database_specific']['severity']
			vuln_severity = temp if temp != 'MODERATE' else 'MEDIUM'
			df.loc[len(df.index)] = [package['package_name'], 
									 package['package_version'],
									 vuln_id,
									 ghsa_base_url.format(vuln_id),
									 vuln_severity,
									 package['vulnerabilities'][vuln]['summary'],
									 package['vulnerabilities'][vuln]['details'], ]

	print('writing CSV output file...')
	df.to_csv(output)
	print('analysis complete.')

if __name__ == '__main__':
	analyze_sbom()
