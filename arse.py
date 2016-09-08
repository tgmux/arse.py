#! /usr/bin/python
import arsedefs
import boto3
import collections
from colorama import Fore, Back, Style, init
import json
import re
import sys

		
def main():
	# Let's be sure we get a command line option
	clOption = ''
	if len(sys.argv) < 2:
		arsedefs.printHelp()
	else:
		clOption = sys.argv[1]

		# Load JSON config file
		try:
			with open('arse.conf.json') as arseConfigJson:
				arseConfig = json.load(arseConfigJson)
		except Exception as e:
			sys.exit("Unable to open json config file: " + str(e))

		#
		# Loop through aws accounts - specify something on the cli later
		resources = []
		sys.stdout.write("* Searching AWS Accounts: ")
		sys.stdout.flush()
		for awsAccount in arseConfig['configurations']:
			awsAccountName = awsAccount['account']
			sys.stdout.write(awsAccountName + ' ')
			sys.stdout.flush()

			# Create session based on account name
			session = boto3.session.Session(profile_name=awsAccountName)

			# Loop through regions - specify something on the cli later
			awsRegions = awsAccount['regions']
			for awsRegion in awsRegions:
				# elastic load balancers	
				if clOption == "elbs":
					try:
						elbs = arsedefs.getEc2Elbs(awsAccountName, awsRegion, session, '')
					except Exception as e:
						sys.exit("getElbs query failure: " + str(e[0]))

					resources.append(elbs)
				# AMIs
				elif clOption == "images":
					try:
						images = arsedefs.getEc2Images(awsAccountName, awsRegion, session)
					except Exception as e:
						sys.exit("getImages query failure: " + str(e[0]))

					resources.append(images)
				# instances	
				elif clOption == "instances":
					try:
						instances = arsedefs.getEc2Instances(awsAccountName, awsRegion, session, '')
					except Exception as e:
						sys.exit("getInstances query failure: " + str(e[0]))

					resources.append(instances)
				# ssh keys
				elif clOption == "keys":
					try:
						keys = arsedefs.getEc2KeyPairs(awsAccountName, awsRegion, session)
					except Exception as e:
						sys.exit("getKeyPairs query failure: " + str(e[0]))

					resources.append(keys)
				# ssh keys
				elif clOption == "security":
					try:
						groups = arsedefs.getEc2SecurityGroups(awsAccountName, awsRegion, session, '')
					except Exception as e:
						sys.exit("getSecurityGroups query failure: " + str(e[0]))

					resources.append(groups)
				# ebs volumes
				elif clOption == "volumes":
				 	try:
				 		volumes = arsedefs.getEc2Volumes(awsAccountName, awsRegion, session, '')
				 	except Exception as e:
						sys.exit("getVolumes query failure: " + str(e[0]))

					resources.append(volumes)
		#
		# Display the data we've received
		print ""
		arsedefs.printHeader(clOption)
		
		for resourceArray in resources:
			for resource in resourceArray:
				resource.printShort()

	print ""
#
if __name__ == '__main__':
	main()