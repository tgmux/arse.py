#! /usr/bin/python
import arsedefs
import boto3
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
		shortResources = []
		longResources = []

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
				# elastic IP addresses
				if clOption == "eips":
					try:
						eips = arsedefs.getEc2EIps(awsAccountName, awsRegion, session)
					except Exception as e:
						sys.exit("get EIPs query failure: " + str(e[0]))

					shortResources.append(eips)
				# elastic load balancers	
				elif clOption == "elbs":
					try:
						elbs = arsedefs.getEc2Elbs(awsAccountName, awsRegion, session, '')
					except Exception as e:
						sys.exit("getElbs query failure: " + str(e[0]))

					shortResources.append(elbs)
				# individual load balancers
				elif re.search('^elb\-', clOption):
					try:
						groups = arsedefs.getEc2Elbs(awsAccountName, awsRegion, session, clOption[4:])
					except Exception as e:
						sys.exit("getElbs query failure: " + str(e[0]))

					longResources.append(groups)
				# AMIs
				elif clOption == "images":
					try:
						images = arsedefs.getEc2Images(awsAccountName, awsRegion, session)
					except Exception as e:
						sys.exit("getImages query failure: " + str(e[0]))

					shortResources.append(images)
				# instances	
				elif clOption == "instances":
					try:
						instances = arsedefs.getEc2Instances(awsAccountName, awsRegion, session, '')
					except Exception as e:
						sys.exit("getInstances query failure: " + str(e[0]))

					shortResources.append(instances)
				# ssh keys
				elif clOption == "keys":
					try:
						keys = arsedefs.getEc2KeyPairs(awsAccountName, awsRegion, session)
					except Exception as e:
						sys.exit("getKeyPairs query failure: " + str(e[0]))

					shortResources.append(keys)
				# security groups
				elif clOption == "security":
					try:
						groups = arsedefs.getEc2SecurityGroups(awsAccountName, awsRegion, session, '')
					except Exception as e:
						sys.exit("getSecurityGroups query failure: " + str(e[0]))

					shortResources.append(groups)
				# individual security groups
				elif re.search('^sg\-', clOption):
					try:
						groups = arsedefs.getEc2SecurityGroups(awsAccountName, awsRegion, session, clOption)
					except Exception as e:
						sys.exit("getSecurityGroups query failure: " + str(e[0]))

					longResources.append(groups)
				# iam users
				elif clOption == "users":
					try:
						users = arsedefs.getIamUsers(awsAccountName, session)
					except Exception as e:
						sys.exit("getIamUsers query failure: " + str(e[0]))

					shortResources.append(users)
				# ebs volumes
				elif clOption == "volumes":
				 	try:
				 		volumes = arsedefs.getEc2Volumes(awsAccountName, awsRegion, session, '')
				 	except Exception as e:
						sys.exit("getVolumes query failure: " + str(e[0]))

					shortResources.append(volumes)
		# Handle what we get back. 
		# If it's a bunch of stuff, print a header then the rest line by line
		print "\n"
		if len(shortResources) > 0:
			arsedefs.printHeader(clOption)
		
			for resourceArray in shortResources:
				for resource in resourceArray:
					resource.printShort()

		# If it's just one thing, hey print that too. Probably don't need to loop, but just in case i need to alter later. 
		if len(longResources) > 0:
			for resourceArray in longResources:
				for resource in resourceArray:
					resource.printLong()

	print ""
#
if __name__ == '__main__':
	main()