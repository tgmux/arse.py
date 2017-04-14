#! /usr/bin/python
import arsedefs
import boto3
import json
import re
import sys

		
def main():
	# Let's be sure we get a command line option
	cli_option = ''
	if len(sys.argv) < 2:
		arsedefs.printHelp()
	else:
		cli_option = sys.argv[1]

		# Load JSON config file
		try:
			with open('arse.conf.json') as arse_config_json:
				arse_config = json.load(arse_config_json)
		except Exception as e:
			sys.exit("Unable to open json config file: " + str(e))

		#
		# Loop through aws accounts - specify something on the cli later
		short_resources = []
		long_resources = []

		sys.stdout.write("* Searching AWS Accounts: ")
		sys.stdout.flush()
		for aws_account in arse_config['configurations']:
			aws_account_name = aws_account['account']
			sys.stdout.write(aws_account_name + ' ')
			sys.stdout.flush()

			# Create session based on account name
			session = boto3.session.Session(profile_name=aws_account_name)

			# Loop through regions - specify something on the cli later
			aws_regions = aws_account['regions']
			for aws_region in aws_regions:
				# elastic IP addresses
				if cli_option == "eips":
					try:
						eips = arsedefs.getEc2EIps(aws_account_name, aws_region, session)
					except Exception as e:
						sys.exit("get EIPs query failure: " + str(e[0]))

					short_resources.append(eips)
				# elastic load balancers	
				elif cli_option == "elbs":
					try:
						elbs = arsedefs.getEc2Elbs(aws_account_name, aws_region, session, '')
					except Exception as e:
						sys.exit("getElbs query failure: " + str(e[0]))

					short_resources.append(elbs)
				# individual load balancers
				elif re.search('^elb\-', cli_option):
					try:
						groups = arsedefs.getEc2Elbs(aws_account_name, aws_region, session, cli_option[4:])
					except Exception as e:
						sys.exit("getElbs query failure: " + str(e[0]))

					long_resources.append(groups)
				# AMIs
				elif cli_option == "images":
					try:
						images = arsedefs.getEc2Images(aws_account_name, aws_region, session)
					except Exception as e:
						sys.exit("getImages query failure: " + str(e[0]))

					short_resources.append(images)
				# instances	
				elif cli_option == "instances":
					try:
						instances = arsedefs.getEc2Instances(aws_account_name, aws_region, session, '')
					except Exception as e:
						sys.exit("getInstances query failure: " + str(e[0]))

					short_resources.append(instances)
				# ssh keys
				elif cli_option == "keys":
					try:
						keys = arsedefs.getEc2KeyPairs(aws_account_name, aws_region, session)
					except Exception as e:
						sys.exit("getKeyPairs query failure: " + str(e[0]))

					short_resources.append(keys)
				# security groups
				elif cli_option == "security":
					try:
						groups = arsedefs.getEc2SecurityGroups(aws_account_name, aws_region, session, '')
					except Exception as e:
						sys.exit("getSecurityGroups query failure: " + str(e[0]))

					short_resources.append(groups)
				# individual security groups
				elif re.search('^sg\-', cli_option):
					try:
						groups = arsedefs.getEc2SecurityGroups(aws_account_name, aws_region, session, cli_option)
					except Exception as e:
						sys.exit("getSecurityGroups query failure: " + str(e[0]))

					long_resources.append(groups)
				# iam users
				elif cli_option == "users":
					try:
						users = arsedefs.getIamUsers(aws_account_name, session)
					except Exception as e:
						sys.exit("getIamUsers query failure: " + str(e[0]))

					short_resources.append(users)
				# ebs volumes
				elif cli_option == "volumes":
				 	try:
				 		volumes = arsedefs.getEc2Volumes(aws_account_name, aws_region, session, '')
				 	except Exception as e:
						sys.exit("getVolumes query failure: " + str(e[0]))

					short_resources.append(volumes)

		# Get ready to display our data
		print "\n"
		line_counter = 1
		arbitrary_pagination_max = 80

		# Handle what we get back. 
		# If it's a bunch of stuff, print a header then the rest line by line
		if len(short_resources) > 0:
			arsedefs.printHeader(cli_option)

			for resource_array in short_resources:
				for resource in resource_array:
					# Arbitrary paginator at 40 lines
					if line_counter % arbitrary_pagination_max == 0:
						arsedefs.printHeader(cli_option)

					resource.printShort()
					line_counter += 1

			print "\n -- " + str(line_counter) + " results found."


		# If it's just one thing, hey print that too. Probably don't need to loop, but just in case i need to alter later. 
		if len(long_resources) > 0:
			for resource_array in long_resources:
				for resource in resource_array:
					resource.printLong()

#
if __name__ == '__main__':
	main()