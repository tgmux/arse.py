#! /usr/bin/python
import arsedefs
import boto3
import collections
from colorama import Fore, Back, Style, init
import json
import re
import sys

#
# Display all EC2 AMIs
def getEc2Images(ec2):
	try:
		diskImages = ec2.describe_images(Owners=['self'])
	except Exception as e:
		sys.exit("Images query failure: " + str(e[0]))

	images = []
	for ami in diskImages['Images']:
		image = arsedefs.Ec2Image()
		image.imageId = ami['ImageId']
		image.name = ami['Name']
		image.virtualizationType = ami['VirtualizationType']
		image.created = ami['CreationDate']
		images.append(image)

	return images
#
# Request EC2 security groups from AWS API
def getEc2SecurityGroups(ec2, securityGroupId):
	try:
		if securityGroupId == "all":
			securityGroups = ec2.describe_security_groups()
		else:
			securityGroups = ec2.describe_security_groups(GroupIds=[securityGroupId])
	except Exception as e:
		sys.exit("Security groups query failure: " + str(e[0]))

	# Array of returned EC2 security group objects
	groups = []
	for group in securityGroups['SecurityGroups']:
		securityGroup = arsedefs.Ec2SecurityGroup(group['GroupId'])
		securityGroup.name = group['GroupName']
		securityGroup.description = group['Description']

		# There are two Security Group Types. One for ingress and another for egress. 
		groupTypes = ['IpPermissionsEgress', 'IpPermissions']
		groupPermissions = []
		for groupType in groupTypes:
			# Let's create an array of EC2 security group objects
			for permission in group[groupType]:
				groupPermission = arsedefs.Ec2SecurityGroupPermission()
				if 'FromPort' in permission:
					groupPermission.fromPort = permission['FromPort']
				else:
					groupPermission.fromPort = 'all'
				
				if 'ToPort' in permission:
					groupPermission.toPort = permission['ToPort']
				else:
					groupPermission.fromPort = 'all'
				
				groupPermission.protocol = permission['IpProtocol']
				if groupType == 'IpPermissionsEgress':
					groupPermission.type = 'outgoing'
				elif groupType == 'IpPermissions': 
					groupPermission.type = 'incoming'

				ranges = []
				# Catches lists of IPs
				if len(permission['IpRanges']) > 1:
					for cidr in permission['IpRanges']:
						ranges.append(cidr['CidrIp'])
				# This is pretty much to catch 0.0.0.0/0
				elif len(permission['IpRanges']) == 1:
					ranges.append(permission['IpRanges'][0]['CidrIp'])
				# When objects beside cidr ranges appear, we don't handle those yet
				else:
					ranges = "n/a"

				# Append array of IP ranges to group permission object
				groupPermission.ranges = ranges
				groupPermissions.append(groupPermission)
			# Append array of permissions objects to the security group object
			securityGroup.permissions = groupPermissions
		# Append security group object to array of security groups
		groups.append(securityGroup)

	if securityGroupId == "all":
		return groups
	else:
		return groups[0]
#
#
def displayEc2Images(ec2):
	try:
		images = getEc2Images(ec2)
	except Exception as e:
		sys.exit("getEc2Images query failure: " + str(e[0]))

	print("{0:<14s} {1:<70s} {2:<7s} {3:<30s}".format("ID:", "Name:", "vType:", "Creation Date:"))
	print "======================================================================================================================"
	for image in images:
		image.printShort()
#
#
def displayEc2SecurityGroups(ec2, securityGroupId):
	try:
		groups = getEc2SecurityGroups(ec2, securityGroupId)
	except Exception as e:
	 	sys.exit("Get Security Groups query failure: " + str(e[0]))

	if isinstance(groups, collections.Sequence):
		print " ID:          Name:                    Description"
		print "================================================================="

		for group in groups:
			group.printShort()
	else:
		groups.printLong()
#
#		
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