#! /usr/local/bin/python
import arsedefs
import boto3
import collections
from colorama import Fore, Back, Style, init
import re
import sys
#
# Request EC2 Elastic Loadbalancers from AWS API
def getEc2Elbs(ec2, elbName):
	try:
		if elbName == '':
			loadBalancers = ec2.describe_load_balancers()
		else:
			loadBalancers = ec2.describe_load_balancers(LoadBalancerNames=[elbName])
	except Exception as e:
		sys.exit("Elastic Load Balancer query failure: " + str(e[0]))

	elbs = []
	for lb in loadBalancers['LoadBalancerDescriptions']:
		elb = arsedefs.Ec2Elb(lb['LoadBalancerName'])
		elb.dnsName = lb['DNSName'],
		elb.vpcId = lb['VPCId'],
		elb.zones = lb['AvailabilityZones']

		# Loop over instances to which ELB is attached
		instances = []
		for instance in lb['Instances']:
			instances.append(instance['InstanceId'])
		elb.instances = instances

		elbListeners = []
		# Iterate & display through each listener of the ELB in question
		for listener in lb['ListenerDescriptions']:
			elbListener = arsedefs.Ec2ElbListener()
			elbListener.lbPort = listener['Listener']['LoadBalancerPort']
			elbListener.lbProtocol = listener['Listener']['Protocol']
			elbListener.instancePort = listener['Listener']['InstancePort']
			elbListener.instanceProtocol = listener['Listener']['InstanceProtocol']
			elbListeners.append(elbListener)
		elb.listeners = elbListeners
		elbs.append(elb)

	#if elbName == '':
	return elbs
	# else:
	# 	return elbs[0]
#
# Request EC2 SSH Key Pairs from AWS API
def getEc2KeyPairs(ec2):
	try:
		pairs = ec2.describe_key_pairs()
	except Exception as e:
		sys.exit("Key pair query failure: " + str(e[0]))

	keyPairs = []
	for key in pairs['KeyPairs']:
		keyPair = arsedefs.Ec2KeyPair()
		keyPair.name = key['KeyName']
		keyPair.fingerprint = key['KeyFingerprint']
		keyPairs.append(keyPair)

	return keyPairs
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
# Get a list of volumes or a single volumes and return an Ec2Volume object
#  or array of Ec2Volume objects
def getEc2Volume(ec2, volumeId):
	try:
		if volumeId == "all":
			volumes = ec2.describe_volumes()
		else:
			volumes = ec2.describe_volumes(VolumeIds=[volumeId])
	except Exception as e:
		sys.exit("Volumes query failure: " + str(e[0]))

	returnedVolumes = []
	# Always an array, even of 1. Iterate through any volumes returned.
	for volume in volumes['Volumes']:
		returnedVolume = arsedefs.Ec2Volume(volume['VolumeId'])

		# Get the value of the name tag. Don't die in a fire if there isn't one. 
		tagName = ''
		if 'Tags' in volume:
			for tag in volume['Tags']:
				if tag['Key'] == "Name":
					tagName = tag['Value']

		returnedVolume.availabilityZone = volume['AvailabilityZone']
		returnedVolume.attached['attachDevice'] = volume['Attachments'][0]['Device']
		returnedVolume.attached['attachInstanceId'] = volume['Attachments'][0]['InstanceId']
		returnedVolume.attached['attachTime'] = volume['Attachments'][0]['AttachTime']
		#
		# So, in order to make this work we're going to have to probably make an array of all instance IDs
		#   then ec2.describe_instances(instanceIDs=[thatarray]). Iterate over that and put the hostname
		#   tags in the volume objects
		returnedVolume.attached['attachHostname'] = returnedVolume.attached['attachInstanceId']
		returnedVolume.size = volume['Size']
		returnedVolume.state = volume['State']
		returnedVolume.tagName = tagName

		returnedVolumes.append(returnedVolume)

	# If we asked for all, return an array of Ec2Volumes or just one
	if volumeId == "all":
		return returnedVolumes
	else:
		return returnedVolumes[0]
#
#
def displayEc2Elbs(ec2, lbName):
	try:
		elbs = getEc2Elbs(ec2, lbName)
	except Exception as e:
		sys.exit("getEc2Elbs query failure: " + str(e[0]))

	print("{0:<13} {1:<16} {2:<29} {3}".format('VPC ID:', 'ELB Name:', 'Zones:', 'Public DNS Name:'))
	print("===================================================================================================")

	for elb in elbs:
		elb.printShort()		
#
#
def displayEc2KeyPairs(ec2):
	try:
		keyPairs = getEc2KeyPairs(ec2)
	except Exception as e:
		sys.exit("getKeyPairs query failure: " + str(e[0]))

	print("{0:<12s} {1}".format("Name:", "Fingerprint:"))
	print "========================================================================"

	for keyPair in keyPairs:
		keyPair.printLong()
#
#
def displayEc2SecurityGroups(ec2, securityGroupId):
	#try:
	groups = getEc2SecurityGroups(ec2, securityGroupId)
	# except Exception as e:
	# 	sys.exit("Get Security Groups query failure: " + str(e[0]))

	if isinstance(groups, collections.Sequence):
		print " ID:          Name:                    Description"
		print "================================================================="

		for group in groups:
			group.printShort()
	else:
		groups.printLong()
#
# 
def displayEc2Volumes(ec2, volumeId):
	try:
		volumes = getEc2Volume(ec2, volumeId)
	except Exception as e:
		sys.exit("getVolumes query failure: " + str(e[0]))

	if isinstance(volumes, collections.Sequence):
		print " ID:           Attached:                GB:  Device:    Status:   Zone:       Name:"
		print "===================================================================================================="
		#print ("-[{0}]----------[{1}]--------------[{2}]--[{3}]--[{4}]---[{5}]-----[{6}]----------------------".format(
		#	"ID", "Attached", "GB", "Device", "Status", "Zone", "Name"))

		for volume in volumes:
			volume.printShort()
	else:
	 	volumes.printLong()

def main():
	# Let's be sure we get a command line option
	clOption = ''
	if len(sys.argv) < 2:
		arsedefs.printHelp()
	else:
		clOption = sys.argv[1]

		# Parse said command line option
		if clOption == "" or re.search('^(-)?(-)?h(elp)?', clOption):
			arsedefs.printHelp()
		else: 
			# Initialize the AWS client object
			if re.search('^elb', clOption):
				ec2 = boto3.client('elb')
			else:
				ec2 = boto3.client('ec2')

			# We don't need no stinkin argparse
			#
			# Elastic Loadbalancers
			if clOption == "elb":
				displayEc2Elbs(ec2, '')
			elif re.search('^elb\-', clOption):
				displayEc2Elbs(ec2, clOption.lstrip('elb-'))
			# 
			elif clOption == "keys":
				displayEc2KeyPairs(ec2)
			elif clOption == "security":
				displayEc2SecurityGroups(ec2, 'all')
			elif re.search('^sg\-', clOption):
				displayEc2SecurityGroups(ec2, clOption)				
			elif clOption == "volumes":
				displayEc2Volumes(ec2, 'all')
			elif re.search('^vol\-', clOption):
				displayEc2Volumes(ec2, clOption)
			else:
				print "Error: invalid option."
				arsedefs.printHelp()

	print ""
#
if __name__ == '__main__':
	main()