#! /usr/local/bin/python
import arsedefs
import boto3
import collections
from colorama import Fore, Back, Style, init
import re
import sys

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

	# If we request all volumes, we return an array
	if volumeId == "all":
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

		if volumeId == "all":
			returnedVolumes.append(returnedVolume)

	# If we asked for all, return an array of Ec2Volumes or just one
	if volumeId == "all":
		return returnedVolumes
	else:
		return returnedVolume
#
#
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
#
def displayEc2KeyPairs(ec2):
	try:
		keyPairs = getEc2KeyPairs(ec2)
	except Exception as e:
		sys.exit("getKeyPairs query failure: " + str(e[0]))

	print("{0:<12s} {1}".format("Name:", "Fingerprint:"))
	print "========================================================================"

	for keyPair in keyPairs:
		keyPair.display()
#
# 
def displayEc2Volume(ec2, volumeId):
	try:
		volumes = getEc2Volume(ec2, volumeId)
	except Exception as e:
		sys.exit("getVolumes query failure: " + str(e[0]))

	if isinstance(volumes, collections.Sequence):
		print ("{0:<12}  {1:<24} {2:<4} {3:<9} {4:<8} {5:<10} {6}".format(
			"ID:", "Attached:", "GB:", "Device:", "Status:", "Zone:", "Name:"))
		print "===================================================================================================="

		for volume in volumes:
			volume.printShort()
	else:
	 	volumes.printLong()

def main():
	# Let's be sure we get a command line option
	clOption = ''
	if len(sys.argv) < 2:
		sys.exit("no")
	else:
		clOption = sys.argv[1]

	# Parse said command line option
	if clOption == "" or re.search('(-)?(-)?h(elp)?', clOption):
		arsedefs.printHelp()
	else: 
		# Initialize the client object
		ec2 = boto3.client('ec2')

		# We don't need no stinkin argparse
		if clOption == "volumes":
			displayEc2Volume(ec2, 'all')
		elif re.search('^vol\-', clOption):
			displayEc2Volume(ec2, clOption)
		elif clOption == "keys":
			displayEc2KeyPairs(ec2)
		else:
			print "Error: invalid option."
			arsedefs.printHelp()

	print ""
#
if __name__ == '__main__':
	main()