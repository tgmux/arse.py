import boto3
from colorama import Fore, Back, Style, init
import re
import sys

class Ec2EIp:
	'Common base class for EC2 Elastic IP Addresses'

	def __init__(self):
		self.awsAccountName = ''
		self.instanceId = ''
		self.networkInterfaceId = ''
		self.networkInterfaceOwnerId = ''
		self.publicIp = ''
		self.privateIpAddress = ''
		
	def printShort(self):
		# Colors are the new white text
		if self.privateIpAddress is None:
			self.privateIpAddress = Fore.RED + "Detached       " + Fore.RESET

		print (" {account:<9s} {publicIp:<15} {privateIpAddress:<15} {instanceId:<20} {networkInterfaceId:<13} {networkInterfaceOwnerId}".format(
			account=self.awsAccountName,
			publicIp=self.publicIp,
			instanceId=self.instanceId,
			networkInterfaceId=self.networkInterfaceId,
			networkInterfaceOwnerId=self.networkInterfaceOwnerId,
			privateIpAddress=self.privateIpAddress))

class Ec2Elb:
	'Common base class for EC2 Elastic Loadbalancers'

	def __init__(self, elbName):
		self.availabilityZones = []
		self.awsAccountName = ''
		self.created = ''
		self.elbName = elbName
		self.dnsName = ''
		self.healthCheck = ''
		self.instances = []
		self.listeners = []
		self.policies = ''
		self.securityGroups = []
		self.subnets = []
		self.vpcId = ''

	def printShort(self):
		# funky work to condense the AZs into an easily readable nugget 
		zones = []
		for zone in self.availabilityZones:
			split_zone = zone.split("-")
			region = split_zone[0] + "-" + split_zone[1]
			zones.append(split_zone[2])

		print (" {account:<5s} {vpcid:<13} {lbname:<41} {zones:<33} {dnsname}".format(
			account=self.awsAccountName,
			lbname=Style.BRIGHT + self.elbName + Style.RESET_ALL,
			dnsname=self.dnsName[:-18],
			vpcid=self.vpcId,
			zones=region + " " + str(zones)))

	def printLong(self):
		print("- Created: {created}".format(
			created=str(self.created)))

		print "\n--[ Networking ]----------------------"
		print(" - {vpcId}\n - {groups}\n - {subnets}".format(
			groups=str(self.securityGroups),
			subnets=str(self.subnets),
			vpcId=self.vpcId))

		print "\n--[ Listeners ]-----------------------"
		for listener in self.listeners:
			print(" > {lbprotocol:<8} {lbport:<6} :: {iprotocol:<8} {iport:<6}".format(
				lbport=listener.lbPort,
				lbprotocol=listener.lbProtocol,
				iport=listener.instancePort,
				iprotocol=listener.instanceProtocol))

		print "\n--[ Policies ]------------------------"
		print str(self.policies)

class Ec2ElbListener:
	def __init__(self):
		self.instancePort = ''
		self.instanceProtocol = ''
		self.lbPort = ''
		self.lbProtocol = ''

class Ec2Image:
	'Common base class for EC2 AMIs'

	def __init__(self):
		self.awsAccountName = ''
		self.created = ''
		self.imageId = ''
		self.name = ''
		self.virtualizationType = ''

	def printShort(self):
		print(" {account:<9s} {id:<14s} {name:<70s} {vtype:<7s} {date:<30s}".format(
			account=self.awsAccountName,
			id=self.imageId,
			name=self.name,
			vtype=self.virtualizationType[:5],
			date=self.created))

class Ec2Instance:
	'Common base class for EC2 Instances'

	def __init__(self, instanceId):
		self.awsAccountName = ''
		self.instanceId = instanceId
		self.ip = ''
		self.itype = ''
		self.launchtime = ''
		self.name = ''
		self.reason = ''
		self.state = ''
		self.vtype = ''
		self.zone = ''

	def printShort(self):
		# Colors are the new white text
		if self.state == "running":
			self.state = Fore.GREEN + self.state + Fore.RESET
		elif self.state == "stopped":
			self.state = Fore.RED + self.state + Fore.RESET
		else: 
			self.state = Fore.YELLOW + self.state + Fore.RESET

		print(" {account:<9s} {name:<31s}  {id:<20s}  {itype:<10s}  {vtype:<6s}  {zone:<15s}  {state:<8}  {ip}".format(
			account=self.awsAccountName,
			name=self.name[:30],
			id=self.instanceId,
			itype=self.itype,
			vtype=self.vtype[:4],
			zone=self.zone,
			state=self.state,
			ip=self.ip))

class Ec2KeyPair:
	'Common base class for EC2 key pairs'

	def __init__(self):
		self.awsAccountName = ''
		self.fingerprint = ''
		self.name = ''

	def printShort(self):
		print(" {account: <9s} {name:<24s} {fingerprint}".format(
			account=self.awsAccountName,
			name=self.name,
			fingerprint=self.fingerprint))

class Ec2SecurityGroup:
	'Common base class for EC2 Security Groups'

	def __init__(self, securityGroupId):
		self.awsAccountName = ''
		self.description = ''
		self.name = ''
		self.permissions = []
		self.securityGroupId = securityGroupId

	def printShort(self):
		print(" {account:<9s} {id:<12s} {name:<32s} {description}").format(
			account=self.awsAccountName,
			name=self.name[0:31],
			id=self.securityGroupId,
			description=self.description[0:60])

	def printLong(self):
		print(" {id:<12s} {name:<24s} {description}\n").format(
			name=self.name,
			id=self.securityGroupId,
			description=self.description)

		for permission in self.permissions:
			print ("  {type:<9} {protocol:<14}  {fromPort:<6}  {toPort:<6} {ranges}".format(
				type=permission.groupType,
				protocol=Fore.CYAN + permission.protocol + Fore.RESET,
				fromPort=permission.fromPort,
				toPort=permission.toPort,
				ranges=permission.ranges))

class Ec2SecurityGroupPermission:
	'EC2 Security Group Permission Data Structure'

	def __init__(self):
		self.fromPort = ''
		self.groupType = ''
		self.protocol = ''
		self.ranges = []
		self.toPort = ''

class Ec2Volume:
	'Class to describe EC2 EBS Volumes'

	def __init__(self, volumeId):
		self.awsAccountName = ''
		self.attached = {
			'attachDevice': '',
			'attachHostname': '',
			'attachInstanceId': '',
			'attachTime': ''}
		self.availabilityZone = ''
		self.created = ''
		self.name = ''
		self.size = ''
		self.state = ''
		self.tagName = ''
		self.volumeId = volumeId
		self.volumeType = ''

	def printShort(self):
		# Color it. 
		if self.state == 'in-use':
			self.state = Fore.GREEN + 'in-use' + Fore.RESET
		elif self.state == 'available': 
			self.state = Fore.CYAN + 'available' + Fore.RESET
		else:
			self.state = Fore.RED + self.state + Fore.RESET

		self.combinedInstanceName = (self.attached['attachInstanceId'] +
			" (" + str(self.attached['attachHostname']) + ")")
		print (" {account:<9s} {volumeId:<22}  {instance:<41} {size:<5} {device:<10} {state:<19} {zone:<16} {type:<3} {tagname}".format(
				account=self.awsAccountName,
				zone=self.availabilityZone,
				volumeId=self.volumeId,
				instance=self.combinedInstanceName,
				state=self.state,
				device=self.attached['attachDevice'],
				size=self.size,
				type=self.volumeType,
				tagname=self.tagName))

	def printLong(self):
		print "{zone} {volumeId} {state} {size}GB {tagname}".format(
				zone=self.availabilityZone,
				volumeId=self.volumeId,
				state=self.state,
				size=self.size,
				tagname=self.tagName)

class IamUser:
	'Class for IAM Users'

	def __init__(self):
		self.awsAccountName = ''
		self.arn = ''
		self.createDate = ''
		self.path = ''
		self.passwordLastUsed = ''
		self.userId = ''
		self.userName = ''

	def printShort(self):
		print (" {account:<9} {userName:<21} {userId:<22} {createDate:<27s} {passwordLastUsed:<27s}".format(
			account=self.awsAccountName,
			userName=self.userName,
			userId=self.userId,
			createDate=str(self.createDate),
			passwordLastUsed=str(self.passwordLastUsed)))

class RdsInstance:
	'Class for RDS Instances'

	def __init__(self, dbInstanceIdentifier):
		self.allocatedStorage = ''
		self.awsAccountName = ''
		self.availabilityZone = ''
		self.backupRetentionPeriod = ''
		self.copyTagsToSnapshot = bool
		self.dbInstanceArn = ''
		self.dbInstanceClass = ''
		self.dbInstanceIdentifier = dbInstanceIdentifier
		self.dbInstancePort = ''
		self.dbInstanceStatus = ''
		self.dbiResourceId = ''
		self.dbName = ''
		self.dbParameterGroups = ''
		self.dbSecurityGroups = ''
		self.dbSubnetGroup = []
		self.dbSubnetGroupDescription = ''
		self.dbSubnetGroupName = ''
		self.dbSubnetGroupStatus = ''
		self.endpointAddress = ''
		self.endpointId = ''
		self.endpointPort = ''
		self.engine = ''
		self.engineVersion = ''
		self.enhancedMonitoringResourceArn = ''
		self.instanceCreateTime = ''
		self.latestRestorableTime = ''
		self.masterUsername = ''
		self.monitoringInterval = ''
		self.monitoringRoleArn = ''
		self.multiAZ = bool
		self.optionGroupMemberships = []
		self.preferredBackupWindow = ''
		self.preferredMaintenanceWindow = ''
		self.publiclyAccessible = ''
		self.readReplicaDBInstanceIdentifiers = []
		self.secondaryAvailabilityZone = ''
		self.storageType = ''
		self.storageEncrypted = bool
		self.vpcSecurityGroups = []
		self.vpcId = ''

	def printShort(self):
		print (" {account:<6} {dbidentifier:<18} {storage:<4} {storageType:<6} {paz:<14} {saz:<14} {engine:<8} {version:<10} {type:<14} {maintwindow:<21} {backupwindow}" .format(
			account=self.awsAccountName,
			backupwindow=self.preferredBackupWindow,
			dbidentifier=self.dbInstanceIdentifier,
			engine=self.engine,
			maintwindow=self.preferredMaintenanceWindow,
			paz=self.availabilityZone,
			saz=self.secondaryAvailabilityZone,
			storage=self.allocatedStorage,
			storageType=self.storageType,
			type=self.dbInstanceClass,
			version=self.engineVersion))

	def printLong(self):
		print ("--[ account: {account} ]---------------------------------".format(account=self.awsAccountName))
		print ("{dbIdentifierField:<20} {dbidentifier} \n{engineField:<20} {engine} {version}".format(
			dbIdentifierField="identifier:",
			dbidentifier=self.dbInstanceIdentifier,
			engineField="engine:",
			engine=self.engine,
			version=self.engineVersion))

		# Color the encrypted field
		if self.storageEncrypted == False:
			self.storageEncrypted = Fore.RED + 'false' + Fore.RESET
		else:
			self.storageEncrypted = Fore.GREEN + 'true' + Fore.RESET

		print ("{storageField:<20} {storageSize}GB {storageType} \n{instanceField:<20} {instanceType} \n{encryptedField:<20} {storageEncrypted}".format(
			encryptedField="encrypted:",
			instanceField="instance:",
			instanceType=self.dbInstanceClass,
			storageField="storage:",
			storageEncrypted=self.storageEncrypted,
			storageSize=self.allocatedStorage,
			storageType=self.storageType))
		print ("{endpointField:<20} {endpointAddress}:{endpointPort} \n{dbInstanceArnField:<20} {dbInstanceArn}".format(
			dbInstanceArnField="instance arn:",
			dbInstanceArn=self.dbInstanceArn,
			endpointField="endpoint:",
			endpointAddress=self.endpointAddress,
			endpointPort=self.endpointPort))
		print ("{regionField:<20} {primaryAZ} // {secondaryAZ} \n{monitoringField:<20} {monitoringInterval} \n{masterNameField:<20} {masterUsername}".format(
			masterNameField="master uname:",
			masterUsername=self.masterUsername,
			monitoringField="monitor interval:",
			monitoringInterval=self.monitoringInterval,
			primaryAZ=self.availabilityZone,
			regionField="region:",
			secondaryAZ=self.secondaryAvailabilityZone))
		print ("\n--[ maintenance: ]------------------------------------".format(account=self.awsAccountName))
		print ("{createdField:<20} {instanceCreateTime} \n{restorableField:<20} {latestRestorableTime}".format(
			createdField="created:",
			instanceCreateTime=self.instanceCreateTime,
			restorableField="latest restore:",
			latestRestorableTime=self.latestRestorableTime))
		print ("{maintenanceField:<20} {preferredMaintenanceWindow} \n{backupField:<20} {preferredBackupWindow} \n{retentionField:<20} {retentionPeriod}".format(
			backupField="backup window:",
			maintenanceField="maintenance window:",
			preferredBackupWindow=self.preferredBackupWindow,
			preferredMaintenanceWindow=self.preferredMaintenanceWindow,
			retentionField="retention period:",
			retentionPeriod=self.backupRetentionPeriod))
		print "\n"

#
# Request EC2 Elastic IP Addresses from AWS API
def getEc2EIps(awsAccountName, awsRegion, session):
	ec2 = session.client('ec2', region_name=awsRegion)

	try:
		ec2eips = ec2.describe_addresses()
	except Exception as e:
		sys.exit("EIPs query failure: " + str(e[0]))

	eips = []
	for ip in ec2eips['Addresses']:
		eip = Ec2EIp()
		eip.allocationId = ip.get('AllocationId')
		eip.associationId = ip.get('AssociationId')
		eip.awsAccountName = awsAccountName
		eip.instanceId = ip.get('InstanceId')
		eip.networkInterfaceId = ip.get('NetworkInterfaceId')
		eip.networkInterfaceOwnerId = ip.get('NetworkInterfaceOwnerId')
		eip.privateIpAddress = ip.get('PrivateIpAddress')
		eip.publicIp = ip['PublicIp']
		eips.append(eip)

	return eips

#
# Request EC2 Elastic Loadbalancers from AWS API
def getEc2Elbs(awsAccountName, awsRegion, session, elbName):
	ec2 = session.client('elb', region_name=awsRegion)
	loadBalancers = {}
	loadBalancers['LoadBalancerDescriptions'] = []

	try:
		if elbName == '':
			loadBalancers = ec2.describe_load_balancers()
		else:
			loadBalancers = ec2.describe_load_balancers(LoadBalancerNames=[elbName])
	except Exception as e:
		# All regions and accounts we check for this group will throw an error, this is fine.
		if not re.search('LoadBalancerNotFound', e[0]):
			sys.exit("\nLoad balancer query failure: " + str((e[0])))

	# Iterate through the returned loadbalancers
	elbs = []
	for lb in loadBalancers['LoadBalancerDescriptions']:
		elb = Ec2Elb(lb['LoadBalancerName'])
		elb.availabilityZones = lb['AvailabilityZones']
		elb.awsAccountName = awsAccountName
		elb.created = lb['CreatedTime']
		elb.dnsName = lb['DNSName']
		elb.policies = lb['Policies']
		elb.securityGroups = lb['SecurityGroups']
		elb.subnets = lb['Subnets']
		elb.vpcId = lb.get('VPCId')

		# Loop over instances to which ELB is attached
		instances = []
		for instance in lb['Instances']:
			instances.append(instance['InstanceId'])
		elb.instances = instances

		elbListeners = []
		# Iterate & display through each listener of the ELB in question
		for listener in lb['ListenerDescriptions']:
			elbListener = Ec2ElbListener()
			elbListener.lbPort = listener['Listener']['LoadBalancerPort']
			elbListener.lbProtocol = listener['Listener']['Protocol']
			elbListener.instancePort = listener['Listener']['InstancePort']
			elbListener.instanceProtocol = listener['Listener']['InstanceProtocol']
			elbListeners.append(elbListener)
			
		elb.listeners = elbListeners
		elbs.append(elb)

	return elbs
#
# Display all EC2 AMIs
def getEc2Images(awsAccountName, awsRegion, session):
	ec2 = session.client('ec2', region_name=awsRegion)

	try:
		diskImages = ec2.describe_images(Owners=['self'])
	except Exception as e:
		sys.exit("Images query failure: " + str(e[0]))

	images = []
	for ami in diskImages['Images']:
		image = Ec2Image()
		image.awsAccountName = awsAccountName
		image.created = ami['CreationDate']
		image.imageId = ami['ImageId']
		image.name = ami['Name']
		image.virtualizationType = ami['VirtualizationType']
		images.append(image)

	return images
#
#
def getEc2Instances(awsAccountName, awsRegion, session, instanceId):
	ec2 = session.client('ec2', region_name=awsRegion)

	if instanceId == "":
		try:
			reservations = ec2.describe_instances()
		except Exception as e:
			sys.exit("Instance reservation query failure: " + str(e[0]))

	instances = []
	for reservation in reservations['Reservations']:
		for inst in reservation['Instances']:
			instance = Ec2Instance(inst['InstanceId'])
			for tag in inst['Tags']:
				if tag['Key'] == 'Name':
					inst['NameFromTag'] = tag['Value']

			if 'PrivateIpAddress' in inst:
				inst['VerifiedIp'] = inst['PrivateIpAddress']
			else:
				inst['VerifiedIp'] = 'n/a'

			instance.awsAccountName = awsAccountName
			instance.name = inst['NameFromTag']
			instance.itype = inst['InstanceType']
			instance.vtype = inst['VirtualizationType']
			instance.zone = inst['Placement']['AvailabilityZone']
			instance.state = inst['State']['Name']
			instance.ip = inst['VerifiedIp']
			instances.append(instance)

	ec2 = None
	return instances
#
# Request EC2 SSH Key Pairs from AWS API
def getEc2KeyPairs(awsAccountName, awsRegion, session):
	ec2 = session.client('ec2', region_name=awsRegion)

	try:
		pairs = ec2.describe_key_pairs()
	except Exception as e:
		sys.exit("Key pair query failure: " + str(e[0]))

	keyPairs = []
	for key in pairs['KeyPairs']:
		keyPair = Ec2KeyPair()
		keyPair.awsAccountName = awsAccountName
		keyPair.name = key['KeyName']
		keyPair.fingerprint = key['KeyFingerprint']
		keyPairs.append(keyPair)

	return keyPairs
#
# Request EC2 security groups from AWS API
def getEc2SecurityGroups(awsAccountName, awsRegion, session, securityGroupId):
	ec2 = session.client('ec2', region_name=awsRegion)
	securityGroups = {}
	securityGroups['SecurityGroups'] = []

	try:
		if securityGroupId == '':
			securityGroups = ec2.describe_security_groups()
		else:
			securityGroups = ec2.describe_security_groups(GroupIds=[securityGroupId])
	except Exception as e:
		# All regions and accounts we check for this group will throw an error, this is fine.
		if not re.search('InvalidGroup\.NotFound', e[0]):
			sys.exit("\nSecurity group query failure: " + str((e[0])))

	# Array of returned EC2 security group objects
	groups = []
	for group in securityGroups['SecurityGroups']:
		securityGroup = Ec2SecurityGroup(group['GroupId'])
		securityGroup.awsAccountName = awsAccountName
		securityGroup.name = group['GroupName']
		securityGroup.description = group['Description']

		# There are two Security Group Types. One for ingress and another for egress. 
		groupTypes = ['IpPermissionsEgress', 'IpPermissions']
		groupPermissions = []
		for groupType in groupTypes:
			# Let's create an array of EC2 security group objects
			for permission in group[groupType]:
				groupPermission = Ec2SecurityGroupPermission()
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
					groupPermission.groupType = 'outgoing'
				elif groupType == 'IpPermissions': 
					groupPermission.groupType = 'incoming'

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

	return groups
# Get a list of volumes or a single volumes and return an Ec2Volume object
#  or array of Ec2Volume objects
def getEc2Volumes(awsAccountName, awsRegion, session, volumeId):
	ec2 = session.client('ec2', region_name=awsRegion)
	try:
		if volumeId == '':
			volumes = ec2.describe_volumes()
		else:
			volumes = ec2.describe_volumes(VolumeIds=[volumeId])
	except Exception as e:
		sys.exit("Volumes query failure: " + str(e[0]))

	returnedVolumes = []
	# Always an array, even of 1. Iterate through any volumes returned.
	for volume in volumes['Volumes']:
		returnedVolume = Ec2Volume(volume['VolumeId'])

		# Get the value of the name tag. Don't die in a fire if there isn't one. 
		tagName = ''
		if 'Tags' in volume:
			for tag in volume['Tags']:
				if tag['Key'] == "Name":
					tagName = tag['Value']

		returnedVolume.availabilityZone = volume['AvailabilityZone']

		# If a volume is not attached to an instance, the array of attachments will exist
		#	but will be of course length of 0
		if len(volume['Attachments']) > 0:
			returnedVolume.attached['attachDevice'] = volume['Attachments'][0]['Device']
			returnedVolume.attached['attachInstanceId'] = volume['Attachments'][0]['InstanceId']
			returnedVolume.attached['attachTime'] = volume['Attachments'][0]['AttachTime']
			#
			# So, in order to make this work we're going to have to probably make an array of all instance IDs
			#   then ec2.describe_instances(instanceIDs=[thatarray]). Iterate over that and put the hostname
			#   tags in the volume objects. Otherwise it's going to be N + a few API calls where N is the number of volumes. 
			returnedVolume.attached['attachHostname'] = returnedVolume.attached['attachInstanceId']
		else:
			returnedVolume.attached['attachInstanceId'] = ' detached '
			returnedVolume.attached['attachHostname'] = ' detached '

		returnedVolume.size = volume['Size']
		returnedVolume.state = volume['State']
		returnedVolume.tagName = tagName
		returnedVolume.awsAccountName = awsAccountName
		returnedVolume.volumeType = volume['VolumeType']

		returnedVolumes.append(returnedVolume)

	return returnedVolumes
#
# Get a list of all IAM users
def getIamUsers(awsAccountName, session):
	iam = session.client('iam')
	try:
		users = iam.list_users()
	except Exception as e:
		sys.exit("IAM Users query failure:" + str(e[0]))

	returnedUsers = []
	for user in users['Users']:
		returnedUser = IamUser()
		returnedUser.awsAccountName = awsAccountName
		returnedUser.arn = user['Arn']
		returnedUser.createDate = user['CreateDate']
		returnedUser.passwordLastUsed = user.get('PasswordLastUsed')
		returnedUser.path = user['Path']
		returnedUser.userName = user['UserName']
		returnedUser.userId = user['UserId']

		returnedUsers.append(returnedUser)

	return returnedUsers
# 
# Get a list of all RDS Instances
def getRdsInstances(awsAccountName, awsRegion, session, dbInstanceIdentifier):
	rds = session.client('rds', region_name=awsRegion)
	try:
		if dbInstanceIdentifier == '':
			instances = rds.describe_db_instances()
		else:
			instances = rds.describe_db_instances(DBInstanceIdentifier=dbInstanceIdentifier)
	except Exception as e:
		instances = {}
		instances['DBInstances'] = []
		
		# An error code of DBInstanceNotFound indicates obviously, the db instance we're searching for
		#	by name does not exist. Let's not die on that, shall we?
		if e.response['Error']['Code'] != 'DBInstanceNotFound':
			sys.exit("rds instances query failure: " + str(e[0]))

	returnedInstances = []
	# Always an array, even of 1. Iterate through any volumes returned.
	for instance in instances['DBInstances']:
		returnedInstance = RdsInstance(instance['DBInstanceIdentifier'])
		returnedInstance.allocatedStorage = instance['AllocatedStorage']
		returnedInstance.awsAccountName = awsAccountName
		returnedInstance.availabilityZone = instance['AvailabilityZone']
		returnedInstance.backupRetentionPeriod = instance['BackupRetentionPeriod']
		returnedInstance.dbInstanceArn = instance['DBInstanceArn']
		returnedInstance.dbInstanceClass = instance['DBInstanceClass']
		returnedInstance.dbInstanceStatus = instance['DBInstanceStatus']
		returnedInstance.endpointAddress = instance['Endpoint']['Address']
		returnedInstance.endpointId = instance['Endpoint']['HostedZoneId']
		returnedInstance.endpointPort = instance['Endpoint']['Port']
		returnedInstance.engine = instance['Engine']
		returnedInstance.engineVersion = instance['EngineVersion']
		returnedInstance.instanceCreateTime = instance['InstanceCreateTime']
		returnedInstance.latestRestorableTime = instance['LatestRestorableTime']
		returnedInstance.optionGroupMemberships = '' #this is an array we need to do something with
		returnedInstance.masterUsername = instance['MasterUsername']
		returnedInstance.monitoringInterval = instance['MonitoringInterval']
		returnedInstance.vpcSecurityGroups = '' #this is an array we need to do something with
		returnedInstance.preferredBackupWindow = instance['PreferredBackupWindow']
		returnedInstance.preferredMaintenanceWindow = instance['PreferredMaintenanceWindow']
		returnedInstance.secondaryAvailabilityZone = instance.get('SecondaryAvailabilityZone')
		returnedInstance.storageEncrypted = instance['StorageEncrypted']
		
		# Formatting for readability
		if instance['StorageType'] == 'standard': 
			returnedInstance.storageType = 'std'
		else:
			returnedInstance.storageType = instance['StorageType']

		returnedInstances.append(returnedInstance)

	return returnedInstances
#
#
def printHeader(headerStyle):
	if headerStyle == "eips":
		print (" {0:<9s} {1:<15} {2:<15} {3:<20} {4:<13} {5}".format(
			"Acct:", "Public IP:", "Private IP:", "EC2 Instance:", "Net IF ID:", "Owner:"))
		print "==========================================================================================="
	elif headerStyle == "elbs":
		print("{0:<6s} {1:<13} {2:<33} {3:<33} {4}".format(
			"Acct:", "VPC ID:", "ELB Name:", "Zones:", "Public DNS Name:   (.elb.amazonaws.com)"))
		print "================================================================================================================================================="
	elif headerStyle == "images":
		print("{0:<10s} {1:<14s} {2:<70s} {3:<7s} {4:<30s}".format(
			"Acct:", "ID:", "Name:", "vType:", "Creation Date:"))
		print "============================================================================================================================="
	elif headerStyle == "instances":
		print("{0:<10s} {1:<32s} {2:<21s} {3:<11s} {4:<5s}  {5:<16s} {6:<7s}  {7}".format(
	 		"Acct:", "Name:", "ID:", "iType:", "vType:", "Zone:", "State:", "IP:"))
	 	print "============================================================================================================================="
	elif headerStyle == "keys":
		print("{0:<10s} {1:<24s} {2}".format(
			"Acct:", "Name:", "Fingerprint:"))
		print "============================================================================================================================="
	elif headerStyle == "rds":
		print ("{0:<6}  {1:<18} {2:<11} {3:<14} {4:<14} {5:<8} {6:<10} {7:<14} {8:<21} {9}" .format(
			"Acct:", "Name:", "Storage:", "Primary AZ:", "Second AZ:", "Engine:", "Version:", "Type:", "Maintenance Window:", "Backup Window:"))
		print "============================================================================================================================================"
	elif headerStyle == "security":
		print("{0:<10s} {1:<12s} {2:<32s} {3}".format(
			"Acct:", "SG ID:", "Name:", "Description:"))
		print "============================================================================================================================="
	elif headerStyle == "users":
		print ("{0:<10s} {1:<21} {2:<22} {3:<27} {4:<27}".format(
			"Acct:", "Username:", "User ID:", "Created:", "Password Last Used:"))
		print "============================================================================================================================="
	elif headerStyle == "volumes":
		print ("{0:<10s} {1:<23} {2:<41} {3:<5} {4:<10} {5:<9} {6:<17} {7}".format(
			"Acct:", "ID:", "Attached:", "GB:", "Device:", "Status:", "Zone:", "Name:"))
		print "==================================================================================================================================================================================="
#
#
def printHelp():
	print "\narse :: Amazon Reource Explorer"
	print "-------------------------------------------------------"
	print "  eips           - EC2 Elastic IP Address List"
	print "  elbs           - EC2 Elastic Loadbalancer List"
	print "  elb-<name>     - Verbose EC2 ELB Display"
	print "  images         - EC2 AMI List"
	print " *ami-xxxxxxxx   - Verbose EC2 AMI Display"
	print "  instances      - EC2 Instance List"
	print " *i-xxxxxxxx     - Verbose EC2 Instance Display"
	print "  keys           - EC2 SSH Keys"
	print "  rds            - RDS Instances"
	print "  rds-xxxxxxx    - Verbose RDS Instance"
	print "  security       - EC2 Security Groups"
	print "  sg-xxxxxxxx    - Verbose EC2 Security Group Display"
	print "  users          - IAM User List"
	print "  volumes        - EBS Volumes"
 	print " *vol-xxxxxxxx   - Verbose EBS Volume Display"
	print "-------------------------------------------------------"
	print "ex: arse [command]\n"
