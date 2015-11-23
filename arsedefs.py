from colorama import Fore, Back, Style, init

class Ec2KeyPair:
	'Common base class for EC2 key pairs'

	def __init__(self):
		self.name = ''
		self.fingerprint = ''

	def printLong(self):
		print("{name:<12s} {fingerprint}".format(
			name=self.name,
			fingerprint=self.fingerprint))

class Ec2Instance:
	'Common base class for EC2 Instances'

	def __init__(self, instanceId):
		self.instanceId = instanceId

class Ec2Elb:
	'Common base class for EC2 Elastic Loadbalancers'

	def __init__(self, elbName):
		self.availabilityZones = []
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
		print ("{vpcid:<13} {lbname:<24} {zones:<29} {dnsname}".format(
			lbname=Style.BRIGHT + self.elbName + Style.RESET_ALL,
			dnsname=self.dnsName,
			vpcid=self.vpcId,
			zones=str(self.availabilityZones)))

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

class Ec2SecurityGroup:
	'Common base class for EC2 Security Groups'

	def __init__(self, securityGroupId):
		self.securityGroupId = securityGroupId
		self.name = ''
		self.description = ''
		self.permissions = []

	def printShort(self):
		print(" {id:<12s} {name:<24s} {description}").format(
			name=self.name,
			id=self.securityGroupId,
			description=self.description)

	def printLong(self):
		print(" {id:<12s} {name:<24s} {description}\n").format(
			name=self.name,
			id=self.securityGroupId,
			description=self.description)

		for permission in self.permissions:
			print ("  {type:<9} {protocol:<14}  {fromPort:<6}  {toPort:<6} {ranges}".format(
				type=permission.type,
				protocol=Fore.CYAN + permission.protocol + Fore.RESET,
				fromPort=permission.fromPort,
				toPort=permission.toPort,
				ranges=permission.ranges))

class Ec2SecurityGroupPermission:
	'EC2 Security Group Permission Data Structure'

	def __init__(self):
		self.type = ''
		self.fromPort = ''
		self.toPort = ''
		self.protocol = ''
		self.ranges = []

class Ec2Volume:
	'Class to describe EC2 EBS Volumes'

	def __init__(self, volumeId):
		self.attached = {
			'attachDevice': '',
			'attachHostname': '',
			'attachInstanceId': '',
			'attachTime': ''}
		self.availabilityZone = ''
		self.createTime = ''
		self.name = ''
		self.size = ''
		self.state = ''
		self.tagName = ''
		self.volumeId = volumeId
		self.volumeType = ''

	def printShort(self):
		self.combinedInstanceName = (self.attached['attachInstanceId'] +
			" (" + str(self.attached['attachHostname']) + ")")
		print (" {volumeId:<12}  {instance:<24} {size:<4} {device:<10} {state:<9} {zone}  {tagname}".format(
				zone=self.availabilityZone,
				volumeId=self.volumeId,
				instance=self.combinedInstanceName,
				state=self.state,
				device=self.attached['attachDevice'],
				size=self.size,
				tagname=self.tagName))

	def printLong(self):
		print "{zone} {volumeId} {state} {size}GB {tagname}".format(
				zone=self.availabilityZone,
				volumeId=self.volumeId,
				state=self.state,
				size=self.size,
				tagname=self.tagName)

def printHelp():
	print "\narse :: Amazon ReSource Explorer"
	print "-------------------------------------------------------"
	print "  elb            - EC2 Elastic Loadbalancer List"
	print "  elb-<name>     - Verbose EC2 ELB Display"
	print "  *images        - EC2 AMI List"
	print "  *ami-xxxxxxxx  - Verbose EC2 AMI Display"
	print "  *instances     - EC2 Instance List"
	print "  *i-xxxxxxxx    - Verbose EC2 Instance Display"
	print "  keys           - EC2 SSH Keys"
	print "  security       - EC2 Security Groups"
	print "  sg-xxxxxxxx    - Verbose EC2 Security Group Display"
	print "  volumes        - EBS Volumes"
	print "  *vol-xxxxxxxx  - Verbose EBS Volume Display"
	print "-------------------------------------------------------"
	print "ex: arse [command]"
