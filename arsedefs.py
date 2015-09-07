class Ec2KeyPair:
	'Common base class for EC2 key pairs'

	def __init__(self):
		self.name = ''
		self.fingerprint = ''

	def display(self):
		print("{name:<12s} {fingerprint}".format(
			name=self.name,
			fingerprint=self.fingerprint))


class Ec2Instance:
	'Common base class for EC2 Instances'

	def __init__(self, instanceId):
		self.instanceId = instanceId


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
		print ("{volumeId:<12}  {instance:<24} {size:<4} {device:<9} {state:<8} {zone} {tagname}".format(
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
	print "\narse :: Amazon Resource Explorer"
	print "---------------------------------"
	print "  keys        - List EC2 SSH Keys"
	print "  volumes     - List EBS volumes"
	print "---------------------------------"
	print "ex: arse [options] [command]"