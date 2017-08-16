# arse

Basic wrapper for AWS API to allow ops folk to avoid the console.

~~~~
% ./arse.py

arse :: Amazon ReSource Explorer
-------------------------------------------------------
  eips           - EC2 Elastic IP Address List
  elb            - EC2 Elastic Loadbalancer List
  elb-<name>     - Verbose EC2 ELB Display
  images         - EC2 AMI List
  **ami-xxxxxxxx - Verbose EC2 AMI Display
  instances      - EC2 Instance List
  **i-xxxxxxxx   - Verbose EC2 Instance Display
  keys           - EC2 SSH Keys
  rds            - RDS Instances
  rds-xxxxxxxx   - Verbose RDS Instance
  security       - EC2 Security Groups
  sg-xxxxxxxx    - Verbose EC2 Security Group Display
  users          - IAM User List
  volumes        - EBS Volumes
  **vol-xxxxxxxx - Verbose EBS Volume Display
-------------------------------------------------------
ex: arse [command]

* - still needs to be fixt :D
~~~~
