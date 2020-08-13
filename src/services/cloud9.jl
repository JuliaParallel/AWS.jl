# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: cloud9

using Compat
using UUIDs
"""
    CreateEnvironmentEC2()

Creates an AWS Cloud9 development environment, launches an Amazon Elastic Compute Cloud (Amazon EC2) instance, and then connects from the instance to the environment.

# Required Parameters
- `instanceType`: The type of instance to connect to the environment (for example, t2.micro).
- `name`: The name of the environment to create. This name is visible to other AWS IAM users in the same AWS account.

# Optional Parameters
- `automaticStopTimeMinutes`: The number of minutes until the running instance is shut down after the environment has last been used.
- `clientRequestToken`: A unique, case-sensitive string that helps AWS Cloud9 to ensure this operation completes no more than one time. For more information, see Client Tokens in the Amazon EC2 API Reference.
- `connectionType`: The connection type used for connecting to an Amazon EC2 environment.
- `description`: The description of the environment to create.
- `ownerArn`: The Amazon Resource Name (ARN) of the environment owner. This ARN can be the ARN of any AWS IAM principal. If this value is not specified, the ARN defaults to this environment's creator.
- `subnetId`: The ID of the subnet in Amazon VPC that AWS Cloud9 will use to communicate with the Amazon EC2 instance.
- `tags`: An array of key-value pairs that will be associated with the new AWS Cloud9 development environment.
"""
CreateEnvironmentEC2(instanceType, name; aws::AWSConfig=AWS.aws_config) = cloud9("CreateEnvironmentEC2", Dict{String, Any}("instanceType"=>instanceType, "name"=>name); aws=aws)
CreateEnvironmentEC2(instanceType, name, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("CreateEnvironmentEC2", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("instanceType"=>instanceType, "name"=>name), args)); aws=aws)

"""
    CreateEnvironmentMembership()

Adds an environment member to an AWS Cloud9 development environment.

# Required Parameters
- `environmentId`: The ID of the environment that contains the environment member you want to add.
- `permissions`: The type of environment member permissions you want to associate with this environment member. Available values include:    read-only: Has read-only access to the environment.    read-write: Has read-write access to the environment.  
- `userArn`: The Amazon Resource Name (ARN) of the environment member you want to add.

"""
CreateEnvironmentMembership(environmentId, permissions, userArn; aws::AWSConfig=AWS.aws_config) = cloud9("CreateEnvironmentMembership", Dict{String, Any}("environmentId"=>environmentId, "permissions"=>permissions, "userArn"=>userArn); aws=aws)
CreateEnvironmentMembership(environmentId, permissions, userArn, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("CreateEnvironmentMembership", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("environmentId"=>environmentId, "permissions"=>permissions, "userArn"=>userArn), args)); aws=aws)

"""
    DeleteEnvironment()

Deletes an AWS Cloud9 development environment. If an Amazon EC2 instance is connected to the environment, also terminates the instance.

# Required Parameters
- `environmentId`: The ID of the environment to delete.

"""
DeleteEnvironment(environmentId; aws::AWSConfig=AWS.aws_config) = cloud9("DeleteEnvironment", Dict{String, Any}("environmentId"=>environmentId); aws=aws)
DeleteEnvironment(environmentId, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("DeleteEnvironment", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("environmentId"=>environmentId), args)); aws=aws)

"""
    DeleteEnvironmentMembership()

Deletes an environment member from an AWS Cloud9 development environment.

# Required Parameters
- `environmentId`: The ID of the environment to delete the environment member from.
- `userArn`: The Amazon Resource Name (ARN) of the environment member to delete from the environment.

"""
DeleteEnvironmentMembership(environmentId, userArn; aws::AWSConfig=AWS.aws_config) = cloud9("DeleteEnvironmentMembership", Dict{String, Any}("environmentId"=>environmentId, "userArn"=>userArn); aws=aws)
DeleteEnvironmentMembership(environmentId, userArn, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("DeleteEnvironmentMembership", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("environmentId"=>environmentId, "userArn"=>userArn), args)); aws=aws)

"""
    DescribeEnvironmentMemberships()

Gets information about environment members for an AWS Cloud9 development environment.

# Optional Parameters
- `environmentId`: The ID of the environment to get environment member information about.
- `maxResults`: The maximum number of environment members to get information about.
- `nextToken`: During a previous call, if there are more than 25 items in the list, only the first 25 items are returned, along with a unique string called a next token. To get the next batch of items in the list, call this operation again, adding the next token to the call. To get all of the items in the list, keep calling this operation with each subsequent next token that is returned, until no more next tokens are returned.
- `permissions`: The type of environment member permissions to get information about. Available values include:    owner: Owns the environment.    read-only: Has read-only access to the environment.    read-write: Has read-write access to the environment.   If no value is specified, information about all environment members are returned.
- `userArn`: The Amazon Resource Name (ARN) of an individual environment member to get information about. If no value is specified, information about all environment members are returned.
"""
DescribeEnvironmentMemberships(; aws::AWSConfig=AWS.aws_config) = cloud9("DescribeEnvironmentMemberships"; aws=aws)
DescribeEnvironmentMemberships(args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("DescribeEnvironmentMemberships", args; aws=aws)

"""
    DescribeEnvironmentStatus()

Gets status information for an AWS Cloud9 development environment.

# Required Parameters
- `environmentId`: The ID of the environment to get status information about.

"""
DescribeEnvironmentStatus(environmentId; aws::AWSConfig=AWS.aws_config) = cloud9("DescribeEnvironmentStatus", Dict{String, Any}("environmentId"=>environmentId); aws=aws)
DescribeEnvironmentStatus(environmentId, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("DescribeEnvironmentStatus", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("environmentId"=>environmentId), args)); aws=aws)

"""
    DescribeEnvironments()

Gets information about AWS Cloud9 development environments.

# Required Parameters
- `environmentIds`: The IDs of individual environments to get information about.

"""
DescribeEnvironments(environmentIds; aws::AWSConfig=AWS.aws_config) = cloud9("DescribeEnvironments", Dict{String, Any}("environmentIds"=>environmentIds); aws=aws)
DescribeEnvironments(environmentIds, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("DescribeEnvironments", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("environmentIds"=>environmentIds), args)); aws=aws)

"""
    ListEnvironments()

Gets a list of AWS Cloud9 development environment identifiers.

# Optional Parameters
- `maxResults`: The maximum number of environments to get identifiers for.
- `nextToken`: During a previous call, if there are more than 25 items in the list, only the first 25 items are returned, along with a unique string called a next token. To get the next batch of items in the list, call this operation again, adding the next token to the call. To get all of the items in the list, keep calling this operation with each subsequent next token that is returned, until no more next tokens are returned.
"""
ListEnvironments(; aws::AWSConfig=AWS.aws_config) = cloud9("ListEnvironments"; aws=aws)
ListEnvironments(args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("ListEnvironments", args; aws=aws)

"""
    ListTagsForResource()

Gets a list of the tags associated with an AWS Cloud9 development environment.

# Required Parameters
- `ResourceARN`: The Amazon Resource Name (ARN) of the AWS Cloud9 development environment to get the tags for.

"""
ListTagsForResource(ResourceARN; aws::AWSConfig=AWS.aws_config) = cloud9("ListTagsForResource", Dict{String, Any}("ResourceARN"=>ResourceARN); aws=aws)
ListTagsForResource(ResourceARN, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("ListTagsForResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResourceARN"=>ResourceARN), args)); aws=aws)

"""
    TagResource()

Adds tags to an AWS Cloud9 development environment.  Tags that you add to an AWS Cloud9 environment by using this method will NOT be automatically propagated to underlying resources. 

# Required Parameters
- `ResourceARN`: The Amazon Resource Name (ARN) of the AWS Cloud9 development environment to add tags to.
- `Tags`: The list of tags to add to the given AWS Cloud9 development environment.

"""
TagResource(ResourceARN, Tags; aws::AWSConfig=AWS.aws_config) = cloud9("TagResource", Dict{String, Any}("ResourceARN"=>ResourceARN, "Tags"=>Tags); aws=aws)
TagResource(ResourceARN, Tags, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("TagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResourceARN"=>ResourceARN, "Tags"=>Tags), args)); aws=aws)

"""
    UntagResource()

Removes tags from an AWS Cloud9 development environment.

# Required Parameters
- `ResourceARN`: The Amazon Resource Name (ARN) of the AWS Cloud9 development environment to remove tags from.
- `TagKeys`: The tag names of the tags to remove from the given AWS Cloud9 development environment.

"""
UntagResource(ResourceARN, TagKeys; aws::AWSConfig=AWS.aws_config) = cloud9("UntagResource", Dict{String, Any}("ResourceARN"=>ResourceARN, "TagKeys"=>TagKeys); aws=aws)
UntagResource(ResourceARN, TagKeys, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("UntagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResourceARN"=>ResourceARN, "TagKeys"=>TagKeys), args)); aws=aws)

"""
    UpdateEnvironment()

Changes the settings of an existing AWS Cloud9 development environment.

# Required Parameters
- `environmentId`: The ID of the environment to change settings.

# Optional Parameters
- `description`: Any new or replacement description for the environment.
- `name`: A replacement name for the environment.
"""
UpdateEnvironment(environmentId; aws::AWSConfig=AWS.aws_config) = cloud9("UpdateEnvironment", Dict{String, Any}("environmentId"=>environmentId); aws=aws)
UpdateEnvironment(environmentId, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("UpdateEnvironment", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("environmentId"=>environmentId), args)); aws=aws)

"""
    UpdateEnvironmentMembership()

Changes the settings of an existing environment member for an AWS Cloud9 development environment.

# Required Parameters
- `environmentId`: The ID of the environment for the environment member whose settings you want to change.
- `permissions`: The replacement type of environment member permissions you want to associate with this environment member. Available values include:    read-only: Has read-only access to the environment.    read-write: Has read-write access to the environment.  
- `userArn`: The Amazon Resource Name (ARN) of the environment member whose settings you want to change.

"""
UpdateEnvironmentMembership(environmentId, permissions, userArn; aws::AWSConfig=AWS.aws_config) = cloud9("UpdateEnvironmentMembership", Dict{String, Any}("environmentId"=>environmentId, "permissions"=>permissions, "userArn"=>userArn); aws=aws)
UpdateEnvironmentMembership(environmentId, permissions, userArn, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = cloud9("UpdateEnvironmentMembership", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("environmentId"=>environmentId, "permissions"=>permissions, "userArn"=>userArn), args)); aws=aws)
