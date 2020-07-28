# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
include("_utilities.jl")
using Compat
using UUIDs
using .AWSServices: codestar

"""
    AssociateTeamMember()

Adds an IAM user to the team for an AWS CodeStar project.

# Required Parameters
- `projectId`: The ID of the project to which you will add the IAM user.
- `projectRole`: The AWS CodeStar project role that will apply to this user. This role determines what actions a user can take in an AWS CodeStar project.
- `userArn`: The Amazon Resource Name (ARN) for the IAM user you want to add to the AWS CodeStar project.

# Optional Parameters
- `clientRequestToken`: A user- or system-generated token that identifies the entity that requested the team member association to the project. This token can be used to repeat the request.
- `remoteAccessAllowed`: Whether the team member is allowed to use an SSH public/private key pair to remotely access project resources, for example Amazon EC2 instances.
"""
AssociateTeamMember(projectId, projectRole, userArn) = codestar("AssociateTeamMember", Dict{String, Any}("projectId"=>projectId, "projectRole"=>projectRole, "userArn"=>userArn))
AssociateTeamMember(projectId, projectRole, userArn, args::AbstractDict{String, <:Any}) = codestar("AssociateTeamMember", Dict{String, Any}("projectId"=>projectId, "projectRole"=>projectRole, "userArn"=>userArn, args...))

"""
    CreateProject()

Creates a project, including project resources. This action creates a project based on a submitted project request. A set of source code files and a toolchain template file can be included with the project request. If these are not provided, an empty project is created.

# Required Parameters
- `id`: The ID of the project to be created in AWS CodeStar.
- `name`: The display name for the project to be created in AWS CodeStar.

# Optional Parameters
- `clientRequestToken`: A user- or system-generated token that identifies the entity that requested project creation. This token can be used to repeat the request.
- `description`: The description of the project, if any.
- `sourceCode`: A list of the Code objects submitted with the project request. If this parameter is specified, the request must also include the toolchain parameter.
- `tags`: The tags created for the project.
- `toolchain`: The name of the toolchain template file submitted with the project request. If this parameter is specified, the request must also include the sourceCode parameter.
"""
CreateProject(id, name) = codestar("CreateProject", Dict{String, Any}("id"=>id, "name"=>name))
CreateProject(id, name, args::AbstractDict{String, <:Any}) = codestar("CreateProject", Dict{String, Any}("id"=>id, "name"=>name, args...))

"""
    CreateUserProfile()

Creates a profile for a user that includes user preferences, such as the display name and email address assocciated with the user, in AWS CodeStar. The user profile is not project-specific. Information in the user profile is displayed wherever the user's information appears to other users in AWS CodeStar.

# Required Parameters
- `displayName`: The name that will be displayed as the friendly name for the user in AWS CodeStar. 
- `emailAddress`: The email address that will be displayed as part of the user's profile in AWS CodeStar.
- `userArn`: The Amazon Resource Name (ARN) of the user in IAM.

# Optional Parameters
- `sshPublicKey`: The SSH public key associated with the user in AWS CodeStar. If a project owner allows the user remote access to project resources, this public key will be used along with the user's private key for SSH access.
"""
CreateUserProfile(displayName, emailAddress, userArn) = codestar("CreateUserProfile", Dict{String, Any}("displayName"=>displayName, "emailAddress"=>emailAddress, "userArn"=>userArn))
CreateUserProfile(displayName, emailAddress, userArn, args::AbstractDict{String, <:Any}) = codestar("CreateUserProfile", Dict{String, Any}("displayName"=>displayName, "emailAddress"=>emailAddress, "userArn"=>userArn, args...))

"""
    DeleteProject()

Deletes a project, including project resources. Does not delete users associated with the project, but does delete the IAM roles that allowed access to the project.

# Required Parameters
- `id`: The ID of the project to be deleted in AWS CodeStar.

# Optional Parameters
- `clientRequestToken`: A user- or system-generated token that identifies the entity that requested project deletion. This token can be used to repeat the request. 
- `deleteStack`: Whether to send a delete request for the primary stack in AWS CloudFormation originally used to generate the project and its resources. This option will delete all AWS resources for the project (except for any buckets in Amazon S3) as well as deleting the project itself. Recommended for most use cases.
"""
DeleteProject(id) = codestar("DeleteProject", Dict{String, Any}("id"=>id))
DeleteProject(id, args::AbstractDict{String, <:Any}) = codestar("DeleteProject", Dict{String, Any}("id"=>id, args...))

"""
    DeleteUserProfile()

Deletes a user profile in AWS CodeStar, including all personal preference data associated with that profile, such as display name and email address. It does not delete the history of that user, for example the history of commits made by that user.

# Required Parameters
- `userArn`: The Amazon Resource Name (ARN) of the user to delete from AWS CodeStar.

"""
DeleteUserProfile(userArn) = codestar("DeleteUserProfile", Dict{String, Any}("userArn"=>userArn))
DeleteUserProfile(userArn, args::AbstractDict{String, <:Any}) = codestar("DeleteUserProfile", Dict{String, Any}("userArn"=>userArn, args...))

"""
    DescribeProject()

Describes a project and its resources.

# Required Parameters
- `id`: The ID of the project.

"""
DescribeProject(id) = codestar("DescribeProject", Dict{String, Any}("id"=>id))
DescribeProject(id, args::AbstractDict{String, <:Any}) = codestar("DescribeProject", Dict{String, Any}("id"=>id, args...))

"""
    DescribeUserProfile()

Describes a user in AWS CodeStar and the user attributes across all projects.

# Required Parameters
- `userArn`: The Amazon Resource Name (ARN) of the user.

"""
DescribeUserProfile(userArn) = codestar("DescribeUserProfile", Dict{String, Any}("userArn"=>userArn))
DescribeUserProfile(userArn, args::AbstractDict{String, <:Any}) = codestar("DescribeUserProfile", Dict{String, Any}("userArn"=>userArn, args...))

"""
    DisassociateTeamMember()

Removes a user from a project. Removing a user from a project also removes the IAM policies from that user that allowed access to the project and its resources. Disassociating a team member does not remove that user's profile from AWS CodeStar. It does not remove the user from IAM.

# Required Parameters
- `projectId`: The ID of the AWS CodeStar project from which you want to remove a team member.
- `userArn`: The Amazon Resource Name (ARN) of the IAM user or group whom you want to remove from the project.

"""
DisassociateTeamMember(projectId, userArn) = codestar("DisassociateTeamMember", Dict{String, Any}("projectId"=>projectId, "userArn"=>userArn))
DisassociateTeamMember(projectId, userArn, args::AbstractDict{String, <:Any}) = codestar("DisassociateTeamMember", Dict{String, Any}("projectId"=>projectId, "userArn"=>userArn, args...))

"""
    ListProjects()

Lists all projects in AWS CodeStar associated with your AWS account.

# Optional Parameters
- `maxResults`: The maximum amount of data that can be contained in a single set of results.
- `nextToken`: The continuation token to be used to return the next set of results, if the results cannot be returned in one response.
"""
ListProjects() = codestar("ListProjects")
ListProjects(args::AbstractDict{String, <:Any}) = codestar("ListProjects", args)

"""
    ListResources()

Lists resources associated with a project in AWS CodeStar.

# Required Parameters
- `projectId`: The ID of the project.

# Optional Parameters
- `maxResults`: The maximum amount of data that can be contained in a single set of results.
- `nextToken`: The continuation token for the next set of results, if the results cannot be returned in one response.
"""
ListResources(projectId) = codestar("ListResources", Dict{String, Any}("projectId"=>projectId))
ListResources(projectId, args::AbstractDict{String, <:Any}) = codestar("ListResources", Dict{String, Any}("projectId"=>projectId, args...))

"""
    ListTagsForProject()

Gets the tags for a project.

# Required Parameters
- `id`: The ID of the project to get tags for.

# Optional Parameters
- `maxResults`: Reserved for future use.
- `nextToken`: Reserved for future use.
"""
ListTagsForProject(id) = codestar("ListTagsForProject", Dict{String, Any}("id"=>id))
ListTagsForProject(id, args::AbstractDict{String, <:Any}) = codestar("ListTagsForProject", Dict{String, Any}("id"=>id, args...))

"""
    ListTeamMembers()

Lists all team members associated with a project.

# Required Parameters
- `projectId`: The ID of the project for which you want to list team members.

# Optional Parameters
- `maxResults`: The maximum number of team members you want returned in a response.
- `nextToken`: The continuation token for the next set of results, if the results cannot be returned in one response.
"""
ListTeamMembers(projectId) = codestar("ListTeamMembers", Dict{String, Any}("projectId"=>projectId))
ListTeamMembers(projectId, args::AbstractDict{String, <:Any}) = codestar("ListTeamMembers", Dict{String, Any}("projectId"=>projectId, args...))

"""
    ListUserProfiles()

Lists all the user profiles configured for your AWS account in AWS CodeStar.

# Optional Parameters
- `maxResults`: The maximum number of results to return in a response.
- `nextToken`: The continuation token for the next set of results, if the results cannot be returned in one response.
"""
ListUserProfiles() = codestar("ListUserProfiles")
ListUserProfiles(args::AbstractDict{String, <:Any}) = codestar("ListUserProfiles", args)

"""
    TagProject()

Adds tags to a project.

# Required Parameters
- `id`: The ID of the project you want to add a tag to.
- `tags`: The tags you want to add to the project.

"""
TagProject(id, tags) = codestar("TagProject", Dict{String, Any}("id"=>id, "tags"=>tags))
TagProject(id, tags, args::AbstractDict{String, <:Any}) = codestar("TagProject", Dict{String, Any}("id"=>id, "tags"=>tags, args...))

"""
    UntagProject()

Removes tags from a project.

# Required Parameters
- `id`: The ID of the project to remove tags from.
- `tags`: The tags to remove from the project.

"""
UntagProject(id, tags) = codestar("UntagProject", Dict{String, Any}("id"=>id, "tags"=>tags))
UntagProject(id, tags, args::AbstractDict{String, <:Any}) = codestar("UntagProject", Dict{String, Any}("id"=>id, "tags"=>tags, args...))

"""
    UpdateProject()

Updates a project in AWS CodeStar.

# Required Parameters
- `id`: The ID of the project you want to update.

# Optional Parameters
- `description`: The description of the project, if any.
- `name`: The name of the project you want to update.
"""
UpdateProject(id) = codestar("UpdateProject", Dict{String, Any}("id"=>id))
UpdateProject(id, args::AbstractDict{String, <:Any}) = codestar("UpdateProject", Dict{String, Any}("id"=>id, args...))

"""
    UpdateTeamMember()

Updates a team member's attributes in an AWS CodeStar project. For example, you can change a team member's role in the project, or change whether they have remote access to project resources.

# Required Parameters
- `projectId`: The ID of the project.
- `userArn`: The Amazon Resource Name (ARN) of the user for whom you want to change team membership attributes.

# Optional Parameters
- `projectRole`: The role assigned to the user in the project. Project roles have different levels of access. For more information, see Working with Teams in the AWS CodeStar User Guide.
- `remoteAccessAllowed`: Whether a team member is allowed to remotely access project resources using the SSH public key associated with the user's profile. Even if this is set to True, the user must associate a public key with their profile before the user can access resources.
"""
UpdateTeamMember(projectId, userArn) = codestar("UpdateTeamMember", Dict{String, Any}("projectId"=>projectId, "userArn"=>userArn))
UpdateTeamMember(projectId, userArn, args::AbstractDict{String, <:Any}) = codestar("UpdateTeamMember", Dict{String, Any}("projectId"=>projectId, "userArn"=>userArn, args...))

"""
    UpdateUserProfile()

Updates a user's profile in AWS CodeStar. The user profile is not project-specific. Information in the user profile is displayed wherever the user's information appears to other users in AWS CodeStar. 

# Required Parameters
- `userArn`: The name that will be displayed as the friendly name for the user in AWS CodeStar.

# Optional Parameters
- `displayName`: The name that is displayed as the friendly name for the user in AWS CodeStar.
- `emailAddress`: The email address that is displayed as part of the user's profile in AWS CodeStar.
- `sshPublicKey`: The SSH public key associated with the user in AWS CodeStar. If a project owner allows the user remote access to project resources, this public key will be used along with the user's private key for SSH access.
"""
UpdateUserProfile(userArn) = codestar("UpdateUserProfile", Dict{String, Any}("userArn"=>userArn))
UpdateUserProfile(userArn, args::AbstractDict{String, <:Any}) = codestar("UpdateUserProfile", Dict{String, Any}("userArn"=>userArn, args...))
