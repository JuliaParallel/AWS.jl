# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
using Compat
using .AWSServices: resource_groups

"""
    CreateGroup()

Creates a group with a specified name, description, and resource query.

Required Parameters
Name => The name of the group, which is the identifier of the group in other operations. A resource group name cannot be updated after it is created. A resource group name can have a maximum of 128 characters, including letters, numbers, hyphens, dots, and underscores. The name cannot start with AWS or aws; these are reserved. A resource group name must be unique within your account.
ResourceQuery => The resource query that determines which AWS resources are members of this group.

Optional Parameters
Description => The description of the resource group. Descriptions can have a maximum of 511 characters, including letters, numbers, hyphens, underscores, punctuation, and spaces.
Tags => The tags to add to the group. A tag is a string-to-string map of key-value pairs. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.
"""
CreateGroup(Name, ResourceQuery) = resource_groups("POST", "/groups", Dict{String, Any}("Name"=>Name, "ResourceQuery"=>ResourceQuery))
CreateGroup(Name, ResourceQuery, args::AbstractDict{String, <: Any}) = resource_groups("POST", "/groups", Dict{String, Any}("Name"=>Name, "ResourceQuery"=>ResourceQuery, args...))
CreateGroup(a...; b...) = CreateGroup(a..., b)

"""
    DeleteGroup()

Deletes a specified resource group. Deleting a resource group does not delete resources that are members of the group; it only deletes the group structure.

Required Parameters
GroupName => The name of the resource group to delete.

"""
DeleteGroup(GroupName) = resource_groups("DELETE", "/groups/$(GroupName)")
DeleteGroup(GroupName, args::AbstractDict{String, <: Any}) = resource_groups("DELETE", "/groups/$(GroupName)", args)
DeleteGroup(a...; b...) = DeleteGroup(a..., b)

"""
    GetGroup()

Returns information about a specified resource group.

Required Parameters
GroupName => The name of the resource group.

"""
GetGroup(GroupName) = resource_groups("GET", "/groups/$(GroupName)")
GetGroup(GroupName, args::AbstractDict{String, <: Any}) = resource_groups("GET", "/groups/$(GroupName)", args)
GetGroup(a...; b...) = GetGroup(a..., b)

"""
    GetGroupQuery()

Returns the resource query associated with the specified resource group.

Required Parameters
GroupName => The name of the resource group.

"""
GetGroupQuery(GroupName) = resource_groups("GET", "/groups/$(GroupName)/query")
GetGroupQuery(GroupName, args::AbstractDict{String, <: Any}) = resource_groups("GET", "/groups/$(GroupName)/query", args)
GetGroupQuery(a...; b...) = GetGroupQuery(a..., b)

"""
    GetTags()

Returns a list of tags that are associated with a resource group, specified by an ARN.

Required Parameters
Arn => The ARN of the resource group for which you want a list of tags. The resource must exist within the account you are using.

"""
GetTags(Arn) = resource_groups("GET", "/resources/$(Arn)/tags")
GetTags(Arn, args::AbstractDict{String, <: Any}) = resource_groups("GET", "/resources/$(Arn)/tags", args)
GetTags(a...; b...) = GetTags(a..., b)

"""
    ListGroupResources()

Returns a list of ARNs of resources that are members of a specified resource group.

Required Parameters
GroupName => The name of the resource group.

Optional Parameters
Filters => Filters, formatted as ResourceFilter objects, that you want to apply to a ListGroupResources operation.    resource-type - Filter resources by their type. Specify up to five resource types in the format AWS::ServiceCode::ResourceType. For example, AWS::EC2::Instance, or AWS::S3::Bucket.  
maxResults => The maximum number of group member ARNs that are returned in a single call by ListGroupResources, in paginated output. By default, this number is 50.
nextToken => The NextToken value that is returned in a paginated ListGroupResources request. To get the next page of results, run the call again, add the NextToken parameter, and specify the NextToken value.
"""
ListGroupResources(GroupName) = resource_groups("POST", "/groups/$(GroupName)/resource-identifiers-list")
ListGroupResources(GroupName, args::AbstractDict{String, <: Any}) = resource_groups("POST", "/groups/$(GroupName)/resource-identifiers-list", args)
ListGroupResources(a...; b...) = ListGroupResources(a..., b)

"""
    ListGroups()

Returns a list of existing resource groups in your account.

Optional Parameters
Filters => Filters, formatted as GroupFilter objects, that you want to apply to a ListGroups operation.    resource-type - Filter groups by resource type. Specify up to five resource types in the format AWS::ServiceCode::ResourceType. For example, AWS::EC2::Instance, or AWS::S3::Bucket.  
maxResults => The maximum number of resource group results that are returned by ListGroups in paginated output. By default, this number is 50.
nextToken => The NextToken value that is returned in a paginated ListGroups request. To get the next page of results, run the call again, add the NextToken parameter, and specify the NextToken value.
"""
ListGroups() = resource_groups("POST", "/groups-list")
ListGroups(args::AbstractDict{String, Any}) = resource_groups("POST", "/groups-list", args)
ListGroups(a...; b...) = ListGroups(a..., b)

"""
    SearchResources()

Returns a list of AWS resource identifiers that matches a specified query. The query uses the same format as a resource query in a CreateGroup or UpdateGroupQuery operation.

Required Parameters
ResourceQuery => The search query, using the same formats that are supported for resource group definition.

Optional Parameters
MaxResults => The maximum number of group member ARNs returned by SearchResources in paginated output. By default, this number is 50.
NextToken => The NextToken value that is returned in a paginated SearchResources request. To get the next page of results, run the call again, add the NextToken parameter, and specify the NextToken value.
"""
SearchResources(ResourceQuery) = resource_groups("POST", "/resources/search", Dict{String, Any}("ResourceQuery"=>ResourceQuery))
SearchResources(ResourceQuery, args::AbstractDict{String, <: Any}) = resource_groups("POST", "/resources/search", Dict{String, Any}("ResourceQuery"=>ResourceQuery, args...))
SearchResources(a...; b...) = SearchResources(a..., b)

"""
    Tag()

Adds tags to a resource group with the specified ARN. Existing tags on a resource group are not changed if they are not specified in the request parameters.

Required Parameters
Arn => The ARN of the resource to which to add tags.
Tags => The tags to add to the specified resource. A tag is a string-to-string map of key-value pairs. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

"""
Tag(Arn, Tags) = resource_groups("PUT", "/resources/$(Arn)/tags", Dict{String, Any}("Tags"=>Tags))
Tag(Arn, Tags, args::AbstractDict{String, <: Any}) = resource_groups("PUT", "/resources/$(Arn)/tags", Dict{String, Any}("Tags"=>Tags, args...))
Tag(a...; b...) = Tag(a..., b)

"""
    Untag()

Deletes specified tags from a specified resource.

Required Parameters
Arn => The ARN of the resource from which to remove tags.
Keys => The keys of the tags to be removed.

"""
Untag(Arn, Keys) = resource_groups("PATCH", "/resources/$(Arn)/tags", Dict{String, Any}("Keys"=>Keys))
Untag(Arn, Keys, args::AbstractDict{String, <: Any}) = resource_groups("PATCH", "/resources/$(Arn)/tags", Dict{String, Any}("Keys"=>Keys, args...))
Untag(a...; b...) = Untag(a..., b)

"""
    UpdateGroup()

Updates an existing group with a new or changed description. You cannot update the name of a resource group.

Required Parameters
GroupName => The name of the resource group for which you want to update its description.

Optional Parameters
Description => The description of the resource group. Descriptions can have a maximum of 511 characters, including letters, numbers, hyphens, underscores, punctuation, and spaces.
"""
UpdateGroup(GroupName) = resource_groups("PUT", "/groups/$(GroupName)")
UpdateGroup(GroupName, args::AbstractDict{String, <: Any}) = resource_groups("PUT", "/groups/$(GroupName)", args)
UpdateGroup(a...; b...) = UpdateGroup(a..., b)

"""
    UpdateGroupQuery()

Updates the resource query of a group.

Required Parameters
GroupName => The name of the resource group for which you want to edit the query.
ResourceQuery => The resource query that determines which AWS resources are members of the resource group.

"""
UpdateGroupQuery(GroupName, ResourceQuery) = resource_groups("PUT", "/groups/$(GroupName)/query", Dict{String, Any}("ResourceQuery"=>ResourceQuery))
UpdateGroupQuery(GroupName, ResourceQuery, args::AbstractDict{String, <: Any}) = resource_groups("PUT", "/groups/$(GroupName)/query", Dict{String, Any}("ResourceQuery"=>ResourceQuery, args...))
UpdateGroupQuery(a...; b...) = UpdateGroupQuery(a..., b)
