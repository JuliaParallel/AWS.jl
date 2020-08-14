# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: iotsecuretunneling

using Compat
using UUIDs
"""
    CloseTunnel()

Closes a tunnel identified by the unique tunnel id. When a CloseTunnel request is received, we close the WebSocket connections between the client and proxy server so no data can be transmitted.

# Required Parameters
- `tunnelId`: The ID of the tunnel to close.

# Optional Parameters
- `delete`: When set to true, AWS IoT Secure Tunneling deletes the tunnel data immediately.
"""
CloseTunnel(tunnelId; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("CloseTunnel", Dict{String, Any}("tunnelId"=>tunnelId); aws=aws)
CloseTunnel(tunnelId, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("CloseTunnel", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tunnelId"=>tunnelId), args)); aws=aws)

"""
    DescribeTunnel()

Gets information about a tunnel identified by the unique tunnel id.

# Required Parameters
- `tunnelId`: The tunnel to describe.

"""
DescribeTunnel(tunnelId; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("DescribeTunnel", Dict{String, Any}("tunnelId"=>tunnelId); aws=aws)
DescribeTunnel(tunnelId, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("DescribeTunnel", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tunnelId"=>tunnelId), args)); aws=aws)

"""
    ListTagsForResource()

Lists the tags for the specified resource.

# Required Parameters
- `resourceArn`: The resource ARN.

"""
ListTagsForResource(resourceArn; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("ListTagsForResource", Dict{String, Any}("resourceArn"=>resourceArn); aws=aws)
ListTagsForResource(resourceArn, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("ListTagsForResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("resourceArn"=>resourceArn), args)); aws=aws)

"""
    ListTunnels()

List all tunnels for an AWS account. Tunnels are listed by creation time in descending order, newer tunnels will be listed before older tunnels.

# Optional Parameters
- `maxResults`: The maximum number of results to return at once.
- `nextToken`: A token to retrieve the next set of results.
- `thingName`: The name of the IoT thing associated with the destination device.
"""
ListTunnels(; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("ListTunnels"; aws=aws)
ListTunnels(args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("ListTunnels", args; aws=aws)

"""
    OpenTunnel()

Creates a new tunnel, and returns two client access tokens for clients to use to connect to the AWS IoT Secure Tunneling proxy server. .

# Optional Parameters
- `description`: A short text description of the tunnel. 
- `destinationConfig`: The destination configuration for the OpenTunnel request.
- `tags`: A collection of tag metadata.
- `timeoutConfig`: Timeout configuration for a tunnel.
"""
OpenTunnel(; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("OpenTunnel"; aws=aws)
OpenTunnel(args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("OpenTunnel", args; aws=aws)

"""
    TagResource()

A resource tag.

# Required Parameters
- `resourceArn`: The ARN of the resource.
- `tags`: The tags for the resource.

"""
TagResource(resourceArn, tags; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("TagResource", Dict{String, Any}("resourceArn"=>resourceArn, "tags"=>tags); aws=aws)
TagResource(resourceArn, tags, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("TagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("resourceArn"=>resourceArn, "tags"=>tags), args)); aws=aws)

"""
    UntagResource()

Removes a tag from a resource.

# Required Parameters
- `resourceArn`: The resource ARN.
- `tagKeys`: The keys of the tags to remove.

"""
UntagResource(resourceArn, tagKeys; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("UntagResource", Dict{String, Any}("resourceArn"=>resourceArn, "tagKeys"=>tagKeys); aws=aws)
UntagResource(resourceArn, tagKeys, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = iotsecuretunneling("UntagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("resourceArn"=>resourceArn, "tagKeys"=>tagKeys), args)); aws=aws)
