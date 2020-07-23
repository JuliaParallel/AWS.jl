# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
using Compat
using .AWSServices: ivs

"""
    BatchGetChannel()

Performs GetChannel on multiple ARNs simultaneously.

Required Parameters
arns => Array of ARNs, one per channel.

"""
BatchGetChannel(arns) = ivs("POST", "/BatchGetChannel", Dict{String, Any}("arns"=>arns))
BatchGetChannel(arns, args::AbstractDict{String, <: Any}) = ivs("POST", "/BatchGetChannel", Dict{String, Any}("arns"=>arns, args...))
BatchGetChannel(a...; b...) = BatchGetChannel(a..., b)

"""
    BatchGetStreamKey()

Performs GetStreamKey on multiple ARNs simultaneously.

Required Parameters
arns => Array of ARNs, one per channel.

"""
BatchGetStreamKey(arns) = ivs("POST", "/BatchGetStreamKey", Dict{String, Any}("arns"=>arns))
BatchGetStreamKey(arns, args::AbstractDict{String, <: Any}) = ivs("POST", "/BatchGetStreamKey", Dict{String, Any}("arns"=>arns, args...))
BatchGetStreamKey(a...; b...) = BatchGetStreamKey(a..., b)

"""
    CreateChannel()

Creates a new channel and an associated stream key to start streaming.

Optional Parameters
latencyMode => Channel latency mode. Default: LOW.
name => Channel name.
tags => See Channel tags.
type => Channel type, which determines the allowable resolution and bitrate. STANDARD: The stream is transcoded; resolution (width, in landscape orientation) can be up to 1080p or the input source resolution, whichever is lower; and bitrate can be up to 8.5 Mbps. BASIC: The stream is transfixed; resolution can be up to 480p; and bitrate can be up to 1.5 Mbps. Default: STANDARD.
"""
CreateChannel() = ivs("POST", "/CreateChannel")
CreateChannel(args::AbstractDict{String, Any}) = ivs("POST", "/CreateChannel", args)
CreateChannel(a...; b...) = CreateChannel(a..., b)

"""
    CreateStreamKey()

Creates a stream key, used to initiate a stream, for a specified channel ARN. Note that CreateChannel creates a stream key. If you subsequently use CreateStreamKey on the same channel, it will fail because a stream key already exists and there is a limit of 1 stream key per channel. To reset the stream key on a channel, use DeleteStreamKey and then CreateStreamKey.

Required Parameters
channelArn => ARN of the channel for which to create the stream key.

Optional Parameters
tags => See Channel tags.
"""
CreateStreamKey(channelArn) = ivs("POST", "/CreateStreamKey", Dict{String, Any}("channelArn"=>channelArn))
CreateStreamKey(channelArn, args::AbstractDict{String, <: Any}) = ivs("POST", "/CreateStreamKey", Dict{String, Any}("channelArn"=>channelArn, args...))
CreateStreamKey(a...; b...) = CreateStreamKey(a..., b)

"""
    DeleteChannel()

Deletes a specified channel and its associated stream keys.

Required Parameters
arn => ARN of the channel to be deleted.

"""
DeleteChannel(arn) = ivs("POST", "/DeleteChannel", Dict{String, Any}("arn"=>arn))
DeleteChannel(arn, args::AbstractDict{String, <: Any}) = ivs("POST", "/DeleteChannel", Dict{String, Any}("arn"=>arn, args...))
DeleteChannel(a...; b...) = DeleteChannel(a..., b)

"""
    DeleteStreamKey()

Deletes the stream key for a specified ARN, so it can no longer be used to stream.

Required Parameters
arn => ARN of the stream key to be deleted.

"""
DeleteStreamKey(arn) = ivs("POST", "/DeleteStreamKey", Dict{String, Any}("arn"=>arn))
DeleteStreamKey(arn, args::AbstractDict{String, <: Any}) = ivs("POST", "/DeleteStreamKey", Dict{String, Any}("arn"=>arn, args...))
DeleteStreamKey(a...; b...) = DeleteStreamKey(a..., b)

"""
    GetChannel()

Gets the channel configuration for a specified channel ARN. See also BatchGetChannel.

Required Parameters
arn => ARN of the channel for which the configuration is to be retrieved.

"""
GetChannel(arn) = ivs("POST", "/GetChannel", Dict{String, Any}("arn"=>arn))
GetChannel(arn, args::AbstractDict{String, <: Any}) = ivs("POST", "/GetChannel", Dict{String, Any}("arn"=>arn, args...))
GetChannel(a...; b...) = GetChannel(a..., b)

"""
    GetStream()

Gets information about the active (live) stream on a specified channel.

Required Parameters
channelArn => Channel ARN for stream to be accessed.

"""
GetStream(channelArn) = ivs("POST", "/GetStream", Dict{String, Any}("channelArn"=>channelArn))
GetStream(channelArn, args::AbstractDict{String, <: Any}) = ivs("POST", "/GetStream", Dict{String, Any}("channelArn"=>channelArn, args...))
GetStream(a...; b...) = GetStream(a..., b)

"""
    GetStreamKey()

Gets stream-key information for a specified ARN.

Required Parameters
arn => ARN for the stream key to be retrieved.

"""
GetStreamKey(arn) = ivs("POST", "/GetStreamKey", Dict{String, Any}("arn"=>arn))
GetStreamKey(arn, args::AbstractDict{String, <: Any}) = ivs("POST", "/GetStreamKey", Dict{String, Any}("arn"=>arn, args...))
GetStreamKey(a...; b...) = GetStreamKey(a..., b)

"""
    ListChannels()

Gets summary information about channels. This list can be filtered to match a specified string.

Optional Parameters
filterByName => Filters the channel list to match the specified name.
maxResults => Maximum number of channels to return.
nextToken => The first channel to retrieve. This is used for pagination; see the nextToken response field.
"""
ListChannels() = ivs("POST", "/ListChannels")
ListChannels(args::AbstractDict{String, Any}) = ivs("POST", "/ListChannels", args)
ListChannels(a...; b...) = ListChannels(a..., b)

"""
    ListStreamKeys()

Gets summary information about stream keys. The list can be filtered to a particular channel.

Required Parameters
channelArn => Channel ARN used to filter the list.

Optional Parameters
maxResults => Maximum number of streamKeys to return.
nextToken => The first stream key to retrieve. This is used for pagination; see the nextToken response field.
"""
ListStreamKeys(channelArn) = ivs("POST", "/ListStreamKeys", Dict{String, Any}("channelArn"=>channelArn))
ListStreamKeys(channelArn, args::AbstractDict{String, <: Any}) = ivs("POST", "/ListStreamKeys", Dict{String, Any}("channelArn"=>channelArn, args...))
ListStreamKeys(a...; b...) = ListStreamKeys(a..., b)

"""
    ListStreams()

Gets summary information about live streams.

Optional Parameters
maxResults => Maximum number of streams to return.
nextToken => The first stream to retrieve. This is used for pagination; see the nextToken response field.
"""
ListStreams() = ivs("POST", "/ListStreams")
ListStreams(args::AbstractDict{String, Any}) = ivs("POST", "/ListStreams", args)
ListStreams(a...; b...) = ListStreams(a..., b)

"""
    ListTagsForResource()

Gets information about the tags for a specified ARN.

Required Parameters
resourceArn => The ARN of the resource to be retrieved.

Optional Parameters
maxResults => Maximum number of tags to return.
nextToken => The first tag to retrieve. This is used for pagination; see the nextToken response field.
"""
ListTagsForResource(resourceArn) = ivs("GET", "/tags/$(resourceArn)")
ListTagsForResource(resourceArn, args::AbstractDict{String, <: Any}) = ivs("GET", "/tags/$(resourceArn)", args)
ListTagsForResource(a...; b...) = ListTagsForResource(a..., b)

"""
    PutMetadata()

Inserts metadata into an RTMP stream for a specified channel. A maximum of 5 requests per second per channel is allowed, each with a maximum 1KB payload.

Required Parameters
channelArn => ARN of the channel into which metadata is inserted. This channel must have an active stream.
metadata => Metadata to insert into the stream. Maximum: 1 KB per request.

"""
PutMetadata(channelArn, metadata) = ivs("POST", "/PutMetadata", Dict{String, Any}("channelArn"=>channelArn, "metadata"=>metadata))
PutMetadata(channelArn, metadata, args::AbstractDict{String, <: Any}) = ivs("POST", "/PutMetadata", Dict{String, Any}("channelArn"=>channelArn, "metadata"=>metadata, args...))
PutMetadata(a...; b...) = PutMetadata(a..., b)

"""
    StopStream()

Disconnects the stream for the specified channel. This disconnects the incoming RTMP stream from the client. Can be used in conjunction with DeleteStreamKey to prevent further streaming to a channel.  Many streaming client-software libraries automatically reconnect a dropped RTMP session, so to stop the stream permanently, you may want to first revoke the streamKey attached to the channel. 

Required Parameters
channelArn => ARN of the channel for which the stream is to be stopped.

"""
StopStream(channelArn) = ivs("POST", "/StopStream", Dict{String, Any}("channelArn"=>channelArn))
StopStream(channelArn, args::AbstractDict{String, <: Any}) = ivs("POST", "/StopStream", Dict{String, Any}("channelArn"=>channelArn, args...))
StopStream(a...; b...) = StopStream(a..., b)

"""
    TagResource()

Adds or updates tags for a resource with a specified ARN.

Required Parameters
resourceArn => ARN of the resource for which tags are to be added or updated.
tags => Array of tags to be added or updated.

"""
TagResource(resourceArn, tags) = ivs("POST", "/tags/$(resourceArn)", Dict{String, Any}("tags"=>tags))
TagResource(resourceArn, tags, args::AbstractDict{String, <: Any}) = ivs("POST", "/tags/$(resourceArn)", Dict{String, Any}("tags"=>tags, args...))
TagResource(a...; b...) = TagResource(a..., b)

"""
    UntagResource()

Removes tags for a resource with a specified ARN.

Required Parameters
resourceArn => ARN of the resource for which tags are to be removed.
tagKeys => Array of tags to be removed.

"""
UntagResource(resourceArn, tagKeys) = ivs("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys))
UntagResource(resourceArn, tagKeys, args::AbstractDict{String, <: Any}) = ivs("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys, args...))
UntagResource(a...; b...) = UntagResource(a..., b)

"""
    UpdateChannel()

Updates a channel's configuration. This does not affect an ongoing stream of this channel. You must stop and restart the stream for the changes to take effect.

Required Parameters
arn => ARN of the channel to be updated.

Optional Parameters
latencyMode => Channel latency mode. Default: LOW.
name => Channel name.
type => Channel type, which determines the allowable resolution and bitrate. STANDARD: The stream is transcoded; resolution (width, in landscape orientation) can be up to 1080p or the input source resolution, whichever is lower; and bitrate can be up to 8.5 Mbps. BASIC: The stream is transfixed; resolution can be up to 480p; and bitrate can be up to 1.5 Mbps. Default STANDARD.
"""
UpdateChannel(arn) = ivs("POST", "/UpdateChannel", Dict{String, Any}("arn"=>arn))
UpdateChannel(arn, args::AbstractDict{String, <: Any}) = ivs("POST", "/UpdateChannel", Dict{String, Any}("arn"=>arn, args...))
UpdateChannel(a...; b...) = UpdateChannel(a..., b)
