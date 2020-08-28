# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: iot_1click_devices_service

using Compat
using UUIDs
"""
    ClaimDevicesByClaimCode()

Adds device(s) to your account (i.e., claim one or more devices) if and only if you
 received a claim code with the device(s).

# Required Parameters
- `claimCode`: The claim code, starting with \"C-\", as provided by the device manufacturer.

"""

claim_devices_by_claim_code(claimCode; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/claims/$(claimCode)"; aws_config=aws_config)
claim_devices_by_claim_code(claimCode, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/claims/$(claimCode)", args; aws_config=aws_config)

"""
    DescribeDevice()

Given a device ID, returns a DescribeDeviceResponse object describing the
 details of the device.

# Required Parameters
- `deviceId`: The unique identifier of the device.

"""

describe_device(deviceId; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices/$(deviceId)"; aws_config=aws_config)
describe_device(deviceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices/$(deviceId)", args; aws_config=aws_config)

"""
    FinalizeDeviceClaim()

Given a device ID, finalizes the claim request for the associated device.
 Claiming a device consists of initiating a claim, then publishing a device event,
 and finalizing the claim. For a device of type button, a device event can
 be published by simply clicking the device.
 

# Required Parameters
- `deviceId`: The unique identifier of the device.

# Optional Parameters
- `tags`: A collection of key/value pairs defining the resource tags. For example, {
 \"tags\": {\"key1\": \"value1\", \"key2\": \"value2\"} }. For more information, see AWS
 Tagging Strategies.
 
 
"""

finalize_device_claim(deviceId; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/finalize-claim"; aws_config=aws_config)
finalize_device_claim(deviceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/finalize-claim", args; aws_config=aws_config)

"""
    GetDeviceMethods()

Given a device ID, returns the invokable methods associated with the device.

# Required Parameters
- `deviceId`: The unique identifier of the device.

"""

get_device_methods(deviceId; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices/$(deviceId)/methods"; aws_config=aws_config)
get_device_methods(deviceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices/$(deviceId)/methods", args; aws_config=aws_config)

"""
    InitiateDeviceClaim()

Given a device ID, initiates a claim request for the associated device.
 Claiming a device consists of initiating a claim, then publishing a device event,
 and finalizing the claim. For a device of type button, a device event can
 be published by simply clicking the device.
 

# Required Parameters
- `deviceId`: The unique identifier of the device.

"""

initiate_device_claim(deviceId; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/initiate-claim"; aws_config=aws_config)
initiate_device_claim(deviceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/initiate-claim", args; aws_config=aws_config)

"""
    InvokeDeviceMethod()

Given a device ID, issues a request to invoke a named device method (with possible
 parameters). See the \"Example POST\" code snippet below.

# Required Parameters
- `deviceId`: The unique identifier of the device.

# Optional Parameters
- `deviceMethod`: The device method to invoke.
- `deviceMethodParameters`: A JSON encoded string containing the device method request parameters.
"""

invoke_device_method(deviceId; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("POST", "/devices/$(deviceId)/methods"; aws_config=aws_config)
invoke_device_method(deviceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("POST", "/devices/$(deviceId)/methods", args; aws_config=aws_config)

"""
    ListDeviceEvents()

Using a device ID, returns a DeviceEventsResponse object containing an
 array of events for the device.

# Required Parameters
- `deviceId`: The unique identifier of the device.
- `fromTimeStamp`: The start date for the device event query, in ISO8061 format. For example,
 2018-03-28T15:45:12.880Z
 
- `toTimeStamp`: The end date for the device event query, in ISO8061 format. For example,
 2018-03-28T15:45:12.880Z
 

# Optional Parameters
- `maxResults`: The maximum number of results to return per request. If not set, a default value of
 100 is used.
- `nextToken`: The token to retrieve the next set of results.
"""

list_device_events(deviceId, fromTimeStamp, toTimeStamp; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices/$(deviceId)/events", Dict{String, Any}("fromTimeStamp"=>fromTimeStamp, "toTimeStamp"=>toTimeStamp); aws_config=aws_config)
list_device_events(deviceId, fromTimeStamp, toTimeStamp, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices/$(deviceId)/events", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("fromTimeStamp"=>fromTimeStamp, "toTimeStamp"=>toTimeStamp), args)); aws_config=aws_config)

"""
    ListDevices()

Lists the 1-Click compatible devices associated with your AWS account.

# Optional Parameters
- `deviceType`: The type of the device, such as \"button\".
- `maxResults`: The maximum number of results to return per request. If not set, a default value of
 100 is used.
- `nextToken`: The token to retrieve the next set of results.
"""

list_devices(; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices"; aws_config=aws_config)
list_devices(args::AbstractDict{String, Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/devices", args; aws_config=aws_config)

"""
    ListTagsForResource()

Lists the tags associated with the specified resource ARN.

# Required Parameters
- `resource-arn`: The ARN of the resource.

"""

list_tags_for_resource(resource_arn; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/tags/$(resource-arn)"; aws_config=aws_config)
list_tags_for_resource(resource_arn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("GET", "/tags/$(resource-arn)", args; aws_config=aws_config)

"""
    TagResource()

Adds or updates the tags associated with the resource ARN. See AWS IoT 1-Click Service Limits for the maximum number of tags allowed per
 resource.

# Required Parameters
- `resource-arn`: The ARN of the resource.
- `tags`: A collection of key/value pairs defining the resource tags. For example, {
 \"tags\": {\"key1\": \"value1\", \"key2\": \"value2\"} }. For more information, see AWS
 Tagging Strategies.
 
 

"""

tag_resource(resource_arn, tags; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("POST", "/tags/$(resource-arn)", Dict{String, Any}("tags"=>tags); aws_config=aws_config)
tag_resource(resource_arn, tags, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("POST", "/tags/$(resource-arn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tags"=>tags), args)); aws_config=aws_config)

"""
    UnclaimDevice()

Disassociates a device from your AWS account using its device ID.

# Required Parameters
- `deviceId`: The unique identifier of the device.

"""

unclaim_device(deviceId; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/unclaim"; aws_config=aws_config)
unclaim_device(deviceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/unclaim", args; aws_config=aws_config)

"""
    UntagResource()

Using tag keys, deletes the tags (key/value pairs) associated with the specified
 resource ARN.

# Required Parameters
- `resource-arn`: The ARN of the resource.
- `tagKeys`: A collections of tag keys. For example, {\"key1\",\"key2\"}

"""

untag_resource(resource_arn, tagKeys; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("DELETE", "/tags/$(resource-arn)", Dict{String, Any}("tagKeys"=>tagKeys); aws_config=aws_config)
untag_resource(resource_arn, tagKeys, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("DELETE", "/tags/$(resource-arn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tagKeys"=>tagKeys), args)); aws_config=aws_config)

"""
    UpdateDeviceState()

Using a Boolean value (true or false), this operation
 enables or disables the device given a device ID.

# Required Parameters
- `deviceId`: The unique identifier of the device.

# Optional Parameters
- `enabled`: If true, the device is enabled. If false, the device is
 disabled.
"""

update_device_state(deviceId; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/state"; aws_config=aws_config)
update_device_state(deviceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = iot_1click_devices_service("PUT", "/devices/$(deviceId)/state", args; aws_config=aws_config)
