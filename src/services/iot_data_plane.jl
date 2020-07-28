# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
include("_utilities.jl")
using Compat
using UUIDs
using .AWSServices: iot_data_plane

"""
    DeleteThingShadow()

Deletes the shadow for the specified thing. For more information, see DeleteThingShadow in the AWS IoT Developer Guide.

# Required Parameters
- `thingName`: The name of the thing.

# Optional Parameters
- `name`: The name of the shadow.
"""
DeleteThingShadow(thingName) = iot_data_plane("DELETE", "/things/$(thingName)/shadow")
DeleteThingShadow(thingName, args::AbstractDict{String, <:Any}) = iot_data_plane("DELETE", "/things/$(thingName)/shadow", args)

"""
    GetThingShadow()

Gets the shadow for the specified thing. For more information, see GetThingShadow in the AWS IoT Developer Guide.

# Required Parameters
- `thingName`: The name of the thing.

# Optional Parameters
- `name`: The name of the shadow.
"""
GetThingShadow(thingName) = iot_data_plane("GET", "/things/$(thingName)/shadow")
GetThingShadow(thingName, args::AbstractDict{String, <:Any}) = iot_data_plane("GET", "/things/$(thingName)/shadow", args)

"""
    ListNamedShadowsForThing()

Lists the shadows for the specified thing.

# Required Parameters
- `thingName`: The name of the thing.

# Optional Parameters
- `nextToken`: The token to retrieve the next set of results.
- `pageSize`: The result page size.
"""
ListNamedShadowsForThing(thingName) = iot_data_plane("GET", "/api/things/shadow/ListNamedShadowsForThing/$(thingName)")
ListNamedShadowsForThing(thingName, args::AbstractDict{String, <:Any}) = iot_data_plane("GET", "/api/things/shadow/ListNamedShadowsForThing/$(thingName)", args)

"""
    Publish()

Publishes state information. For more information, see HTTP Protocol in the AWS IoT Developer Guide.

# Required Parameters
- `topic`: The name of the MQTT topic.

# Optional Parameters
- `payload`: The state information, in JSON format.
- `qos`: The Quality of Service (QoS) level.
"""
Publish(topic) = iot_data_plane("POST", "/topics/$(topic)")
Publish(topic, args::AbstractDict{String, <:Any}) = iot_data_plane("POST", "/topics/$(topic)", args)

"""
    UpdateThingShadow()

Updates the shadow for the specified thing. For more information, see UpdateThingShadow in the AWS IoT Developer Guide.

# Required Parameters
- `payload`: The state information, in JSON format.
- `thingName`: The name of the thing.

# Optional Parameters
- `name`: The name of the shadow.
"""
UpdateThingShadow(payload, thingName) = iot_data_plane("POST", "/things/$(thingName)/shadow", Dict{String, Any}("payload"=>payload))
UpdateThingShadow(payload, thingName, args::AbstractDict{String, <:Any}) = iot_data_plane("POST", "/things/$(thingName)/shadow", Dict{String, Any}("payload"=>payload, args...))
