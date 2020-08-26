# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: personalize_events

using Compat
using UUIDs
"""
    PutEvents()

Records user interaction event data. For more information see event-record-api.

# Required Parameters
- `eventList`: A list of event data from the session.
- `sessionId`: The session ID associated with the user's visit. Your application generates the sessionId when a user first visits your website or uses your application. Amazon Personalize uses the sessionId to associate events with the user before they log in. For more information see event-record-api.
- `trackingId`: The tracking ID for the event. The ID is generated by a call to the CreateEventTracker API.

# Optional Parameters
- `userId`: The user associated with the event.
"""

put_events(eventList, sessionId, trackingId; aws_config::AWSConfig=global_aws_config()) = personalize_events("POST", "/events", Dict{String, Any}("eventList"=>eventList, "sessionId"=>sessionId, "trackingId"=>trackingId); aws_config=aws_config)
put_events(eventList, sessionId, trackingId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = personalize_events("POST", "/events", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("eventList"=>eventList, "sessionId"=>sessionId, "trackingId"=>trackingId), args)); aws_config=aws_config)
