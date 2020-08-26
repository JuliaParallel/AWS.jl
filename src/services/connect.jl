# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: connect

using Compat
using UUIDs
"""
    CreateUser()

Creates a user account for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.
- `PhoneConfig`: The phone settings for the user.
- `RoutingProfileId`: The identifier of the routing profile for the user.
- `SecurityProfileIds`: The identifier of the security profile for the user.
- `Username`: The user name for the account. For instances not using SAML for identity management, the user name can include up to 20 characters. If you are using SAML for identity management, the user name can include up to 64 characters from [a-zA-Z0-9_-. @]+.

# Optional Parameters
- `DirectoryUserId`: The identifier of the user account in the directory used for identity management. If Amazon Connect cannot access the directory, you can specify this identifier to authenticate users. If you include the identifier, we assume that Amazon Connect cannot access the directory. Otherwise, the identity information is used to authenticate users from your directory. This parameter is required if you are using an existing directory for identity management in Amazon Connect when Amazon Connect cannot access your directory to authenticate users. If you are using SAML for identity management and include this parameter, an error is returned.
- `HierarchyGroupId`: The identifier of the hierarchy group for the user.
- `IdentityInfo`: The information about the identity of the user.
- `Password`: The password for the user account. A password is required if you are using Amazon Connect for identity management. Otherwise, it is an error to include a password.
- `Tags`: One or more tags.
"""

create_user(InstanceId, PhoneConfig, RoutingProfileId, SecurityProfileIds, Username; aws_config::AWSConfig=global_aws_config()) = connect("PUT", "/users/$(InstanceId)", Dict{String, Any}("PhoneConfig"=>PhoneConfig, "RoutingProfileId"=>RoutingProfileId, "SecurityProfileIds"=>SecurityProfileIds, "Username"=>Username); aws_config=aws_config)
create_user(InstanceId, PhoneConfig, RoutingProfileId, SecurityProfileIds, Username, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("PUT", "/users/$(InstanceId)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("PhoneConfig"=>PhoneConfig, "RoutingProfileId"=>RoutingProfileId, "SecurityProfileIds"=>SecurityProfileIds, "Username"=>Username), args)); aws_config=aws_config)

"""
    DeleteUser()

Deletes a user account from the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.
- `UserId`: The identifier of the user.

"""

delete_user(InstanceId, UserId; aws_config::AWSConfig=global_aws_config()) = connect("DELETE", "/users/$(InstanceId)/$(UserId)"; aws_config=aws_config)
delete_user(InstanceId, UserId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("DELETE", "/users/$(InstanceId)/$(UserId)", args; aws_config=aws_config)

"""
    DescribeUser()

Describes the specified user account. You can find the instance ID in the console (it’s the final part of the ARN). The console does not display the user IDs. Instead, list the users and note the IDs provided in the output.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.
- `UserId`: The identifier of the user account.

"""

describe_user(InstanceId, UserId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/users/$(InstanceId)/$(UserId)"; aws_config=aws_config)
describe_user(InstanceId, UserId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/users/$(InstanceId)/$(UserId)", args; aws_config=aws_config)

"""
    DescribeUserHierarchyGroup()

Describes the specified hierarchy group.

# Required Parameters
- `HierarchyGroupId`: The identifier of the hierarchy group.
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

describe_user_hierarchy_group(HierarchyGroupId, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user-hierarchy-groups/$(InstanceId)/$(HierarchyGroupId)"; aws_config=aws_config)
describe_user_hierarchy_group(HierarchyGroupId, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user-hierarchy-groups/$(InstanceId)/$(HierarchyGroupId)", args; aws_config=aws_config)

"""
    DescribeUserHierarchyStructure()

Describes the hierarchy structure of the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

describe_user_hierarchy_structure(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user-hierarchy-structure/$(InstanceId)"; aws_config=aws_config)
describe_user_hierarchy_structure(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user-hierarchy-structure/$(InstanceId)", args; aws_config=aws_config)

"""
    GetContactAttributes()

Retrieves the contact attributes for the specified contact.

# Required Parameters
- `InitialContactId`: The identifier of the initial contact.
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

get_contact_attributes(InitialContactId, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/contact/attributes/$(InstanceId)/$(InitialContactId)"; aws_config=aws_config)
get_contact_attributes(InitialContactId, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/contact/attributes/$(InstanceId)/$(InitialContactId)", args; aws_config=aws_config)

"""
    GetCurrentMetricData()

Gets the real-time metric data from the specified Amazon Connect instance. For more information, see Real-time Metrics Reports in the Amazon Connect Administrator Guide.

# Required Parameters
- `CurrentMetrics`: The metrics to retrieve. Specify the name and unit for each metric. The following metrics are available. For a description of each metric, see Real-time Metrics Definitions in the Amazon Connect Administrator Guide.  AGENTS_AFTER_CONTACT_WORK  Unit: COUNT  AGENTS_AVAILABLE  Unit: COUNT  AGENTS_ERROR  Unit: COUNT  AGENTS_NON_PRODUCTIVE  Unit: COUNT  AGENTS_ON_CALL  Unit: COUNT  AGENTS_ON_CONTACT  Unit: COUNT  AGENTS_ONLINE  Unit: COUNT  AGENTS_STAFFED  Unit: COUNT  CONTACTS_IN_QUEUE  Unit: COUNT  CONTACTS_SCHEDULED  Unit: COUNT  OLDEST_CONTACT_AGE  Unit: SECONDS  SLOTS_ACTIVE  Unit: COUNT  SLOTS_AVAILABLE  Unit: COUNT  
- `Filters`: The queues, up to 100, or channels, to use to filter the metrics returned. Metric data is retrieved only for the resources associated with the queues or channels included in the filter. You can include both queue IDs and queue ARNs in the same request. The only supported channel is VOICE.
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `Groupings`: The grouping applied to the metrics returned. For example, when grouped by QUEUE, the metrics returned apply to each queue rather than aggregated for all queues. If you group by CHANNEL, you should include a Channels filter. The only supported channel is VOICE. If no Grouping is included in the request, a summary of metrics is returned.
- `MaxResults`: The maximimum number of results to return per page.
- `NextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results. The token expires after 5 minutes from the time it is created. Subsequent requests that use the token must use the same request parameters as the request that generated the token.
"""

get_current_metric_data(CurrentMetrics, Filters, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/metrics/current/$(InstanceId)", Dict{String, Any}("CurrentMetrics"=>CurrentMetrics, "Filters"=>Filters); aws_config=aws_config)
get_current_metric_data(CurrentMetrics, Filters, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/metrics/current/$(InstanceId)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("CurrentMetrics"=>CurrentMetrics, "Filters"=>Filters), args)); aws_config=aws_config)

"""
    GetFederationToken()

Retrieves a token for federation.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

get_federation_token(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user/federate/$(InstanceId)"; aws_config=aws_config)
get_federation_token(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user/federate/$(InstanceId)", args; aws_config=aws_config)

"""
    GetMetricData()

Gets historical metric data from the specified Amazon Connect instance. For more information, see Historical Metrics Reports in the Amazon Connect Administrator Guide.

# Required Parameters
- `EndTime`: The timestamp, in UNIX Epoch time format, at which to end the reporting interval for the retrieval of historical metrics data. The time must be specified using an interval of 5 minutes, such as 11:00, 11:05, 11:10, and must be later than the start time timestamp. The time range between the start and end time must be less than 24 hours.
- `Filters`: The queues, up to 100, or channels, to use to filter the metrics returned. Metric data is retrieved only for the resources associated with the queues or channels included in the filter. You can include both queue IDs and queue ARNs in the same request. The only supported channel is VOICE.
- `HistoricalMetrics`: The metrics to retrieve. Specify the name, unit, and statistic for each metric. The following historical metrics are available. For a description of each metric, see Historical Metrics Definitions in the Amazon Connect Administrator Guide.  ABANDON_TIME  Unit: SECONDS Statistic: AVG  AFTER_CONTACT_WORK_TIME  Unit: SECONDS Statistic: AVG  API_CONTACTS_HANDLED  Unit: COUNT Statistic: SUM  CALLBACK_CONTACTS_HANDLED  Unit: COUNT Statistic: SUM  CONTACTS_ABANDONED  Unit: COUNT Statistic: SUM  CONTACTS_AGENT_HUNG_UP_FIRST  Unit: COUNT Statistic: SUM  CONTACTS_CONSULTED  Unit: COUNT Statistic: SUM  CONTACTS_HANDLED  Unit: COUNT Statistic: SUM  CONTACTS_HANDLED_INCOMING  Unit: COUNT Statistic: SUM  CONTACTS_HANDLED_OUTBOUND  Unit: COUNT Statistic: SUM  CONTACTS_HOLD_ABANDONS  Unit: COUNT Statistic: SUM  CONTACTS_MISSED  Unit: COUNT Statistic: SUM  CONTACTS_QUEUED  Unit: COUNT Statistic: SUM  CONTACTS_TRANSFERRED_IN  Unit: COUNT Statistic: SUM  CONTACTS_TRANSFERRED_IN_FROM_QUEUE  Unit: COUNT Statistic: SUM  CONTACTS_TRANSFERRED_OUT  Unit: COUNT Statistic: SUM  CONTACTS_TRANSFERRED_OUT_FROM_QUEUE  Unit: COUNT Statistic: SUM  HANDLE_TIME  Unit: SECONDS Statistic: AVG  HOLD_TIME  Unit: SECONDS Statistic: AVG  INTERACTION_AND_HOLD_TIME  Unit: SECONDS Statistic: AVG  INTERACTION_TIME  Unit: SECONDS Statistic: AVG  OCCUPANCY  Unit: PERCENT Statistic: AVG  QUEUE_ANSWER_TIME  Unit: SECONDS Statistic: AVG  QUEUED_TIME  Unit: SECONDS Statistic: MAX  SERVICE_LEVEL  Unit: PERCENT Statistic: AVG Threshold: Only \"Less than\" comparisons are supported, with the following service level thresholds: 15, 20, 25, 30, 45, 60, 90, 120, 180, 240, 300, 600  
- `InstanceId`: The identifier of the Amazon Connect instance.
- `StartTime`: The timestamp, in UNIX Epoch time format, at which to start the reporting interval for the retrieval of historical metrics data. The time must be specified using a multiple of 5 minutes, such as 10:05, 10:10, 10:15. The start time cannot be earlier than 24 hours before the time of the request. Historical metrics are available only for 24 hours.

# Optional Parameters
- `Groupings`: The grouping applied to the metrics returned. For example, when results are grouped by queue, the metrics returned are grouped by queue. The values returned apply to the metrics for each queue rather than aggregated for all queues. The only supported grouping is QUEUE. If no grouping is specified, a summary of metrics for all queues is returned.
- `MaxResults`: The maximimum number of results to return per page.
- `NextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
"""

get_metric_data(EndTime, Filters, HistoricalMetrics, InstanceId, StartTime; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/metrics/historical/$(InstanceId)", Dict{String, Any}("EndTime"=>EndTime, "Filters"=>Filters, "HistoricalMetrics"=>HistoricalMetrics, "StartTime"=>StartTime); aws_config=aws_config)
get_metric_data(EndTime, Filters, HistoricalMetrics, InstanceId, StartTime, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/metrics/historical/$(InstanceId)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("EndTime"=>EndTime, "Filters"=>Filters, "HistoricalMetrics"=>HistoricalMetrics, "StartTime"=>StartTime), args)); aws_config=aws_config)

"""
    ListContactFlows()

Provides information about the contact flows for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `contactFlowTypes`: The type of contact flow.
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
"""

list_contact_flows(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/contact-flows-summary/$(InstanceId)"; aws_config=aws_config)
list_contact_flows(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/contact-flows-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ListHoursOfOperations()

Provides information about the hours of operation for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
"""

list_hours_of_operations(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/hours-of-operations-summary/$(InstanceId)"; aws_config=aws_config)
list_hours_of_operations(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/hours-of-operations-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ListPhoneNumbers()

Provides information about the phone numbers for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
- `phoneNumberCountryCodes`: The ISO country code.
- `phoneNumberTypes`: The type of phone number.
"""

list_phone_numbers(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/phone-numbers-summary/$(InstanceId)"; aws_config=aws_config)
list_phone_numbers(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/phone-numbers-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ListQueues()

Provides information about the queues for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
- `queueTypes`: The type of queue.
"""

list_queues(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/queues-summary/$(InstanceId)"; aws_config=aws_config)
list_queues(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/queues-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ListRoutingProfiles()

Provides summary information about the routing profiles for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
"""

list_routing_profiles(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/routing-profiles-summary/$(InstanceId)"; aws_config=aws_config)
list_routing_profiles(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/routing-profiles-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ListSecurityProfiles()

Provides summary information about the security profiles for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
"""

list_security_profiles(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/security-profiles-summary/$(InstanceId)"; aws_config=aws_config)
list_security_profiles(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/security-profiles-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ListTagsForResource()

Lists the tags for the specified resource.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the resource.

"""

list_tags_for_resource(resourceArn; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/tags/$(resourceArn)"; aws_config=aws_config)
list_tags_for_resource(resourceArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/tags/$(resourceArn)", args; aws_config=aws_config)

"""
    ListUserHierarchyGroups()

Provides summary information about the hierarchy groups for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
"""

list_user_hierarchy_groups(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user-hierarchy-groups-summary/$(InstanceId)"; aws_config=aws_config)
list_user_hierarchy_groups(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/user-hierarchy-groups-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ListUsers()

Provides summary information about the users for the specified Amazon Connect instance.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `maxResults`: The maximimum number of results to return per page.
- `nextToken`: The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.
"""

list_users(InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/users-summary/$(InstanceId)"; aws_config=aws_config)
list_users(InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("GET", "/users-summary/$(InstanceId)", args; aws_config=aws_config)

"""
    ResumeContactRecording()

When a contact is being recorded, and the recording has been suspended using SuspendContactRecording, this API resumes recording the call. Only voice recordings are supported at this time.

# Required Parameters
- `ContactId`: The identifier of the contact.
- `InitialContactId`: The identifier of the contact. This is the identifier of the contact associated with the first interaction with the contact center.
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

resume_contact_recording(ContactId, InitialContactId, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/resume-recording", Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId); aws_config=aws_config)
resume_contact_recording(ContactId, InitialContactId, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/resume-recording", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId), args)); aws_config=aws_config)

"""
    StartChatContact()

Initiates a contact flow to start a new chat for the customer. Response of this API provides a token required to obtain credentials from the CreateParticipantConnection API in the Amazon Connect Participant Service. When a new chat contact is successfully created, clients need to subscribe to the participant’s connection for the created chat within 5 minutes. This is achieved by invoking CreateParticipantConnection with WEBSOCKET and CONNECTION_CREDENTIALS. 

# Required Parameters
- `ContactFlowId`: The identifier of the contact flow for the chat.
- `InstanceId`: The identifier of the Amazon Connect instance.
- `ParticipantDetails`: Information identifying the participant.

# Optional Parameters
- `Attributes`: A custom key-value pair using an attribute map. The attributes are standard Amazon Connect attributes, and can be accessed in contact flows just like any other contact attributes.  There can be up to 32,768 UTF-8 bytes across all key-value pairs per contact. Attribute keys can include only alphanumeric, dash, and underscore characters.
- `ClientToken`: A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.
- `InitialMessage`: The initial message to be sent to the newly created chat.
"""

start_chat_contact(ContactFlowId, InstanceId, ParticipantDetails; aws_config::AWSConfig=global_aws_config()) = connect("PUT", "/contact/chat", Dict{String, Any}("ContactFlowId"=>ContactFlowId, "InstanceId"=>InstanceId, "ParticipantDetails"=>ParticipantDetails, "ClientToken"=>string(uuid4())); aws_config=aws_config)
start_chat_contact(ContactFlowId, InstanceId, ParticipantDetails, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("PUT", "/contact/chat", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ContactFlowId"=>ContactFlowId, "InstanceId"=>InstanceId, "ParticipantDetails"=>ParticipantDetails, "ClientToken"=>string(uuid4())), args)); aws_config=aws_config)

"""
    StartContactRecording()

This API starts recording the contact when the agent joins the call. StartContactRecording is a one-time action. For example, if you use StopContactRecording to stop recording an ongoing call, you can't use StartContactRecording to restart it. For scenarios where the recording has started and you want to suspend and resume it, such as when collecting sensitive information (for example, a credit card number), use SuspendContactRecording and ResumeContactRecording. You can use this API to override the recording behavior configured in the Set recording behavior block. Only voice recordings are supported at this time.

# Required Parameters
- `ContactId`: The identifier of the contact.
- `InitialContactId`: The identifier of the contact. This is the identifier of the contact associated with the first interaction with the contact center.
- `InstanceId`: The identifier of the Amazon Connect instance.
- `VoiceRecordingConfiguration`: Who is being recorded.

"""

start_contact_recording(ContactId, InitialContactId, InstanceId, VoiceRecordingConfiguration; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/start-recording", Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId, "VoiceRecordingConfiguration"=>VoiceRecordingConfiguration); aws_config=aws_config)
start_contact_recording(ContactId, InitialContactId, InstanceId, VoiceRecordingConfiguration, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/start-recording", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId, "VoiceRecordingConfiguration"=>VoiceRecordingConfiguration), args)); aws_config=aws_config)

"""
    StartOutboundVoiceContact()

This API places an outbound call to a contact, and then initiates the contact flow. It performs the actions in the contact flow that's specified (in ContactFlowId). Agents are not involved in initiating the outbound API (that is, dialing the contact). If the contact flow places an outbound call to a contact, and then puts the contact in queue, that's when the call is routed to the agent, like any other inbound case. There is a 60 second dialing timeout for this operation. If the call is not connected after 60 seconds, it fails.

# Required Parameters
- `ContactFlowId`: The identifier of the contact flow for the outbound call.
- `DestinationPhoneNumber`: The phone number of the customer, in E.164 format.
- `InstanceId`: The identifier of the Amazon Connect instance.

# Optional Parameters
- `Attributes`: A custom key-value pair using an attribute map. The attributes are standard Amazon Connect attributes, and can be accessed in contact flows just like any other contact attributes. There can be up to 32,768 UTF-8 bytes across all key-value pairs per contact. Attribute keys can include only alphanumeric, dash, and underscore characters.
- `ClientToken`: A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. The token is valid for 7 days after creation. If a contact is already started, the contact ID is returned. If the contact is disconnected, a new contact is started.
- `QueueId`: The queue for the call. If you specify a queue, the phone displayed for caller ID is the phone number specified in the queue. If you do not specify a queue, the queue defined in the contact flow is used. If you do not specify a queue, you must specify a source phone number.
- `SourcePhoneNumber`: The phone number associated with the Amazon Connect instance, in E.164 format. If you do not specify a source phone number, you must specify a queue.
"""

start_outbound_voice_contact(ContactFlowId, DestinationPhoneNumber, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("PUT", "/contact/outbound-voice", Dict{String, Any}("ContactFlowId"=>ContactFlowId, "DestinationPhoneNumber"=>DestinationPhoneNumber, "InstanceId"=>InstanceId, "ClientToken"=>string(uuid4())); aws_config=aws_config)
start_outbound_voice_contact(ContactFlowId, DestinationPhoneNumber, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("PUT", "/contact/outbound-voice", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ContactFlowId"=>ContactFlowId, "DestinationPhoneNumber"=>DestinationPhoneNumber, "InstanceId"=>InstanceId, "ClientToken"=>string(uuid4())), args)); aws_config=aws_config)

"""
    StopContact()

Ends the specified contact.

# Required Parameters
- `ContactId`: The ID of the contact.
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

stop_contact(ContactId, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/stop", Dict{String, Any}("ContactId"=>ContactId, "InstanceId"=>InstanceId); aws_config=aws_config)
stop_contact(ContactId, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/stop", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ContactId"=>ContactId, "InstanceId"=>InstanceId), args)); aws_config=aws_config)

"""
    StopContactRecording()

When a contact is being recorded, this API stops recording the call. StopContactRecording is a one-time action. If you use StopContactRecording to stop recording an ongoing call, you can't use StartContactRecording to restart it. For scenarios where the recording has started and you want to suspend it for sensitive information (for example, to collect a credit card number), and then restart it, use SuspendContactRecording and ResumeContactRecording. Only voice recordings are supported at this time.

# Required Parameters
- `ContactId`: The identifier of the contact.
- `InitialContactId`: The identifier of the contact. This is the identifier of the contact associated with the first interaction with the contact center.
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

stop_contact_recording(ContactId, InitialContactId, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/stop-recording", Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId); aws_config=aws_config)
stop_contact_recording(ContactId, InitialContactId, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/stop-recording", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId), args)); aws_config=aws_config)

"""
    SuspendContactRecording()

When a contact is being recorded, this API suspends recording the call. For example, you might suspend the call recording while collecting sensitive information, such as a credit card number. Then use ResumeContactRecording to restart recording.  The period of time that the recording is suspended is filled with silence in the final recording.  Only voice recordings are supported at this time.

# Required Parameters
- `ContactId`: The identifier of the contact.
- `InitialContactId`: The identifier of the contact. This is the identifier of the contact associated with the first interaction with the contact center.
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

suspend_contact_recording(ContactId, InitialContactId, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/suspend-recording", Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId); aws_config=aws_config)
suspend_contact_recording(ContactId, InitialContactId, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/suspend-recording", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ContactId"=>ContactId, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId), args)); aws_config=aws_config)

"""
    TagResource()

Adds the specified tags to the specified resource. The supported resource type is users.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the resource.
- `tags`: One or more tags. For example, { \"tags\": {\"key1\":\"value1\", \"key2\":\"value2\"} }.

"""

tag_resource(resourceArn, tags; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/tags/$(resourceArn)", Dict{String, Any}("tags"=>tags); aws_config=aws_config)
tag_resource(resourceArn, tags, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tags"=>tags), args)); aws_config=aws_config)

"""
    UntagResource()

Removes the specified tags from the specified resource.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the resource.
- `tagKeys`: The tag keys.

"""

untag_resource(resourceArn, tagKeys; aws_config::AWSConfig=global_aws_config()) = connect("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys); aws_config=aws_config)
untag_resource(resourceArn, tagKeys, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("DELETE", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tagKeys"=>tagKeys), args)); aws_config=aws_config)

"""
    UpdateContactAttributes()

Creates or updates the contact attributes associated with the specified contact. You can add or update attributes for both ongoing and completed contacts. For example, you can update the customer's name or the reason the customer called while the call is active, or add notes about steps that the agent took during the call that are displayed to the next agent that takes the call. You can also update attributes for a contact using data from your CRM application and save the data with the contact in Amazon Connect. You could also flag calls for additional analysis, such as legal review or identifying abusive callers. Contact attributes are available in Amazon Connect for 24 months, and are then deleted.  Important: You cannot use the operation to update attributes for contacts that occurred prior to the release of the API, September 12, 2018. You can update attributes only for contacts that started after the release of the API. If you attempt to update attributes for a contact that occurred prior to the release of the API, a 400 error is returned. This applies also to queued callbacks that were initiated prior to the release of the API but are still active in your instance.

# Required Parameters
- `Attributes`: The Amazon Connect attributes. These attributes can be accessed in contact flows just like any other contact attributes. You can have up to 32,768 UTF-8 bytes across all attributes for a contact. Attribute keys can include only alphanumeric, dash, and underscore characters.
- `InitialContactId`: The identifier of the contact. This is the identifier of the contact associated with the first interaction with the contact center.
- `InstanceId`: The identifier of the Amazon Connect instance.

"""

update_contact_attributes(Attributes, InitialContactId, InstanceId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/attributes", Dict{String, Any}("Attributes"=>Attributes, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId); aws_config=aws_config)
update_contact_attributes(Attributes, InitialContactId, InstanceId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/contact/attributes", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Attributes"=>Attributes, "InitialContactId"=>InitialContactId, "InstanceId"=>InstanceId), args)); aws_config=aws_config)

"""
    UpdateUserHierarchy()

Assigns the specified hierarchy group to the specified user.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.
- `UserId`: The identifier of the user account.

# Optional Parameters
- `HierarchyGroupId`: The identifier of the hierarchy group.
"""

update_user_hierarchy(InstanceId, UserId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/hierarchy"; aws_config=aws_config)
update_user_hierarchy(InstanceId, UserId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/hierarchy", args; aws_config=aws_config)

"""
    UpdateUserIdentityInfo()

Updates the identity information for the specified user.

# Required Parameters
- `IdentityInfo`: The identity information for the user.
- `InstanceId`: The identifier of the Amazon Connect instance.
- `UserId`: The identifier of the user account.

"""

update_user_identity_info(IdentityInfo, InstanceId, UserId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/identity-info", Dict{String, Any}("IdentityInfo"=>IdentityInfo); aws_config=aws_config)
update_user_identity_info(IdentityInfo, InstanceId, UserId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/identity-info", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("IdentityInfo"=>IdentityInfo), args)); aws_config=aws_config)

"""
    UpdateUserPhoneConfig()

Updates the phone configuration settings for the specified user.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.
- `PhoneConfig`: Information about phone configuration settings for the user.
- `UserId`: The identifier of the user account.

"""

update_user_phone_config(InstanceId, PhoneConfig, UserId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/phone-config", Dict{String, Any}("PhoneConfig"=>PhoneConfig); aws_config=aws_config)
update_user_phone_config(InstanceId, PhoneConfig, UserId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/phone-config", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("PhoneConfig"=>PhoneConfig), args)); aws_config=aws_config)

"""
    UpdateUserRoutingProfile()

Assigns the specified routing profile to the specified user.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.
- `RoutingProfileId`: The identifier of the routing profile for the user.
- `UserId`: The identifier of the user account.

"""

update_user_routing_profile(InstanceId, RoutingProfileId, UserId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/routing-profile", Dict{String, Any}("RoutingProfileId"=>RoutingProfileId); aws_config=aws_config)
update_user_routing_profile(InstanceId, RoutingProfileId, UserId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/routing-profile", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("RoutingProfileId"=>RoutingProfileId), args)); aws_config=aws_config)

"""
    UpdateUserSecurityProfiles()

Assigns the specified security profiles to the specified user.

# Required Parameters
- `InstanceId`: The identifier of the Amazon Connect instance.
- `SecurityProfileIds`: The identifiers of the security profiles for the user.
- `UserId`: The identifier of the user account.

"""

update_user_security_profiles(InstanceId, SecurityProfileIds, UserId; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/security-profiles", Dict{String, Any}("SecurityProfileIds"=>SecurityProfileIds); aws_config=aws_config)
update_user_security_profiles(InstanceId, SecurityProfileIds, UserId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = connect("POST", "/users/$(InstanceId)/$(UserId)/security-profiles", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("SecurityProfileIds"=>SecurityProfileIds), args)); aws_config=aws_config)
