# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
using Compat
using .AWSServices: migration_hub

"""
    AssociateCreatedArtifact()

Associates a created artifact of an AWS cloud resource, the target receiving the migration, with the migration task performed by a migration tool. This API has the following traits:   Migration tools can call the AssociateCreatedArtifact operation to indicate which AWS artifact is associated with a migration task.   The created artifact name must be provided in ARN (Amazon Resource Name) format which will contain information about type and region; for example: arn:aws:ec2:us-east-1:488216288981:image/ami-6d0ba87b.   Examples of the AWS resource behind the created artifact are, AMI's, EC2 instance, or DMS endpoint, etc.  

Required Parameters
CreatedArtifact => An ARN of the AWS resource related to the migration (e.g., AMI, EC2 instance, RDS instance, etc.) 
MigrationTaskName => Unique identifier that references the migration task. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream. 

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
AssociateCreatedArtifact(CreatedArtifact, MigrationTaskName, ProgressUpdateStream) = migration_hub("AssociateCreatedArtifact", Dict{String, Any}("CreatedArtifact"=>CreatedArtifact, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
AssociateCreatedArtifact(CreatedArtifact, MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("AssociateCreatedArtifact", Dict{String, Any}("CreatedArtifact"=>CreatedArtifact, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    AssociateDiscoveredResource()

Associates a discovered resource ID from Application Discovery Service with a migration task.

Required Parameters
DiscoveredResource => Object representing a Resource.
MigrationTaskName => The identifier given to the MigrationTask. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream.

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
AssociateDiscoveredResource(DiscoveredResource, MigrationTaskName, ProgressUpdateStream) = migration_hub("AssociateDiscoveredResource", Dict{String, Any}("DiscoveredResource"=>DiscoveredResource, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
AssociateDiscoveredResource(DiscoveredResource, MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("AssociateDiscoveredResource", Dict{String, Any}("DiscoveredResource"=>DiscoveredResource, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    CreateProgressUpdateStream()

Creates a progress update stream which is an AWS resource used for access control as well as a namespace for migration task names that is implicitly linked to your AWS account. It must uniquely identify the migration tool as it is used for all updates made by the tool; however, it does not need to be unique for each AWS account because it is scoped to the AWS account.

Required Parameters
ProgressUpdateStreamName => The name of the ProgressUpdateStream. Do not store personal data in this field. 

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
CreateProgressUpdateStream(ProgressUpdateStreamName) = migration_hub("CreateProgressUpdateStream", Dict{String, Any}("ProgressUpdateStreamName"=>ProgressUpdateStreamName))
CreateProgressUpdateStream(ProgressUpdateStreamName, args::AbstractDict{String, <: Any}) = migration_hub("CreateProgressUpdateStream", Dict{String, Any}("ProgressUpdateStreamName"=>ProgressUpdateStreamName, args...))

"""
    DeleteProgressUpdateStream()

Deletes a progress update stream, including all of its tasks, which was previously created as an AWS resource used for access control. This API has the following traits:   The only parameter needed for DeleteProgressUpdateStream is the stream name (same as a CreateProgressUpdateStream call).   The call will return, and a background process will asynchronously delete the stream and all of its resources (tasks, associated resources, resource attributes, created artifacts).   If the stream takes time to be deleted, it might still show up on a ListProgressUpdateStreams call.    CreateProgressUpdateStream, ImportMigrationTask, NotifyMigrationTaskState, and all Associate[*] APIs related to the tasks belonging to the stream will throw "InvalidInputException" if the stream of the same name is in the process of being deleted.   Once the stream and all of its resources are deleted, CreateProgressUpdateStream for a stream of the same name will succeed, and that stream will be an entirely new logical resource (without any resources associated with the old stream).  

Required Parameters
ProgressUpdateStreamName => The name of the ProgressUpdateStream. Do not store personal data in this field. 

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
DeleteProgressUpdateStream(ProgressUpdateStreamName) = migration_hub("DeleteProgressUpdateStream", Dict{String, Any}("ProgressUpdateStreamName"=>ProgressUpdateStreamName))
DeleteProgressUpdateStream(ProgressUpdateStreamName, args::AbstractDict{String, <: Any}) = migration_hub("DeleteProgressUpdateStream", Dict{String, Any}("ProgressUpdateStreamName"=>ProgressUpdateStreamName, args...))

"""
    DescribeApplicationState()

Gets the migration status of an application.

Required Parameters
ApplicationId => The configurationId in Application Discovery Service that uniquely identifies the grouped application.

"""
DescribeApplicationState(ApplicationId) = migration_hub("DescribeApplicationState", Dict{String, Any}("ApplicationId"=>ApplicationId))
DescribeApplicationState(ApplicationId, args::AbstractDict{String, <: Any}) = migration_hub("DescribeApplicationState", Dict{String, Any}("ApplicationId"=>ApplicationId, args...))

"""
    DescribeMigrationTask()

Retrieves a list of all attributes associated with a specific migration task.

Required Parameters
MigrationTaskName => The identifier given to the MigrationTask. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream. 

"""
DescribeMigrationTask(MigrationTaskName, ProgressUpdateStream) = migration_hub("DescribeMigrationTask", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
DescribeMigrationTask(MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("DescribeMigrationTask", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    DisassociateCreatedArtifact()

Disassociates a created artifact of an AWS resource with a migration task performed by a migration tool that was previously associated. This API has the following traits:   A migration user can call the DisassociateCreatedArtifacts operation to disassociate a created AWS Artifact from a migration task.   The created artifact name must be provided in ARN (Amazon Resource Name) format which will contain information about type and region; for example: arn:aws:ec2:us-east-1:488216288981:image/ami-6d0ba87b.   Examples of the AWS resource behind the created artifact are, AMI's, EC2 instance, or RDS instance, etc.  

Required Parameters
CreatedArtifactName => An ARN of the AWS resource related to the migration (e.g., AMI, EC2 instance, RDS instance, etc.)
MigrationTaskName => Unique identifier that references the migration task to be disassociated with the artifact. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream. 

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
DisassociateCreatedArtifact(CreatedArtifactName, MigrationTaskName, ProgressUpdateStream) = migration_hub("DisassociateCreatedArtifact", Dict{String, Any}("CreatedArtifactName"=>CreatedArtifactName, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
DisassociateCreatedArtifact(CreatedArtifactName, MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("DisassociateCreatedArtifact", Dict{String, Any}("CreatedArtifactName"=>CreatedArtifactName, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    DisassociateDiscoveredResource()

Disassociate an Application Discovery Service discovered resource from a migration task.

Required Parameters
ConfigurationId => ConfigurationId of the Application Discovery Service resource to be disassociated.
MigrationTaskName => The identifier given to the MigrationTask. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream.

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
DisassociateDiscoveredResource(ConfigurationId, MigrationTaskName, ProgressUpdateStream) = migration_hub("DisassociateDiscoveredResource", Dict{String, Any}("ConfigurationId"=>ConfigurationId, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
DisassociateDiscoveredResource(ConfigurationId, MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("DisassociateDiscoveredResource", Dict{String, Any}("ConfigurationId"=>ConfigurationId, "MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    ImportMigrationTask()

Registers a new migration task which represents a server, database, etc., being migrated to AWS by a migration tool. This API is a prerequisite to calling the NotifyMigrationTaskState API as the migration tool must first register the migration task with Migration Hub.

Required Parameters
MigrationTaskName => Unique identifier that references the migration task. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream. &gt;

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
ImportMigrationTask(MigrationTaskName, ProgressUpdateStream) = migration_hub("ImportMigrationTask", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
ImportMigrationTask(MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("ImportMigrationTask", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    ListApplicationStates()

Lists all the migration statuses for your applications. If you use the optional ApplicationIds parameter, only the migration statuses for those applications will be returned.

Optional Parameters
ApplicationIds => The configurationIds from the Application Discovery Service that uniquely identifies your applications.
MaxResults => Maximum number of results to be returned per page.
NextToken => If a NextToken was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in NextToken.
"""
ListApplicationStates() = migration_hub("ListApplicationStates")
ListApplicationStates(args::AbstractDict{String, <: Any}) = migration_hub("ListApplicationStates", args)

"""
    ListCreatedArtifacts()

Lists the created artifacts attached to a given migration task in an update stream. This API has the following traits:   Gets the list of the created artifacts while migration is taking place.   Shows the artifacts created by the migration tool that was associated by the AssociateCreatedArtifact API.    Lists created artifacts in a paginated interface.   

Required Parameters
MigrationTaskName => Unique identifier that references the migration task. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream. 

Optional Parameters
MaxResults => Maximum number of results to be returned per page.
NextToken => If a NextToken was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in NextToken.
"""
ListCreatedArtifacts(MigrationTaskName, ProgressUpdateStream) = migration_hub("ListCreatedArtifacts", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
ListCreatedArtifacts(MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("ListCreatedArtifacts", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    ListDiscoveredResources()

Lists discovered resources associated with the given MigrationTask.

Required Parameters
MigrationTaskName => The name of the MigrationTask. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream.

Optional Parameters
MaxResults => The maximum number of results returned per page.
NextToken => If a NextToken was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in NextToken.
"""
ListDiscoveredResources(MigrationTaskName, ProgressUpdateStream) = migration_hub("ListDiscoveredResources", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream))
ListDiscoveredResources(MigrationTaskName, ProgressUpdateStream, args::AbstractDict{String, <: Any}) = migration_hub("ListDiscoveredResources", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, args...))

"""
    ListMigrationTasks()

Lists all, or filtered by resource name, migration tasks associated with the user account making this call. This API has the following traits:   Can show a summary list of the most recent migration tasks.   Can show a summary list of migration tasks associated with a given discovered resource.   Lists migration tasks in a paginated interface.  

Optional Parameters
MaxResults => Value to specify how many results are returned per page.
NextToken => If a NextToken was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in NextToken.
ResourceName => Filter migration tasks by discovered resource name.
"""
ListMigrationTasks() = migration_hub("ListMigrationTasks")
ListMigrationTasks(args::AbstractDict{String, <: Any}) = migration_hub("ListMigrationTasks", args)

"""
    ListProgressUpdateStreams()

Lists progress update streams associated with the user account making this call.

Optional Parameters
MaxResults => Filter to limit the maximum number of results to list per page.
NextToken => If a NextToken was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in NextToken.
"""
ListProgressUpdateStreams() = migration_hub("ListProgressUpdateStreams")
ListProgressUpdateStreams(args::AbstractDict{String, <: Any}) = migration_hub("ListProgressUpdateStreams", args)

"""
    NotifyApplicationState()

Sets the migration state of an application. For a given application identified by the value passed to ApplicationId, its status is set or updated by passing one of three values to Status: NOT_STARTED | IN_PROGRESS | COMPLETED.

Required Parameters
ApplicationId => The configurationId in Application Discovery Service that uniquely identifies the grouped application.
Status => Status of the application - Not Started, In-Progress, Complete.

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
UpdateDateTime => The timestamp when the application state changed.
"""
NotifyApplicationState(ApplicationId, Status) = migration_hub("NotifyApplicationState", Dict{String, Any}("ApplicationId"=>ApplicationId, "Status"=>Status))
NotifyApplicationState(ApplicationId, Status, args::AbstractDict{String, <: Any}) = migration_hub("NotifyApplicationState", Dict{String, Any}("ApplicationId"=>ApplicationId, "Status"=>Status, args...))

"""
    NotifyMigrationTaskState()

Notifies Migration Hub of the current status, progress, or other detail regarding a migration task. This API has the following traits:   Migration tools will call the NotifyMigrationTaskState API to share the latest progress and status.    MigrationTaskName is used for addressing updates to the correct target.    ProgressUpdateStream is used for access control and to provide a namespace for each migration tool.  

Required Parameters
MigrationTaskName => Unique identifier that references the migration task. Do not store personal data in this field. 
NextUpdateSeconds => Number of seconds after the UpdateDateTime within which the Migration Hub can expect an update. If Migration Hub does not receive an update within the specified interval, then the migration task will be considered stale.
ProgressUpdateStream => The name of the ProgressUpdateStream. 
Task => Information about the task's progress and status.
UpdateDateTime => The timestamp when the task was gathered.

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
NotifyMigrationTaskState(MigrationTaskName, NextUpdateSeconds, ProgressUpdateStream, Task, UpdateDateTime) = migration_hub("NotifyMigrationTaskState", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "NextUpdateSeconds"=>NextUpdateSeconds, "ProgressUpdateStream"=>ProgressUpdateStream, "Task"=>Task, "UpdateDateTime"=>UpdateDateTime))
NotifyMigrationTaskState(MigrationTaskName, NextUpdateSeconds, ProgressUpdateStream, Task, UpdateDateTime, args::AbstractDict{String, <: Any}) = migration_hub("NotifyMigrationTaskState", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "NextUpdateSeconds"=>NextUpdateSeconds, "ProgressUpdateStream"=>ProgressUpdateStream, "Task"=>Task, "UpdateDateTime"=>UpdateDateTime, args...))

"""
    PutResourceAttributes()

Provides identifying details of the resource being migrated so that it can be associated in the Application Discovery Service repository. This association occurs asynchronously after PutResourceAttributes returns.    Keep in mind that subsequent calls to PutResourceAttributes will override previously stored attributes. For example, if it is first called with a MAC address, but later, it is desired to add an IP address, it will then be required to call it with both the IP and MAC addresses to prevent overriding the MAC address.   Note the instructions regarding the special use case of the  ResourceAttributeList  parameter when specifying any "VM" related value.     Because this is an asynchronous call, it will always return 200, whether an association occurs or not. To confirm if an association was found based on the provided details, call ListDiscoveredResources. 

Required Parameters
MigrationTaskName => Unique identifier that references the migration task. Do not store personal data in this field. 
ProgressUpdateStream => The name of the ProgressUpdateStream. 
ResourceAttributeList => Information about the resource that is being migrated. This data will be used to map the task to a resource in the Application Discovery Service repository.  Takes the object array of ResourceAttribute where the Type field is reserved for the following values: IPV4_ADDRESS | IPV6_ADDRESS | MAC_ADDRESS | FQDN | VM_MANAGER_ID | VM_MANAGED_OBJECT_REFERENCE | VM_NAME | VM_PATH | BIOS_ID | MOTHERBOARD_SERIAL_NUMBER where the identifying value can be a string up to 256 characters.     If any "VM" related value is set for a ResourceAttribute object, it is required that VM_MANAGER_ID, as a minimum, is always set. If VM_MANAGER_ID is not set, then all "VM" fields will be discarded and "VM" fields will not be used for matching the migration task to a server in Application Discovery Service repository. See the Example section below for a use case of specifying "VM" related values.    If a server you are trying to match has multiple IP or MAC addresses, you should provide as many as you know in separate type/value pairs passed to the ResourceAttributeList parameter to maximize the chances of matching.   

Optional Parameters
DryRun => Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.
"""
PutResourceAttributes(MigrationTaskName, ProgressUpdateStream, ResourceAttributeList) = migration_hub("PutResourceAttributes", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, "ResourceAttributeList"=>ResourceAttributeList))
PutResourceAttributes(MigrationTaskName, ProgressUpdateStream, ResourceAttributeList, args::AbstractDict{String, <: Any}) = migration_hub("PutResourceAttributes", Dict{String, Any}("MigrationTaskName"=>MigrationTaskName, "ProgressUpdateStream"=>ProgressUpdateStream, "ResourceAttributeList"=>ResourceAttributeList, args...))
