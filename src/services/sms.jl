# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: sms

using Compat
using UUIDs
"""
    CreateApp()

Creates an application. An application consists of one or more server groups. Each server group contain one or more servers.

# Optional Parameters
- `clientToken`: A unique, case-sensitive identifier that you provide to ensure the idempotency of application creation.
- `description`: The description of the new application
- `name`: The name of the new application.
- `roleName`: The name of the service role in the customer's account to be used by AWS SMS.
- `serverGroups`: The server groups to include in the application.
- `tags`: The tags to be associated with the application.
"""

create_app(; aws_config::AWSConfig=global_aws_config()) = sms("CreateApp"; aws_config=aws_config)
create_app(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("CreateApp", args; aws_config=aws_config)

"""
    CreateReplicationJob()

Creates a replication job. The replication job schedules periodic replication runs to replicate your server to AWS. Each replication run creates an Amazon Machine Image (AMI).

# Required Parameters
- `seedReplicationTime`: The seed replication time.
- `serverId`: The ID of the server.

# Optional Parameters
- `description`: The description of the replication job.
- `encrypted`: Indicates whether the replication job produces encrypted AMIs.
- `frequency`: The time between consecutive replication runs, in hours.
- `kmsKeyId`: The ID of the KMS key for replication jobs that produce encrypted AMIs. This value can be any of the following:   KMS key ID   KMS key alias   ARN referring to the KMS key ID   ARN referring to the KMS key alias    If encrypted is true but a KMS key ID is not specified, the customer's default KMS key for Amazon EBS is used. 
- `licenseType`: The license type to be used for the AMI created by a successful replication run.
- `numberOfRecentAmisToKeep`: The maximum number of SMS-created AMIs to retain. The oldest is deleted after the maximum number is reached and a new AMI is created.
- `roleName`: The name of the IAM role to be used by the AWS SMS.
- `runOnce`: Indicates whether to run the replication job one time.
"""

create_replication_job(seedReplicationTime, serverId; aws_config::AWSConfig=global_aws_config()) = sms("CreateReplicationJob", Dict{String, Any}("seedReplicationTime"=>seedReplicationTime, "serverId"=>serverId); aws_config=aws_config)
create_replication_job(seedReplicationTime, serverId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("CreateReplicationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("seedReplicationTime"=>seedReplicationTime, "serverId"=>serverId), args)); aws_config=aws_config)

"""
    DeleteApp()

Deletes the specified application. Optionally deletes the launched stack associated with the application and all AWS SMS replication jobs for servers in the application.

# Optional Parameters
- `appId`: The ID of the application.
- `forceStopAppReplication`: Indicates whether to stop all replication jobs corresponding to the servers in the application while deleting the application.
- `forceTerminateApp`: Indicates whether to terminate the stack corresponding to the application while deleting the application.
"""

delete_app(; aws_config::AWSConfig=global_aws_config()) = sms("DeleteApp"; aws_config=aws_config)
delete_app(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("DeleteApp", args; aws_config=aws_config)

"""
    DeleteAppLaunchConfiguration()

Deletes the launch configuration for the specified application.

# Optional Parameters
- `appId`: The ID of the application.
"""

delete_app_launch_configuration(; aws_config::AWSConfig=global_aws_config()) = sms("DeleteAppLaunchConfiguration"; aws_config=aws_config)
delete_app_launch_configuration(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("DeleteAppLaunchConfiguration", args; aws_config=aws_config)

"""
    DeleteAppReplicationConfiguration()

Deletes the replication configuration for the specified application.

# Optional Parameters
- `appId`: The ID of the application.
"""

delete_app_replication_configuration(; aws_config::AWSConfig=global_aws_config()) = sms("DeleteAppReplicationConfiguration"; aws_config=aws_config)
delete_app_replication_configuration(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("DeleteAppReplicationConfiguration", args; aws_config=aws_config)

"""
    DeleteAppValidationConfiguration()

Deletes the validation configuration for the specified application.

# Required Parameters
- `appId`: The ID of the application.

"""

delete_app_validation_configuration(appId; aws_config::AWSConfig=global_aws_config()) = sms("DeleteAppValidationConfiguration", Dict{String, Any}("appId"=>appId); aws_config=aws_config)
delete_app_validation_configuration(appId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("DeleteAppValidationConfiguration", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("appId"=>appId), args)); aws_config=aws_config)

"""
    DeleteReplicationJob()

Deletes the specified replication job. After you delete a replication job, there are no further replication runs. AWS deletes the contents of the Amazon S3 bucket used to store AWS SMS artifacts. The AMIs created by the replication runs are not deleted.

# Required Parameters
- `replicationJobId`: The ID of the replication job.

"""

delete_replication_job(replicationJobId; aws_config::AWSConfig=global_aws_config()) = sms("DeleteReplicationJob", Dict{String, Any}("replicationJobId"=>replicationJobId); aws_config=aws_config)
delete_replication_job(replicationJobId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("DeleteReplicationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("replicationJobId"=>replicationJobId), args)); aws_config=aws_config)

"""
    DeleteServerCatalog()

Deletes all servers from your server catalog.

"""

delete_server_catalog(; aws_config::AWSConfig=global_aws_config()) = sms("DeleteServerCatalog"; aws_config=aws_config)
delete_server_catalog(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("DeleteServerCatalog", args; aws_config=aws_config)

"""
    DisassociateConnector()

Disassociates the specified connector from AWS SMS. After you disassociate a connector, it is no longer available to support replication jobs.

# Required Parameters
- `connectorId`: The ID of the connector.

"""

disassociate_connector(connectorId; aws_config::AWSConfig=global_aws_config()) = sms("DisassociateConnector", Dict{String, Any}("connectorId"=>connectorId); aws_config=aws_config)
disassociate_connector(connectorId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("DisassociateConnector", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("connectorId"=>connectorId), args)); aws_config=aws_config)

"""
    GenerateChangeSet()

Generates a target change set for a currently launched stack and writes it to an Amazon S3 object in the customer’s Amazon S3 bucket.

# Optional Parameters
- `appId`: The ID of the application associated with the change set.
- `changesetFormat`: The format for the change set.
"""

generate_change_set(; aws_config::AWSConfig=global_aws_config()) = sms("GenerateChangeSet"; aws_config=aws_config)
generate_change_set(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GenerateChangeSet", args; aws_config=aws_config)

"""
    GenerateTemplate()

Generates an AWS CloudFormation template based on the current launch configuration and writes it to an Amazon S3 object in the customer’s Amazon S3 bucket.

# Optional Parameters
- `appId`: The ID of the application associated with the AWS CloudFormation template.
- `templateFormat`: The format for generating the AWS CloudFormation template.
"""

generate_template(; aws_config::AWSConfig=global_aws_config()) = sms("GenerateTemplate"; aws_config=aws_config)
generate_template(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GenerateTemplate", args; aws_config=aws_config)

"""
    GetApp()

Retrieve information about the specified application.

# Optional Parameters
- `appId`: The ID of the application.
"""

get_app(; aws_config::AWSConfig=global_aws_config()) = sms("GetApp"; aws_config=aws_config)
get_app(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetApp", args; aws_config=aws_config)

"""
    GetAppLaunchConfiguration()

Retrieves the application launch configuration associated with the specified application.

# Optional Parameters
- `appId`: The ID of the application.
"""

get_app_launch_configuration(; aws_config::AWSConfig=global_aws_config()) = sms("GetAppLaunchConfiguration"; aws_config=aws_config)
get_app_launch_configuration(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetAppLaunchConfiguration", args; aws_config=aws_config)

"""
    GetAppReplicationConfiguration()

Retrieves the application replication configuration associated with the specified application.

# Optional Parameters
- `appId`: The ID of the application.
"""

get_app_replication_configuration(; aws_config::AWSConfig=global_aws_config()) = sms("GetAppReplicationConfiguration"; aws_config=aws_config)
get_app_replication_configuration(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetAppReplicationConfiguration", args; aws_config=aws_config)

"""
    GetAppValidationConfiguration()

Retrieves information about a configuration for validating an application.

# Required Parameters
- `appId`: The ID of the application.

"""

get_app_validation_configuration(appId; aws_config::AWSConfig=global_aws_config()) = sms("GetAppValidationConfiguration", Dict{String, Any}("appId"=>appId); aws_config=aws_config)
get_app_validation_configuration(appId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetAppValidationConfiguration", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("appId"=>appId), args)); aws_config=aws_config)

"""
    GetAppValidationOutput()

Retrieves output from validating an application.

# Required Parameters
- `appId`: The ID of the application.

"""

get_app_validation_output(appId; aws_config::AWSConfig=global_aws_config()) = sms("GetAppValidationOutput", Dict{String, Any}("appId"=>appId); aws_config=aws_config)
get_app_validation_output(appId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetAppValidationOutput", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("appId"=>appId), args)); aws_config=aws_config)

"""
    GetConnectors()

Describes the connectors registered with the AWS SMS.

# Optional Parameters
- `maxResults`: The maximum number of results to return in a single call. The default value is 50. To retrieve the remaining results, make another call with the returned NextToken value.
- `nextToken`: The token for the next set of results.
"""

get_connectors(; aws_config::AWSConfig=global_aws_config()) = sms("GetConnectors"; aws_config=aws_config)
get_connectors(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetConnectors", args; aws_config=aws_config)

"""
    GetReplicationJobs()

Describes the specified replication job or all of your replication jobs.

# Optional Parameters
- `maxResults`: The maximum number of results to return in a single call. The default value is 50. To retrieve the remaining results, make another call with the returned NextToken value.
- `nextToken`: The token for the next set of results.
- `replicationJobId`: The ID of the replication job.
"""

get_replication_jobs(; aws_config::AWSConfig=global_aws_config()) = sms("GetReplicationJobs"; aws_config=aws_config)
get_replication_jobs(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetReplicationJobs", args; aws_config=aws_config)

"""
    GetReplicationRuns()

Describes the replication runs for the specified replication job.

# Required Parameters
- `replicationJobId`: The ID of the replication job.

# Optional Parameters
- `maxResults`: The maximum number of results to return in a single call. The default value is 50. To retrieve the remaining results, make another call with the returned NextToken value.
- `nextToken`: The token for the next set of results.
"""

get_replication_runs(replicationJobId; aws_config::AWSConfig=global_aws_config()) = sms("GetReplicationRuns", Dict{String, Any}("replicationJobId"=>replicationJobId); aws_config=aws_config)
get_replication_runs(replicationJobId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetReplicationRuns", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("replicationJobId"=>replicationJobId), args)); aws_config=aws_config)

"""
    GetServers()

Describes the servers in your server catalog. Before you can describe your servers, you must import them using ImportServerCatalog.

# Optional Parameters
- `maxResults`: The maximum number of results to return in a single call. The default value is 50. To retrieve the remaining results, make another call with the returned NextToken value.
- `nextToken`: The token for the next set of results.
- `vmServerAddressList`: The server addresses.
"""

get_servers(; aws_config::AWSConfig=global_aws_config()) = sms("GetServers"; aws_config=aws_config)
get_servers(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("GetServers", args; aws_config=aws_config)

"""
    ImportAppCatalog()

Allows application import from AWS Migration Hub.

# Optional Parameters
- `roleName`: The name of the service role. If you omit this parameter, we create a service-linked role for AWS Migration Hub in your account. Otherwise, the role that you provide must have the policy and trust policy described in the AWS Migration Hub User Guide.
"""

import_app_catalog(; aws_config::AWSConfig=global_aws_config()) = sms("ImportAppCatalog"; aws_config=aws_config)
import_app_catalog(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("ImportAppCatalog", args; aws_config=aws_config)

"""
    ImportServerCatalog()

Gathers a complete list of on-premises servers. Connectors must be installed and monitoring all servers to import. This call returns immediately, but might take additional time to retrieve all the servers.

"""

import_server_catalog(; aws_config::AWSConfig=global_aws_config()) = sms("ImportServerCatalog"; aws_config=aws_config)
import_server_catalog(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("ImportServerCatalog", args; aws_config=aws_config)

"""
    LaunchApp()

Launches the specified application as a stack in AWS CloudFormation.

# Optional Parameters
- `appId`: The ID of the application.
"""

launch_app(; aws_config::AWSConfig=global_aws_config()) = sms("LaunchApp"; aws_config=aws_config)
launch_app(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("LaunchApp", args; aws_config=aws_config)

"""
    ListApps()

Retrieves summaries for all applications.

# Optional Parameters
- `appIds`: The unique application IDs.
- `maxResults`: The maximum number of results to return in a single call. The default value is 100. To retrieve the remaining results, make another call with the returned NextToken value. 
- `nextToken`: The token for the next set of results.
"""

list_apps(; aws_config::AWSConfig=global_aws_config()) = sms("ListApps"; aws_config=aws_config)
list_apps(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("ListApps", args; aws_config=aws_config)

"""
    NotifyAppValidationOutput()

Provides information to AWS SMS about whether application validation is successful.

# Required Parameters
- `appId`: The ID of the application.

# Optional Parameters
- `notificationContext`: The notification information.
"""

notify_app_validation_output(appId; aws_config::AWSConfig=global_aws_config()) = sms("NotifyAppValidationOutput", Dict{String, Any}("appId"=>appId); aws_config=aws_config)
notify_app_validation_output(appId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("NotifyAppValidationOutput", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("appId"=>appId), args)); aws_config=aws_config)

"""
    PutAppLaunchConfiguration()

Creates or updates the launch configuration for the specified application.

# Optional Parameters
- `appId`: The ID of the application.
- `autoLaunch`: Indicates whether the application is configured to launch automatically after replication is complete.
- `roleName`: The name of service role in the customer's account that AWS CloudFormation uses to launch the application.
- `serverGroupLaunchConfigurations`: Information about the launch configurations for server groups in the application.
"""

put_app_launch_configuration(; aws_config::AWSConfig=global_aws_config()) = sms("PutAppLaunchConfiguration"; aws_config=aws_config)
put_app_launch_configuration(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("PutAppLaunchConfiguration", args; aws_config=aws_config)

"""
    PutAppReplicationConfiguration()

Creates or updates the replication configuration for the specified application.

# Optional Parameters
- `appId`: The ID of the application.
- `serverGroupReplicationConfigurations`: Information about the replication configurations for server groups in the application.
"""

put_app_replication_configuration(; aws_config::AWSConfig=global_aws_config()) = sms("PutAppReplicationConfiguration"; aws_config=aws_config)
put_app_replication_configuration(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("PutAppReplicationConfiguration", args; aws_config=aws_config)

"""
    PutAppValidationConfiguration()

Creates or updates a validation configuration for the specified application.

# Required Parameters
- `appId`: The ID of the application.

# Optional Parameters
- `appValidationConfigurations`: The configuration for application validation.
- `serverGroupValidationConfigurations`: The configuration for instance validation.
"""

put_app_validation_configuration(appId; aws_config::AWSConfig=global_aws_config()) = sms("PutAppValidationConfiguration", Dict{String, Any}("appId"=>appId); aws_config=aws_config)
put_app_validation_configuration(appId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("PutAppValidationConfiguration", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("appId"=>appId), args)); aws_config=aws_config)

"""
    StartAppReplication()

Starts replicating the specified application by creating replication jobs for each server in the application.

# Optional Parameters
- `appId`: The ID of the application.
"""

start_app_replication(; aws_config::AWSConfig=global_aws_config()) = sms("StartAppReplication"; aws_config=aws_config)
start_app_replication(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("StartAppReplication", args; aws_config=aws_config)

"""
    StartOnDemandAppReplication()

Starts an on-demand replication run for the specified application.

# Required Parameters
- `appId`: The ID of the application.

# Optional Parameters
- `description`: The description of the replication run.
"""

start_on_demand_app_replication(appId; aws_config::AWSConfig=global_aws_config()) = sms("StartOnDemandAppReplication", Dict{String, Any}("appId"=>appId); aws_config=aws_config)
start_on_demand_app_replication(appId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("StartOnDemandAppReplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("appId"=>appId), args)); aws_config=aws_config)

"""
    StartOnDemandReplicationRun()

Starts an on-demand replication run for the specified replication job. This replication run starts immediately. This replication run is in addition to the ones already scheduled. There is a limit on the number of on-demand replications runs that you can request in a 24-hour period.

# Required Parameters
- `replicationJobId`: The ID of the replication job.

# Optional Parameters
- `description`: The description of the replication run.
"""

start_on_demand_replication_run(replicationJobId; aws_config::AWSConfig=global_aws_config()) = sms("StartOnDemandReplicationRun", Dict{String, Any}("replicationJobId"=>replicationJobId); aws_config=aws_config)
start_on_demand_replication_run(replicationJobId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("StartOnDemandReplicationRun", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("replicationJobId"=>replicationJobId), args)); aws_config=aws_config)

"""
    StopAppReplication()

Stops replicating the specified application by deleting the replication job for each server in the application.

# Optional Parameters
- `appId`: The ID of the application.
"""

stop_app_replication(; aws_config::AWSConfig=global_aws_config()) = sms("StopAppReplication"; aws_config=aws_config)
stop_app_replication(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("StopAppReplication", args; aws_config=aws_config)

"""
    TerminateApp()

Terminates the stack for the specified application.

# Optional Parameters
- `appId`: The ID of the application.
"""

terminate_app(; aws_config::AWSConfig=global_aws_config()) = sms("TerminateApp"; aws_config=aws_config)
terminate_app(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("TerminateApp", args; aws_config=aws_config)

"""
    UpdateApp()

Updates the specified application.

# Optional Parameters
- `appId`: The ID of the application.
- `description`: The new description of the application.
- `name`: The new name of the application.
- `roleName`: The name of the service role in the customer's account used by AWS SMS.
- `serverGroups`: The server groups in the application to update.
- `tags`: The tags to associate with the application.
"""

update_app(; aws_config::AWSConfig=global_aws_config()) = sms("UpdateApp"; aws_config=aws_config)
update_app(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("UpdateApp", args; aws_config=aws_config)

"""
    UpdateReplicationJob()

Updates the specified settings for the specified replication job.

# Required Parameters
- `replicationJobId`: The ID of the replication job.

# Optional Parameters
- `description`: The description of the replication job.
- `encrypted`: When true, the replication job produces encrypted AMIs. For more information, KmsKeyId.
- `frequency`: The time between consecutive replication runs, in hours.
- `kmsKeyId`: The ID of the KMS key for replication jobs that produce encrypted AMIs. This value can be any of the following:   KMS key ID   KMS key alias   ARN referring to the KMS key ID   ARN referring to the KMS key alias   If encrypted is enabled but a KMS key ID is not specified, the customer's default KMS key for Amazon EBS is used.
- `licenseType`: The license type to be used for the AMI created by a successful replication run.
- `nextReplicationRunStartTime`: The start time of the next replication run.
- `numberOfRecentAmisToKeep`: The maximum number of SMS-created AMIs to retain. The oldest is deleted after the maximum number is reached and a new AMI is created.
- `roleName`: The name of the IAM role to be used by AWS SMS.
"""

update_replication_job(replicationJobId; aws_config::AWSConfig=global_aws_config()) = sms("UpdateReplicationJob", Dict{String, Any}("replicationJobId"=>replicationJobId); aws_config=aws_config)
update_replication_job(replicationJobId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = sms("UpdateReplicationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("replicationJobId"=>replicationJobId), args)); aws_config=aws_config)
