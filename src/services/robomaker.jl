# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: robomaker

using Compat
using UUIDs
"""
    BatchDescribeSimulationJob()

Describes one or more simulation jobs.

# Required Parameters
- `jobs`: A list of Amazon Resource Names (ARNs) of simulation jobs to describe.

"""
BatchDescribeSimulationJob(jobs; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/batchDescribeSimulationJob", Dict{String, Any}("jobs"=>jobs); aws=aws)
BatchDescribeSimulationJob(jobs, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/batchDescribeSimulationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("jobs"=>jobs), args)); aws=aws)

"""
    CancelDeploymentJob()

Cancels the specified deployment job.

# Required Parameters
- `job`: The deployment job ARN to cancel.

"""
CancelDeploymentJob(job; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/cancelDeploymentJob", Dict{String, Any}("job"=>job); aws=aws)
CancelDeploymentJob(job, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/cancelDeploymentJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("job"=>job), args)); aws=aws)

"""
    CancelSimulationJob()

Cancels the specified simulation job.

# Required Parameters
- `job`: The simulation job ARN to cancel.

"""
CancelSimulationJob(job; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/cancelSimulationJob", Dict{String, Any}("job"=>job); aws=aws)
CancelSimulationJob(job, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/cancelSimulationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("job"=>job), args)); aws=aws)

"""
    CancelSimulationJobBatch()

Cancels a simulation job batch. When you cancel a simulation job batch, you are also cancelling all of the active simulation jobs created as part of the batch. 

# Required Parameters
- `batch`: The id of the batch to cancel.

"""
CancelSimulationJobBatch(batch; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/cancelSimulationJobBatch", Dict{String, Any}("batch"=>batch); aws=aws)
CancelSimulationJobBatch(batch, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/cancelSimulationJobBatch", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("batch"=>batch), args)); aws=aws)

"""
    CreateDeploymentJob()

Deploys a specific version of a robot application to robots in a fleet. The robot application must have a numbered applicationVersion for consistency reasons. To create a new version, use CreateRobotApplicationVersion or see Creating a Robot Application Version.   After 90 days, deployment jobs expire and will be deleted. They will no longer be accessible.  

# Required Parameters
- `clientRequestToken`: Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.
- `deploymentApplicationConfigs`: The deployment application configuration.
- `fleet`: The Amazon Resource Name (ARN) of the fleet to deploy.

# Optional Parameters
- `deploymentConfig`: The requested deployment configuration.
- `tags`: A map that contains tag keys and tag values that are attached to the deployment job.
"""
CreateDeploymentJob(clientRequestToken, deploymentApplicationConfigs, fleet; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createDeploymentJob", Dict{String, Any}("clientRequestToken"=>clientRequestToken, "deploymentApplicationConfigs"=>deploymentApplicationConfigs, "fleet"=>fleet); aws=aws)
CreateDeploymentJob(clientRequestToken, deploymentApplicationConfigs, fleet, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createDeploymentJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("clientRequestToken"=>clientRequestToken, "deploymentApplicationConfigs"=>deploymentApplicationConfigs, "fleet"=>fleet), args)); aws=aws)

"""
    CreateFleet()

Creates a fleet, a logical group of robots running the same robot application.

# Required Parameters
- `name`: The name of the fleet.

# Optional Parameters
- `tags`: A map that contains tag keys and tag values that are attached to the fleet.
"""
CreateFleet(name; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createFleet", Dict{String, Any}("name"=>name); aws=aws)
CreateFleet(name, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createFleet", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("name"=>name), args)); aws=aws)

"""
    CreateRobot()

Creates a robot.

# Required Parameters
- `architecture`: The target architecture of the robot.
- `greengrassGroupId`: The Greengrass group id.
- `name`: The name for the robot.

# Optional Parameters
- `tags`: A map that contains tag keys and tag values that are attached to the robot.
"""
CreateRobot(architecture, greengrassGroupId, name; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createRobot", Dict{String, Any}("architecture"=>architecture, "greengrassGroupId"=>greengrassGroupId, "name"=>name); aws=aws)
CreateRobot(architecture, greengrassGroupId, name, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createRobot", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("architecture"=>architecture, "greengrassGroupId"=>greengrassGroupId, "name"=>name), args)); aws=aws)

"""
    CreateRobotApplication()

Creates a robot application. 

# Required Parameters
- `name`: The name of the robot application.
- `robotSoftwareSuite`: The robot software suite (ROS distribuition) used by the robot application.
- `sources`: The sources of the robot application.

# Optional Parameters
- `tags`: A map that contains tag keys and tag values that are attached to the robot application.
"""
CreateRobotApplication(name, robotSoftwareSuite, sources; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createRobotApplication", Dict{String, Any}("name"=>name, "robotSoftwareSuite"=>robotSoftwareSuite, "sources"=>sources); aws=aws)
CreateRobotApplication(name, robotSoftwareSuite, sources, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createRobotApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("name"=>name, "robotSoftwareSuite"=>robotSoftwareSuite, "sources"=>sources), args)); aws=aws)

"""
    CreateRobotApplicationVersion()

Creates a version of a robot application.

# Required Parameters
- `application`: The application information for the robot application.

# Optional Parameters
- `currentRevisionId`: The current revision id for the robot application. If you provide a value and it matches the latest revision ID, a new version will be created.
"""
CreateRobotApplicationVersion(application; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createRobotApplicationVersion", Dict{String, Any}("application"=>application); aws=aws)
CreateRobotApplicationVersion(application, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createRobotApplicationVersion", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application), args)); aws=aws)

"""
    CreateSimulationApplication()

Creates a simulation application.

# Required Parameters
- `name`: The name of the simulation application.
- `robotSoftwareSuite`: The robot software suite (ROS distribution) used by the simulation application.
- `simulationSoftwareSuite`: The simulation software suite used by the simulation application.
- `sources`: The sources of the simulation application.

# Optional Parameters
- `renderingEngine`: The rendering engine for the simulation application.
- `tags`: A map that contains tag keys and tag values that are attached to the simulation application.
"""
CreateSimulationApplication(name, robotSoftwareSuite, simulationSoftwareSuite, sources; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createSimulationApplication", Dict{String, Any}("name"=>name, "robotSoftwareSuite"=>robotSoftwareSuite, "simulationSoftwareSuite"=>simulationSoftwareSuite, "sources"=>sources); aws=aws)
CreateSimulationApplication(name, robotSoftwareSuite, simulationSoftwareSuite, sources, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createSimulationApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("name"=>name, "robotSoftwareSuite"=>robotSoftwareSuite, "simulationSoftwareSuite"=>simulationSoftwareSuite, "sources"=>sources), args)); aws=aws)

"""
    CreateSimulationApplicationVersion()

Creates a simulation application with a specific revision id.

# Required Parameters
- `application`: The application information for the simulation application.

# Optional Parameters
- `currentRevisionId`: The current revision id for the simulation application. If you provide a value and it matches the latest revision ID, a new version will be created.
"""
CreateSimulationApplicationVersion(application; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createSimulationApplicationVersion", Dict{String, Any}("application"=>application); aws=aws)
CreateSimulationApplicationVersion(application, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createSimulationApplicationVersion", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application), args)); aws=aws)

"""
    CreateSimulationJob()

Creates a simulation job.  After 90 days, simulation jobs expire and will be deleted. They will no longer be accessible.  

# Required Parameters
- `iamRole`: The IAM role name that allows the simulation instance to call the AWS APIs that are specified in its associated policies on your behalf. This is how credentials are passed in to your simulation job. 
- `maxJobDurationInSeconds`: The maximum simulation job duration in seconds (up to 14 days or 1,209,600 seconds. When maxJobDurationInSeconds is reached, the simulation job will status will transition to Completed.

# Optional Parameters
- `clientRequestToken`: Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.
- `compute`: Compute information for the simulation job.
- `dataSources`: Specify data sources to mount read-only files from S3 into your simulation. These files are available under /opt/robomaker/datasources/data_source_name.   There is a limit of 100 files and a combined size of 25GB for all DataSourceConfig objects.  
- `failureBehavior`: The failure behavior the simulation job.  Continue  Restart the simulation job in the same host instance.  Fail  Stop the simulation job and terminate the instance.  
- `loggingConfig`: The logging configuration.
- `outputLocation`: Location for output files generated by the simulation job.
- `robotApplications`: The robot application to use in the simulation job.
- `simulationApplications`: The simulation application to use in the simulation job.
- `tags`: A map that contains tag keys and tag values that are attached to the simulation job.
- `vpcConfig`: If your simulation job accesses resources in a VPC, you provide this parameter identifying the list of security group IDs and subnet IDs. These must belong to the same VPC. You must provide at least one security group and one subnet ID. 
"""
CreateSimulationJob(iamRole, maxJobDurationInSeconds; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createSimulationJob", Dict{String, Any}("iamRole"=>iamRole, "maxJobDurationInSeconds"=>maxJobDurationInSeconds, "clientRequestToken"=>string(uuid4())); aws=aws)
CreateSimulationJob(iamRole, maxJobDurationInSeconds, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/createSimulationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("iamRole"=>iamRole, "maxJobDurationInSeconds"=>maxJobDurationInSeconds, "clientRequestToken"=>string(uuid4())), args)); aws=aws)

"""
    DeleteFleet()

Deletes a fleet.

# Required Parameters
- `fleet`: The Amazon Resource Name (ARN) of the fleet.

"""
DeleteFleet(fleet; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteFleet", Dict{String, Any}("fleet"=>fleet); aws=aws)
DeleteFleet(fleet, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteFleet", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("fleet"=>fleet), args)); aws=aws)

"""
    DeleteRobot()

Deletes a robot.

# Required Parameters
- `robot`: The Amazon Resource Name (ARN) of the robot.

"""
DeleteRobot(robot; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteRobot", Dict{String, Any}("robot"=>robot); aws=aws)
DeleteRobot(robot, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteRobot", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("robot"=>robot), args)); aws=aws)

"""
    DeleteRobotApplication()

Deletes a robot application.

# Required Parameters
- `application`: The Amazon Resource Name (ARN) of the the robot application.

# Optional Parameters
- `applicationVersion`: The version of the robot application to delete.
"""
DeleteRobotApplication(application; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteRobotApplication", Dict{String, Any}("application"=>application); aws=aws)
DeleteRobotApplication(application, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteRobotApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application), args)); aws=aws)

"""
    DeleteSimulationApplication()

Deletes a simulation application.

# Required Parameters
- `application`: The application information for the simulation application to delete.

# Optional Parameters
- `applicationVersion`: The version of the simulation application to delete.
"""
DeleteSimulationApplication(application; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteSimulationApplication", Dict{String, Any}("application"=>application); aws=aws)
DeleteSimulationApplication(application, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deleteSimulationApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application), args)); aws=aws)

"""
    DeregisterRobot()

Deregisters a robot.

# Required Parameters
- `fleet`: The Amazon Resource Name (ARN) of the fleet.
- `robot`: The Amazon Resource Name (ARN) of the robot.

"""
DeregisterRobot(fleet, robot; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deregisterRobot", Dict{String, Any}("fleet"=>fleet, "robot"=>robot); aws=aws)
DeregisterRobot(fleet, robot, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/deregisterRobot", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("fleet"=>fleet, "robot"=>robot), args)); aws=aws)

"""
    DescribeDeploymentJob()

Describes a deployment job.

# Required Parameters
- `job`: The Amazon Resource Name (ARN) of the deployment job.

"""
DescribeDeploymentJob(job; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeDeploymentJob", Dict{String, Any}("job"=>job); aws=aws)
DescribeDeploymentJob(job, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeDeploymentJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("job"=>job), args)); aws=aws)

"""
    DescribeFleet()

Describes a fleet.

# Required Parameters
- `fleet`: The Amazon Resource Name (ARN) of the fleet.

"""
DescribeFleet(fleet; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeFleet", Dict{String, Any}("fleet"=>fleet); aws=aws)
DescribeFleet(fleet, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeFleet", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("fleet"=>fleet), args)); aws=aws)

"""
    DescribeRobot()

Describes a robot.

# Required Parameters
- `robot`: The Amazon Resource Name (ARN) of the robot to be described.

"""
DescribeRobot(robot; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeRobot", Dict{String, Any}("robot"=>robot); aws=aws)
DescribeRobot(robot, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeRobot", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("robot"=>robot), args)); aws=aws)

"""
    DescribeRobotApplication()

Describes a robot application.

# Required Parameters
- `application`: The Amazon Resource Name (ARN) of the robot application.

# Optional Parameters
- `applicationVersion`: The version of the robot application to describe.
"""
DescribeRobotApplication(application; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeRobotApplication", Dict{String, Any}("application"=>application); aws=aws)
DescribeRobotApplication(application, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeRobotApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application), args)); aws=aws)

"""
    DescribeSimulationApplication()

Describes a simulation application.

# Required Parameters
- `application`: The application information for the simulation application.

# Optional Parameters
- `applicationVersion`: The version of the simulation application to describe.
"""
DescribeSimulationApplication(application; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeSimulationApplication", Dict{String, Any}("application"=>application); aws=aws)
DescribeSimulationApplication(application, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeSimulationApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application), args)); aws=aws)

"""
    DescribeSimulationJob()

Describes a simulation job.

# Required Parameters
- `job`: The Amazon Resource Name (ARN) of the simulation job to be described.

"""
DescribeSimulationJob(job; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeSimulationJob", Dict{String, Any}("job"=>job); aws=aws)
DescribeSimulationJob(job, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeSimulationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("job"=>job), args)); aws=aws)

"""
    DescribeSimulationJobBatch()

Describes a simulation job batch.

# Required Parameters
- `batch`: The id of the batch to describe.

"""
DescribeSimulationJobBatch(batch; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeSimulationJobBatch", Dict{String, Any}("batch"=>batch); aws=aws)
DescribeSimulationJobBatch(batch, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/describeSimulationJobBatch", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("batch"=>batch), args)); aws=aws)

"""
    ListDeploymentJobs()

Returns a list of deployment jobs for a fleet. You can optionally provide filters to retrieve specific deployment jobs. 

# Optional Parameters
- `filters`: Optional filters to limit results. The filter names status and fleetName are supported. When filtering, you must use the complete value of the filtered item. You can use up to three filters, but they must be for the same named item. For example, if you are looking for items with the status InProgress or the status Pending.
- `maxResults`: When this parameter is used, ListDeploymentJobs only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListDeploymentJobs request with the returned nextToken value. This value can be between 1 and 200. If this parameter is not used, then ListDeploymentJobs returns up to 200 results and a nextToken value if applicable. 
- `nextToken`: The nextToken value returned from a previous paginated ListDeploymentJobs request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. 
"""
ListDeploymentJobs(; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listDeploymentJobs"; aws=aws)
ListDeploymentJobs(args::AbstractDict{String, Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listDeploymentJobs", args; aws=aws)

"""
    ListFleets()

Returns a list of fleets. You can optionally provide filters to retrieve specific fleets. 

# Optional Parameters
- `filters`: Optional filters to limit results. The filter name name is supported. When filtering, you must use the complete value of the filtered item. You can use up to three filters.
- `maxResults`: When this parameter is used, ListFleets only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListFleets request with the returned nextToken value. This value can be between 1 and 200. If this parameter is not used, then ListFleets returns up to 200 results and a nextToken value if applicable. 
- `nextToken`: The nextToken value returned from a previous paginated ListFleets request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value.   This token should be treated as an opaque identifier that is only used to retrieve the next items in a list and not for other programmatic purposes. 
"""
ListFleets(; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listFleets"; aws=aws)
ListFleets(args::AbstractDict{String, Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listFleets", args; aws=aws)

"""
    ListRobotApplications()

Returns a list of robot application. You can optionally provide filters to retrieve specific robot applications.

# Optional Parameters
- `filters`: Optional filters to limit results. The filter name name is supported. When filtering, you must use the complete value of the filtered item. You can use up to three filters.
- `maxResults`: When this parameter is used, ListRobotApplications only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListRobotApplications request with the returned nextToken value. This value can be between 1 and 100. If this parameter is not used, then ListRobotApplications returns up to 100 results and a nextToken value if applicable. 
- `nextToken`: The nextToken value returned from a previous paginated ListRobotApplications request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. 
- `versionQualifier`: The version qualifier of the robot application.
"""
ListRobotApplications(; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listRobotApplications"; aws=aws)
ListRobotApplications(args::AbstractDict{String, Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listRobotApplications", args; aws=aws)

"""
    ListRobots()

Returns a list of robots. You can optionally provide filters to retrieve specific robots.

# Optional Parameters
- `filters`: Optional filters to limit results. The filter names status and fleetName are supported. When filtering, you must use the complete value of the filtered item. You can use up to three filters, but they must be for the same named item. For example, if you are looking for items with the status Registered or the status Available.
- `maxResults`: When this parameter is used, ListRobots only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListRobots request with the returned nextToken value. This value can be between 1 and 200. If this parameter is not used, then ListRobots returns up to 200 results and a nextToken value if applicable. 
- `nextToken`: The nextToken value returned from a previous paginated ListRobots request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. 
"""
ListRobots(; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listRobots"; aws=aws)
ListRobots(args::AbstractDict{String, Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listRobots", args; aws=aws)

"""
    ListSimulationApplications()

Returns a list of simulation applications. You can optionally provide filters to retrieve specific simulation applications. 

# Optional Parameters
- `filters`: Optional list of filters to limit results. The filter name name is supported. When filtering, you must use the complete value of the filtered item. You can use up to three filters.
- `maxResults`: When this parameter is used, ListSimulationApplications only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListSimulationApplications request with the returned nextToken value. This value can be between 1 and 100. If this parameter is not used, then ListSimulationApplications returns up to 100 results and a nextToken value if applicable. 
- `nextToken`: The nextToken value returned from a previous paginated ListSimulationApplications request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. 
- `versionQualifier`: The version qualifier of the simulation application.
"""
ListSimulationApplications(; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listSimulationApplications"; aws=aws)
ListSimulationApplications(args::AbstractDict{String, Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listSimulationApplications", args; aws=aws)

"""
    ListSimulationJobBatches()

Returns a list simulation job batches. You can optionally provide filters to retrieve specific simulation batch jobs. 

# Optional Parameters
- `filters`: Optional filters to limit results.
- `maxResults`: When this parameter is used, ListSimulationJobBatches only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListSimulationJobBatches request with the returned nextToken value. 
- `nextToken`: The nextToken value returned from a previous paginated ListSimulationJobBatches request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. 
"""
ListSimulationJobBatches(; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listSimulationJobBatches"; aws=aws)
ListSimulationJobBatches(args::AbstractDict{String, Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listSimulationJobBatches", args; aws=aws)

"""
    ListSimulationJobs()

Returns a list of simulation jobs. You can optionally provide filters to retrieve specific simulation jobs. 

# Optional Parameters
- `filters`: Optional filters to limit results. The filter names status and simulationApplicationName and robotApplicationName are supported. When filtering, you must use the complete value of the filtered item. You can use up to three filters, but they must be for the same named item. For example, if you are looking for items with the status Preparing or the status Running.
- `maxResults`: When this parameter is used, ListSimulationJobs only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListSimulationJobs request with the returned nextToken value. This value can be between 1 and 1000. If this parameter is not used, then ListSimulationJobs returns up to 1000 results and a nextToken value if applicable. 
- `nextToken`: The nextToken value returned from a previous paginated ListSimulationJobs request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value.   This token should be treated as an opaque identifier that is only used to retrieve the next items in a list and not for other programmatic purposes. 
"""
ListSimulationJobs(; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listSimulationJobs"; aws=aws)
ListSimulationJobs(args::AbstractDict{String, Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/listSimulationJobs", args; aws=aws)

"""
    ListTagsForResource()

Lists all tags on a AWS RoboMaker resource.

# Required Parameters
- `resourceArn`: The AWS RoboMaker Amazon Resource Name (ARN) with tags to be listed.

"""
ListTagsForResource(resourceArn; aws::AWSConfig=AWS.aws_config) = robomaker("GET", "/tags/$(resourceArn)"; aws=aws)
ListTagsForResource(resourceArn, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("GET", "/tags/$(resourceArn)", args; aws=aws)

"""
    RegisterRobot()

Registers a robot with a fleet.

# Required Parameters
- `fleet`: The Amazon Resource Name (ARN) of the fleet.
- `robot`: The Amazon Resource Name (ARN) of the robot.

"""
RegisterRobot(fleet, robot; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/registerRobot", Dict{String, Any}("fleet"=>fleet, "robot"=>robot); aws=aws)
RegisterRobot(fleet, robot, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/registerRobot", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("fleet"=>fleet, "robot"=>robot), args)); aws=aws)

"""
    RestartSimulationJob()

Restarts a running simulation job.

# Required Parameters
- `job`: The Amazon Resource Name (ARN) of the simulation job.

"""
RestartSimulationJob(job; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/restartSimulationJob", Dict{String, Any}("job"=>job); aws=aws)
RestartSimulationJob(job, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/restartSimulationJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("job"=>job), args)); aws=aws)

"""
    StartSimulationJobBatch()

Starts a new simulation job batch. The batch is defined using one or more SimulationJobRequest objects. 

# Required Parameters
- `createSimulationJobRequests`: A list of simulation job requests to create in the batch.

# Optional Parameters
- `batchPolicy`: The batch policy.
- `clientRequestToken`: Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.
- `tags`: A map that contains tag keys and tag values that are attached to the deployment job batch.
"""
StartSimulationJobBatch(createSimulationJobRequests; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/startSimulationJobBatch", Dict{String, Any}("createSimulationJobRequests"=>createSimulationJobRequests, "clientRequestToken"=>string(uuid4())); aws=aws)
StartSimulationJobBatch(createSimulationJobRequests, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/startSimulationJobBatch", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("createSimulationJobRequests"=>createSimulationJobRequests, "clientRequestToken"=>string(uuid4())), args)); aws=aws)

"""
    SyncDeploymentJob()

Syncrhonizes robots in a fleet to the latest deployment. This is helpful if robots were added after a deployment.

# Required Parameters
- `clientRequestToken`: Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.
- `fleet`: The target fleet for the synchronization.

"""
SyncDeploymentJob(clientRequestToken, fleet; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/syncDeploymentJob", Dict{String, Any}("clientRequestToken"=>clientRequestToken, "fleet"=>fleet); aws=aws)
SyncDeploymentJob(clientRequestToken, fleet, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/syncDeploymentJob", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("clientRequestToken"=>clientRequestToken, "fleet"=>fleet), args)); aws=aws)

"""
    TagResource()

Adds or edits tags for a AWS RoboMaker resource. Each tag consists of a tag key and a tag value. Tag keys and tag values are both required, but tag values can be empty strings.  For information about the rules that apply to tag keys and tag values, see User-Defined Tag Restrictions in the AWS Billing and Cost Management User Guide. 

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the AWS RoboMaker resource you are tagging.
- `tags`: A map that contains tag keys and tag values that are attached to the resource.

"""
TagResource(resourceArn, tags; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/tags/$(resourceArn)", Dict{String, Any}("tags"=>tags); aws=aws)
TagResource(resourceArn, tags, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tags"=>tags), args)); aws=aws)

"""
    UntagResource()

Removes the specified tags from the specified AWS RoboMaker resource. To remove a tag, specify the tag key. To change the tag value of an existing tag key, use  TagResource . 

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the AWS RoboMaker resource you are removing tags.
- `tagKeys`: A map that contains tag keys and tag values that will be unattached from the resource.

"""
UntagResource(resourceArn, tagKeys; aws::AWSConfig=AWS.aws_config) = robomaker("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys); aws=aws)
UntagResource(resourceArn, tagKeys, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("DELETE", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tagKeys"=>tagKeys), args)); aws=aws)

"""
    UpdateRobotApplication()

Updates a robot application.

# Required Parameters
- `application`: The application information for the robot application.
- `robotSoftwareSuite`: The robot software suite (ROS distribution) used by the robot application.
- `sources`: The sources of the robot application.

# Optional Parameters
- `currentRevisionId`: The revision id for the robot application.
"""
UpdateRobotApplication(application, robotSoftwareSuite, sources; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/updateRobotApplication", Dict{String, Any}("application"=>application, "robotSoftwareSuite"=>robotSoftwareSuite, "sources"=>sources); aws=aws)
UpdateRobotApplication(application, robotSoftwareSuite, sources, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/updateRobotApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application, "robotSoftwareSuite"=>robotSoftwareSuite, "sources"=>sources), args)); aws=aws)

"""
    UpdateSimulationApplication()

Updates a simulation application.

# Required Parameters
- `application`: The application information for the simulation application.
- `robotSoftwareSuite`: Information about the robot software suite (ROS distribution).
- `simulationSoftwareSuite`: The simulation software suite used by the simulation application.
- `sources`: The sources of the simulation application.

# Optional Parameters
- `currentRevisionId`: The revision id for the robot application.
- `renderingEngine`: The rendering engine for the simulation application.
"""
UpdateSimulationApplication(application, robotSoftwareSuite, simulationSoftwareSuite, sources; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/updateSimulationApplication", Dict{String, Any}("application"=>application, "robotSoftwareSuite"=>robotSoftwareSuite, "simulationSoftwareSuite"=>simulationSoftwareSuite, "sources"=>sources); aws=aws)
UpdateSimulationApplication(application, robotSoftwareSuite, simulationSoftwareSuite, sources, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = robomaker("POST", "/updateSimulationApplication", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("application"=>application, "robotSoftwareSuite"=>robotSoftwareSuite, "simulationSoftwareSuite"=>simulationSoftwareSuite, "sources"=>sources), args)); aws=aws)
