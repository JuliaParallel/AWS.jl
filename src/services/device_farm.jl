include("../AWSServices.jl")
using .AWSServices: device_farm

"""
    GetDevice()

Gets information about a unique device type.

Required Parameters
{
  "arn": "The device type's ARN."
}
"""
GetDevice(args) = device_farm("GetDevice", args)

"""
    StopJob()

Initiates a stop request for the current job. AWS Device Farm immediately stops the job on the device where tests have not started. You are not billed for this device. On the device where tests have started, setup suite and teardown suite tests run to completion on the device. You are billed for setup, teardown, and any tests that were in progress or already completed.

Required Parameters
{
  "arn": "Represents the Amazon Resource Name (ARN) of the Device Farm job to stop."
}
"""
StopJob(args) = device_farm("StopJob", args)

"""
    UpdateProject()

Modifies the specified project name, given the project ARN and a new name.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the project whose name to update."
}

Optional Parameters
{
  "defaultJobTimeoutMinutes": "The number of minutes a test run in the project executes before it times out.",
  "name": "A string that represents the new name of the project that you are updating."
}
"""
UpdateProject(args) = device_farm("UpdateProject", args)

"""
    CreateDevicePool()

Creates a device pool.

Required Parameters
{
  "name": "The device pool's name.",
  "rules": "The device pool's rules.",
  "projectArn": "The ARN of the project for the device pool."
}

Optional Parameters
{
  "maxDevices": "The number of devices that Device Farm can add to your device pool. Device Farm adds devices that are available and meet the criteria that you assign for the rules parameter. Depending on how many devices meet these constraints, your device pool might contain fewer devices than the value for this parameter. By specifying the maximum number of devices, you can control the costs that you incur by running tests.",
  "description": "The device pool's description."
}
"""
CreateDevicePool(args) = device_farm("CreateDevicePool", args)

"""
    ListUploads()

Gets information about uploads, given an AWS Device Farm project ARN.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the project for which you want to list uploads."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list.",
  "type": "The type of upload. Must be one of the following values:   ANDROID_APP   IOS_APP   WEB_APP   EXTERNAL_DATA   APPIUM_JAVA_JUNIT_TEST_PACKAGE   APPIUM_JAVA_TESTNG_TEST_PACKAGE   APPIUM_PYTHON_TEST_PACKAGE   APPIUM_NODE_TEST_PACKAGE   APPIUM_RUBY_TEST_PACKAGE   APPIUM_WEB_JAVA_JUNIT_TEST_PACKAGE   APPIUM_WEB_JAVA_TESTNG_TEST_PACKAGE   APPIUM_WEB_PYTHON_TEST_PACKAGE   APPIUM_WEB_NODE_TEST_PACKAGE   APPIUM_WEB_RUBY_TEST_PACKAGE   CALABASH_TEST_PACKAGE   INSTRUMENTATION_TEST_PACKAGE   UIAUTOMATION_TEST_PACKAGE   UIAUTOMATOR_TEST_PACKAGE   XCTEST_TEST_PACKAGE   XCTEST_UI_TEST_PACKAGE   APPIUM_JAVA_JUNIT_TEST_SPEC   APPIUM_JAVA_TESTNG_TEST_SPEC   APPIUM_PYTHON_TEST_SPEC   APPIUM_NODE_TEST_SPEC    APPIUM_RUBY_TEST_SPEC   APPIUM_WEB_JAVA_JUNIT_TEST_SPEC   APPIUM_WEB_JAVA_TESTNG_TEST_SPEC   APPIUM_WEB_PYTHON_TEST_SPEC   APPIUM_WEB_NODE_TEST_SPEC   APPIUM_WEB_RUBY_TEST_SPEC   INSTRUMENTATION_TEST_SPEC   XCTEST_UI_TEST_SPEC  "
}
"""
ListUploads(args) = device_farm("ListUploads", args)

"""
    RenewOffering()

Explicitly sets the quantity of devices to renew for an offering, starting from the effectiveDate of the next period. The API returns a NotEligible error if the user is not permitted to invoke the operation. If you must be able to invoke this operation, contact aws-devicefarm-support@amazon.com.

Optional Parameters
{
  "offeringId": "The ID of a request to renew an offering.",
  "quantity": "The quantity requested in an offering renewal."
}
"""
RenewOffering() = device_farm("RenewOffering")
RenewOffering(args) = device_farm("RenewOffering", args)

"""
    DeleteUpload()

Deletes an upload given the upload ARN.

Required Parameters
{
  "arn": "Represents the Amazon Resource Name (ARN) of the Device Farm upload to delete."
}
"""
DeleteUpload(args) = device_farm("DeleteUpload", args)

"""
    GetInstanceProfile()

Returns information about the specified instance profile.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of an instance profile."
}
"""
GetInstanceProfile(args) = device_farm("GetInstanceProfile", args)

"""
    GetDeviceInstance()

Returns information about a device instance that belongs to a private device fleet.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the instance you're requesting information about."
}
"""
GetDeviceInstance(args) = device_farm("GetDeviceInstance", args)

"""
    ListOfferingTransactions()

Returns a list of all historical purchases, renewals, and system renewal transactions for an AWS account. The list is paginated and ordered by a descending timestamp (most recent transactions are first). The API returns a NotEligible error if the user is not permitted to invoke the operation. If you must be able to invoke this operation, contact aws-devicefarm-support@amazon.com.

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListOfferingTransactions() = device_farm("ListOfferingTransactions")
ListOfferingTransactions(args) = device_farm("ListOfferingTransactions", args)

"""
    TagResource()

Associates the specified tags to a resource with the specified resourceArn. If existing tags on a resource are not specified in the request parameters, they are not changed. When a resource is deleted, the tags associated with that resource are also deleted.

Required Parameters
{
  "ResourceARN": "The Amazon Resource Name (ARN) of the resource or resources to which to add tags. You can associate tags with the following Device Farm resources: PROJECT, RUN, NETWORK_PROFILE, INSTANCE_PROFILE, DEVICE_INSTANCE, SESSION, DEVICE_POOL, DEVICE, and VPCE_CONFIGURATION.",
  "Tags": "The tags to add to the resource. A tag is an array of key-value pairs. Tag keys can have a maximum character length of 128 characters. Tag values can have a maximum length of 256 characters."
}
"""
TagResource(args) = device_farm("TagResource", args)

"""
    DeleteProject()

Deletes an AWS Device Farm project, given the project ARN.  Deleting this resource does not stop an in-progress run.

Required Parameters
{
  "arn": "Represents the Amazon Resource Name (ARN) of the Device Farm project to delete."
}
"""
DeleteProject(args) = device_farm("DeleteProject", args)

"""
    DeleteDevicePool()

Deletes a device pool given the pool ARN. Does not allow deletion of curated pools owned by the system.

Required Parameters
{
  "arn": "Represents the Amazon Resource Name (ARN) of the Device Farm device pool to delete."
}
"""
DeleteDevicePool(args) = device_farm("DeleteDevicePool", args)

"""
    UpdateDeviceInstance()

Updates information about a private device instance.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the device instance."
}

Optional Parameters
{
  "labels": "An array of strings that you want to associate with the device instance.",
  "profileArn": "The ARN of the profile that you want to associate with the device instance."
}
"""
UpdateDeviceInstance(args) = device_farm("UpdateDeviceInstance", args)

"""
    UpdateDevicePool()

Modifies the name, description, and rules in a device pool given the attributes and the pool ARN. Rule updates are all-or-nothing, meaning they can only be updated as a whole (or not at all).

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the Device Farm device pool to update."
}

Optional Parameters
{
  "name": "A string that represents the name of the device pool to update.",
  "maxDevices": "The number of devices that Device Farm can add to your device pool. Device Farm adds devices that are available and that meet the criteria that you assign for the rules parameter. Depending on how many devices meet these constraints, your device pool might contain fewer devices than the value for this parameter. By specifying the maximum number of devices, you can control the costs that you incur by running tests. If you use this parameter in your request, you cannot use the clearMaxDevices parameter in the same request.",
  "clearMaxDevices": "Sets whether the maxDevices parameter applies to your device pool. If you set this parameter to true, the maxDevices parameter does not apply, and Device Farm does not limit the number of devices that it adds to your device pool. In this case, Device Farm adds all available devices that meet the criteria specified in the rules parameter. If you use this parameter in your request, you cannot use the maxDevices parameter in the same request.",
  "rules": "Represents the rules to modify for the device pool. Updating rules is optional. If you update rules for your request, the update replaces the existing rules.",
  "description": "A description of the device pool to update."
}
"""
UpdateDevicePool(args) = device_farm("UpdateDevicePool", args)

"""
    ListInstanceProfiles()

Returns information about all the instance profiles in an AWS account.

Optional Parameters
{
  "maxResults": "An integer that specifies the maximum number of items you want to return in the API response.",
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListInstanceProfiles() = device_farm("ListInstanceProfiles")
ListInstanceProfiles(args) = device_farm("ListInstanceProfiles", args)

"""
    CreateUpload()

Uploads an app or test scripts.

Required Parameters
{
  "name": "The upload's file name. The name should not contain any forward slashes (/). If you are uploading an iOS app, the file name must end with the .ipa extension. If you are uploading an Android app, the file name must end with the .apk extension. For all others, the file name must end with the .zip file extension.",
  "type": "The upload's upload type. Must be one of the following values:   ANDROID_APP   IOS_APP   WEB_APP   EXTERNAL_DATA   APPIUM_JAVA_JUNIT_TEST_PACKAGE   APPIUM_JAVA_TESTNG_TEST_PACKAGE   APPIUM_PYTHON_TEST_PACKAGE   APPIUM_NODE_TEST_PACKAGE   APPIUM_RUBY_TEST_PACKAGE   APPIUM_WEB_JAVA_JUNIT_TEST_PACKAGE   APPIUM_WEB_JAVA_TESTNG_TEST_PACKAGE   APPIUM_WEB_PYTHON_TEST_PACKAGE   APPIUM_WEB_NODE_TEST_PACKAGE   APPIUM_WEB_RUBY_TEST_PACKAGE   CALABASH_TEST_PACKAGE   INSTRUMENTATION_TEST_PACKAGE   UIAUTOMATION_TEST_PACKAGE   UIAUTOMATOR_TEST_PACKAGE   XCTEST_TEST_PACKAGE   XCTEST_UI_TEST_PACKAGE   APPIUM_JAVA_JUNIT_TEST_SPEC   APPIUM_JAVA_TESTNG_TEST_SPEC   APPIUM_PYTHON_TEST_SPEC   APPIUM_NODE_TEST_SPEC   APPIUM_RUBY_TEST_SPEC   APPIUM_WEB_JAVA_JUNIT_TEST_SPEC   APPIUM_WEB_JAVA_TESTNG_TEST_SPEC   APPIUM_WEB_PYTHON_TEST_SPEC   APPIUM_WEB_NODE_TEST_SPEC   APPIUM_WEB_RUBY_TEST_SPEC   INSTRUMENTATION_TEST_SPEC   XCTEST_UI_TEST_SPEC    If you call CreateUpload with WEB_APP specified, AWS Device Farm throws an ArgumentException error.",
  "projectArn": "The ARN of the project for the upload."
}

Optional Parameters
{
  "contentType": "The upload's content type (for example, application/octet-stream)."
}
"""
CreateUpload(args) = device_farm("CreateUpload", args)

"""
    CreateTestGridProject()

Creates a Selenium testing project. Projects are used to track TestGridSession instances.

Required Parameters
{
  "name": "Human-readable name of the Selenium testing project."
}

Optional Parameters
{
  "description": "Human-readable description of the project."
}
"""
CreateTestGridProject(args) = device_farm("CreateTestGridProject", args)

"""
    DeleteRemoteAccessSession()

Deletes a completed remote access session and its results.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the session for which you want to delete remote access."
}
"""
DeleteRemoteAccessSession(args) = device_farm("DeleteRemoteAccessSession", args)

"""
    UpdateInstanceProfile()

Updates information about an existing private device instance profile.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the instance profile."
}

Optional Parameters
{
  "rebootAfterUse": "The updated choice for whether you want to reboot the device after use. The default value is true.",
  "name": "The updated name for your instance profile.",
  "packageCleanup": "The updated choice for whether you want to specify package cleanup. The default value is false for private devices.",
  "excludeAppPackagesFromCleanup": "An array of strings that specifies the list of app packages that should not be cleaned up from the device after a test run is over. The list of packages is only considered if you set packageCleanup to true.",
  "description": "The updated description for your instance profile."
}
"""
UpdateInstanceProfile(args) = device_farm("UpdateInstanceProfile", args)

"""
    UpdateTestGridProject()

Change details of a project.

Required Parameters
{
  "projectArn": "ARN of the project to update."
}

Optional Parameters
{
  "name": "Human-readable name for the project.",
  "description": "Human-readable description for the project."
}
"""
UpdateTestGridProject(args) = device_farm("UpdateTestGridProject", args)

"""
    ListDevices()

Gets information about unique device types.

Optional Parameters
{
  "filters": "Used to select a set of devices. A filter is made up of an attribute, an operator, and one or more values.   Attribute: The aspect of a device such as platform or model used as the selection criteria in a device filter. Allowed values include:   ARN: The Amazon Resource Name (ARN) of the device (for example, arn:aws:devicefarm:us-west-2::device:12345Example).   PLATFORM: The device platform. Valid values are ANDROID or IOS.   OS_VERSION: The operating system version (for example, 10.3.2).   MODEL: The device model (for example, iPad 5th Gen).   AVAILABILITY: The current availability of the device. Valid values are AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.   FORM_FACTOR: The device form factor. Valid values are PHONE or TABLET.   MANUFACTURER: The device manufacturer (for example, Apple).   REMOTE_ACCESS_ENABLED: Whether the device is enabled for remote access. Valid values are TRUE or FALSE.   REMOTE_DEBUG_ENABLED: Whether the device is enabled for remote debugging. Valid values are TRUE or FALSE. Because remote debugging is no longer supported, this attribute is ignored.   INSTANCE_ARN: The Amazon Resource Name (ARN) of the device instance.   INSTANCE_LABELS: The label of the device instance.   FLEET_TYPE: The fleet type. Valid values are PUBLIC or PRIVATE.     Operator: The filter operator.   The EQUALS operator is available for every attribute except INSTANCE_LABELS.   The CONTAINS operator is available for the INSTANCE_LABELS and MODEL attributes.   The IN and NOT_IN operators are available for the ARN, OS_VERSION, MODEL, MANUFACTURER, and INSTANCE_ARN attributes.   The LESS_THAN, GREATER_THAN, LESS_THAN_OR_EQUALS, and GREATER_THAN_OR_EQUALS operators are also available for the OS_VERSION attribute.     Values: An array of one or more filter values.   The IN and NOT_IN operators take a values array that has one or more elements.   The other operators require an array with a single element.   In a request, the AVAILABILITY attribute takes the following values: AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.    ",
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list.",
  "arn": "The Amazon Resource Name (ARN) of the project."
}
"""
ListDevices() = device_farm("ListDevices")
ListDevices(args) = device_farm("ListDevices", args)

"""
    CreateNetworkProfile()

Creates a network profile.

Required Parameters
{
  "name": "The name for the new network profile.",
  "projectArn": "The Amazon Resource Name (ARN) of the project for which you want to create a network profile."
}

Optional Parameters
{
  "uplinkBandwidthBits": "The data throughput rate in bits per second, as an integer from 0 to 104857600.",
  "downlinkBandwidthBits": "The data throughput rate in bits per second, as an integer from 0 to 104857600.",
  "downlinkDelayMs": "Delay time for all packets to destination in milliseconds as an integer from 0 to 2000.",
  "uplinkDelayMs": "Delay time for all packets to destination in milliseconds as an integer from 0 to 2000.",
  "downlinkJitterMs": "Time variation in the delay of received packets in milliseconds as an integer from 0 to 2000.",
  "uplinkLossPercent": "Proportion of transmitted packets that fail to arrive from 0 to 100 percent.",
  "uplinkJitterMs": "Time variation in the delay of received packets in milliseconds as an integer from 0 to 2000.",
  "description": "The description of the network profile.",
  "downlinkLossPercent": "Proportion of received packets that fail to arrive from 0 to 100 percent.",
  "type": "The type of network profile to create. Valid values are listed here."
}
"""
CreateNetworkProfile(args) = device_farm("CreateNetworkProfile", args)

"""
    ListDeviceInstances()

Returns information about the private device instances associated with one or more AWS accounts.

Optional Parameters
{
  "maxResults": "An integer that specifies the maximum number of items you want to return in the API response.",
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListDeviceInstances() = device_farm("ListDeviceInstances")
ListDeviceInstances(args) = device_farm("ListDeviceInstances", args)

"""
    ListTestGridProjects()

Gets a list of all Selenium testing projects in your account.

Optional Parameters
{
  "maxResult": "Return no more than this number of results.",
  "nextToken": "From a response, used to continue a paginated listing. "
}
"""
ListTestGridProjects() = device_farm("ListTestGridProjects")
ListTestGridProjects(args) = device_farm("ListTestGridProjects", args)

"""
    CreateVPCEConfiguration()

Creates a configuration record in Device Farm for your Amazon Virtual Private Cloud (VPC) endpoint.

Required Parameters
{
  "vpceConfigurationName": "The friendly name you give to your VPC endpoint configuration, to manage your configurations more easily.",
  "serviceDnsName": "The DNS name of the service running in your VPC that you want Device Farm to test.",
  "vpceServiceName": "The name of the VPC endpoint service running in your AWS account that you want Device Farm to test."
}

Optional Parameters
{
  "vpceConfigurationDescription": "An optional description that provides details about your VPC endpoint configuration."
}
"""
CreateVPCEConfiguration(args) = device_farm("CreateVPCEConfiguration", args)

"""
    GetDevicePool()

Gets information about a device pool.

Required Parameters
{
  "arn": "The device pool's ARN."
}
"""
GetDevicePool(args) = device_farm("GetDevicePool", args)

"""
    CreateTestGridUrl()

Creates a signed, short-term URL that can be passed to a Selenium RemoteWebDriver constructor.

Required Parameters
{
  "expiresInSeconds": "Lifetime, in seconds, of the URL.",
  "projectArn": "ARN (from CreateTestGridProject or ListTestGridProjects) to associate with the short-term URL. "
}
"""
CreateTestGridUrl(args) = device_farm("CreateTestGridUrl", args)

"""
    GetTest()

Gets information about a test.

Required Parameters
{
  "arn": "The test's ARN."
}
"""
GetTest(args) = device_farm("GetTest", args)

"""
    GetUpload()

Gets information about an upload.

Required Parameters
{
  "arn": "The upload's ARN."
}
"""
GetUpload(args) = device_farm("GetUpload", args)

"""
    ListRuns()

Gets information about runs, given an AWS Device Farm project ARN.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the project for which you want to list runs."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListRuns(args) = device_farm("ListRuns", args)

"""
    ListSamples()

Gets information about samples, given an AWS Device Farm job ARN.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the job used to list samples."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListSamples(args) = device_farm("ListSamples", args)

"""
    UntagResource()

Deletes the specified tags from a resource.

Required Parameters
{
  "ResourceARN": "The Amazon Resource Name (ARN) of the resource or resources from which to delete tags. You can associate tags with the following Device Farm resources: PROJECT, RUN, NETWORK_PROFILE, INSTANCE_PROFILE, DEVICE_INSTANCE, SESSION, DEVICE_POOL, DEVICE, and VPCE_CONFIGURATION.",
  "TagKeys": "The keys of the tags to be removed."
}
"""
UntagResource(args) = device_farm("UntagResource", args)

"""
    PurchaseOffering()

Immediately purchases offerings for an AWS account. Offerings renew with the latest total purchased quantity for an offering, unless the renewal was overridden. The API returns a NotEligible error if the user is not permitted to invoke the operation. If you must be able to invoke this operation, contact aws-devicefarm-support@amazon.com.

Optional Parameters
{
  "offeringPromotionId": "The ID of the offering promotion to be applied to the purchase.",
  "offeringId": "The ID of the offering.",
  "quantity": "The number of device slots to purchase in an offering request."
}
"""
PurchaseOffering() = device_farm("PurchaseOffering")
PurchaseOffering(args) = device_farm("PurchaseOffering", args)

"""
    DeleteInstanceProfile()

Deletes a profile that can be applied to one or more private device instances.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the instance profile you are requesting to delete."
}
"""
DeleteInstanceProfile(args) = device_farm("DeleteInstanceProfile", args)

"""
    GetRemoteAccessSession()

Returns a link to a currently running remote access session.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the remote access session about which you want to get session information."
}
"""
GetRemoteAccessSession(args) = device_farm("GetRemoteAccessSession", args)

"""
    GetRun()

Gets information about a run.

Required Parameters
{
  "arn": "The run's ARN."
}
"""
GetRun(args) = device_farm("GetRun", args)

"""
    ListOfferings()

Returns a list of products or offerings that the user can manage through the API. Each offering record indicates the recurring price per unit and the frequency for that offering. The API returns a NotEligible error if the user is not permitted to invoke the operation. If you must be able to invoke this operation, contact aws-devicefarm-support@amazon.com.

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListOfferings() = device_farm("ListOfferings")
ListOfferings(args) = device_farm("ListOfferings", args)

"""
    ListTestGridSessionActions()

Returns a list of the actions taken in a TestGridSession.

Required Parameters
{
  "sessionArn": "The ARN of the session to retrieve."
}

Optional Parameters
{
  "maxResult": "The maximum number of sessions to return per response.",
  "nextToken": "Pagination token."
}
"""
ListTestGridSessionActions(args) = device_farm("ListTestGridSessionActions", args)

"""
    ListTagsForResource()

List the tags for an AWS Device Farm resource.

Required Parameters
{
  "ResourceARN": "The Amazon Resource Name (ARN) of the resource or resources for which to list tags. You can associate tags with the following Device Farm resources: PROJECT, RUN, NETWORK_PROFILE, INSTANCE_PROFILE, DEVICE_INSTANCE, SESSION, DEVICE_POOL, DEVICE, and VPCE_CONFIGURATION."
}
"""
ListTagsForResource(args) = device_farm("ListTagsForResource", args)

"""
    GetDevicePoolCompatibility()

Gets information about compatibility with a device pool.

Required Parameters
{
  "devicePoolArn": "The device pool's ARN."
}

Optional Parameters
{
  "appArn": "The ARN of the app that is associated with the specified device pool.",
  "test": "Information about the uploaded test to be run against the device pool.",
  "testType": "The test type for the specified device pool. Allowed values include the following:   BUILTIN_FUZZ.   BUILTIN_EXPLORER. For Android, an app explorer that traverses an Android app, interacting with it and capturing screenshots at the same time.   APPIUM_JAVA_JUNIT.   APPIUM_JAVA_TESTNG.   APPIUM_PYTHON.   APPIUM_NODE.   APPIUM_RUBY.   APPIUM_WEB_JAVA_JUNIT.   APPIUM_WEB_JAVA_TESTNG.   APPIUM_WEB_PYTHON.   APPIUM_WEB_NODE.   APPIUM_WEB_RUBY.   CALABASH.   INSTRUMENTATION.   UIAUTOMATION.   UIAUTOMATOR.   XCTEST.   XCTEST_UI.  ",
  "configuration": "An object that contains information about the settings for a run."
}
"""
GetDevicePoolCompatibility(args) = device_farm("GetDevicePoolCompatibility", args)

"""
    GetVPCEConfiguration()

Returns information about the configuration settings for your Amazon Virtual Private Cloud (VPC) endpoint.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the VPC endpoint configuration you want to describe."
}
"""
GetVPCEConfiguration(args) = device_farm("GetVPCEConfiguration", args)

"""
    ListRemoteAccessSessions()

Returns a list of all currently running remote access sessions.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the project about which you are requesting information."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListRemoteAccessSessions(args) = device_farm("ListRemoteAccessSessions", args)

"""
    UpdateUpload()

Updates an uploaded test spec.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the uploaded test spec."
}

Optional Parameters
{
  "name": "The upload's test spec file name. The name must not contain any forward slashes (/). The test spec file name must end with the .yaml or .yml file extension.",
  "editContent": "Set to true if the YAML file has changed and must be updated. Otherwise, set to false.",
  "contentType": "The upload's content type (for example, application/x-yaml)."
}
"""
UpdateUpload(args) = device_farm("UpdateUpload", args)

"""
    DeleteVPCEConfiguration()

Deletes a configuration for your Amazon Virtual Private Cloud (VPC) endpoint.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the VPC endpoint configuration you want to delete."
}
"""
DeleteVPCEConfiguration(args) = device_farm("DeleteVPCEConfiguration", args)

"""
    GetOfferingStatus()

Gets the current status and future status of all offerings purchased by an AWS account. The response indicates how many offerings are currently available and the offerings that will be available in the next period. The API returns a NotEligible error if the user is not permitted to invoke the operation. If you must be able to invoke this operation, contact aws-devicefarm-support@amazon.com.

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
GetOfferingStatus() = device_farm("GetOfferingStatus")
GetOfferingStatus(args) = device_farm("GetOfferingStatus", args)

"""
    DeleteNetworkProfile()

Deletes a network profile.

Required Parameters
{
  "arn": "The ARN of the network profile to delete."
}
"""
DeleteNetworkProfile(args) = device_farm("DeleteNetworkProfile", args)

"""
    GetSuite()

Gets information about a suite.

Required Parameters
{
  "arn": "The suite's ARN."
}
"""
GetSuite(args) = device_farm("GetSuite", args)

"""
    ListSuites()

Gets information about test suites for a given job.

Required Parameters
{
  "arn": "The job's Amazon Resource Name (ARN)."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListSuites(args) = device_farm("ListSuites", args)

"""
    UpdateNetworkProfile()

Updates the network profile.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the project for which you want to update network profile settings."
}

Optional Parameters
{
  "name": "The name of the network profile about which you are returning information.",
  "uplinkBandwidthBits": "The data throughput rate in bits per second, as an integer from 0 to 104857600.",
  "description": "The description of the network profile about which you are returning information.",
  "downlinkLossPercent": "Proportion of received packets that fail to arrive from 0 to 100 percent.",
  "downlinkBandwidthBits": "The data throughput rate in bits per second, as an integer from 0 to 104857600.",
  "downlinkDelayMs": "Delay time for all packets to destination in milliseconds as an integer from 0 to 2000.",
  "downlinkJitterMs": "Time variation in the delay of received packets in milliseconds as an integer from 0 to 2000.",
  "uplinkJitterMs": "Time variation in the delay of received packets in milliseconds as an integer from 0 to 2000.",
  "uplinkDelayMs": "Delay time for all packets to destination in milliseconds as an integer from 0 to 2000.",
  "uplinkLossPercent": "Proportion of transmitted packets that fail to arrive from 0 to 100 percent.",
  "type": "The type of network profile to return information about. Valid values are listed here."
}
"""
UpdateNetworkProfile(args) = device_farm("UpdateNetworkProfile", args)

"""
    ScheduleRun()

Schedules a run.

Required Parameters
{
  "test": "Information about the test for the run to be scheduled.",
  "projectArn": "The ARN of the project for the run to be scheduled."
}

Optional Parameters
{
  "devicePoolArn": "The ARN of the device pool for the run to be scheduled.",
  "name": "The name for the run to be scheduled.",
  "appArn": "The ARN of an application package to run tests against, created with CreateUpload. See ListUploads.",
  "executionConfiguration": "Specifies configuration information about a test run, such as the execution timeout (in minutes).",
  "deviceSelectionConfiguration": "The filter criteria used to dynamically select a set of devices for a test run and the maximum number of devices to be included in the run. Either  devicePoolArn  or  deviceSelectionConfiguration  is required in a request.",
  "configuration": "Information about the settings for the run to be scheduled."
}
"""
ScheduleRun(args) = device_farm("ScheduleRun", args)

"""
    ListDevicePools()

Gets information about device pools.

Required Parameters
{
  "arn": "The project ARN."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list.",
  "type": "The device pools' type. Allowed values include:   CURATED: A device pool that is created and managed by AWS Device Farm.   PRIVATE: A device pool that is created and managed by the device pool developer.  "
}
"""
ListDevicePools(args) = device_farm("ListDevicePools", args)

"""
    CreateInstanceProfile()

Creates a profile that can be applied to one or more private fleet device instances.

Required Parameters
{
  "name": "The name of your instance profile."
}

Optional Parameters
{
  "rebootAfterUse": "When set to true, Device Farm reboots the instance after a test run. The default value is true.",
  "packageCleanup": "When set to true, Device Farm removes app packages after a test run. The default value is false for private devices.",
  "excludeAppPackagesFromCleanup": "An array of strings that specifies the list of app packages that should not be cleaned up from the device after a test run. The list of packages is considered only if you set packageCleanup to true.",
  "description": "The description of your instance profile."
}
"""
CreateInstanceProfile(args) = device_farm("CreateInstanceProfile", args)

"""
    ListTestGridSessions()

Retrieves a list of sessions for a TestGridProject.

Required Parameters
{
  "projectArn": "ARN of a TestGridProject."
}

Optional Parameters
{
  "maxResult": "Return only this many results at a time.",
  "creationTimeBefore": "Return only sessions created before this time.",
  "creationTimeAfter": "Return only sessions created after this time.",
  "status": "Return only sessions in this state.",
  "endTimeAfter": "Return only sessions that ended after this time.",
  "nextToken": "Pagination token.",
  "endTimeBefore": "Return only sessions that ended before this time."
}
"""
ListTestGridSessions(args) = device_farm("ListTestGridSessions", args)

"""
    ListOfferingPromotions()

Returns a list of offering promotions. Each offering promotion record contains the ID and description of the promotion. The API returns a NotEligible error if the caller is not permitted to invoke the operation. Contact aws-devicefarm-support@amazon.com if you must be able to invoke this operation.

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListOfferingPromotions() = device_farm("ListOfferingPromotions")
ListOfferingPromotions(args) = device_farm("ListOfferingPromotions", args)

"""
    ListVPCEConfigurations()

Returns information about all Amazon Virtual Private Cloud (VPC) endpoint configurations in the AWS account.

Optional Parameters
{
  "maxResults": "An integer that specifies the maximum number of items you want to return in the API response.",
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListVPCEConfigurations() = device_farm("ListVPCEConfigurations")
ListVPCEConfigurations(args) = device_farm("ListVPCEConfigurations", args)

"""
    ListNetworkProfiles()

Returns the list of available network profiles.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the project for which you want to list network profiles."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list.",
  "type": "The type of network profile to return information about. Valid values are listed here."
}
"""
ListNetworkProfiles(args) = device_farm("ListNetworkProfiles", args)

"""
    ListTestGridSessionArtifacts()

Retrieves a list of artifacts created during the session.

Required Parameters
{
  "sessionArn": "The ARN of a TestGridSession. "
}

Optional Parameters
{
  "maxResult": "The maximum number of results to be returned by a request.",
  "nextToken": "Pagination token.",
  "type": "Limit results to a specified type of artifact."
}
"""
ListTestGridSessionArtifacts(args) = device_farm("ListTestGridSessionArtifacts", args)

"""
    CreateRemoteAccessSession()

Specifies and starts a remote access session.

Required Parameters
{
  "deviceArn": "The ARN of the device for which you want to create a remote access session.",
  "projectArn": "The Amazon Resource Name (ARN) of the project for which you want to create a remote access session."
}

Optional Parameters
{
  "remoteRecordAppArn": "The Amazon Resource Name (ARN) for the app to be recorded in the remote access session.",
  "name": "The name of the remote access session to create.",
  "remoteDebugEnabled": "Set to true if you want to access devices remotely for debugging in your remote access session. Remote debugging is no longer supported.",
  "skipAppResign": "When set to true, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again. For more information on how Device Farm modifies your uploads during tests, see Do you modify my app? ",
  "remoteRecordEnabled": "Set to true to enable remote recording for the remote access session.",
  "instanceArn": "The Amazon Resource Name (ARN) of the device instance for which you want to create a remote access session.",
  "interactionMode": "The interaction mode of the remote access session. Valid values are:   INTERACTIVE: You can interact with the iOS device by viewing, touching, and rotating the screen. You cannot run XCUITest framework-based tests in this mode.   NO_VIDEO: You are connected to the device, but cannot interact with it or view the screen. This mode has the fastest test execution speed. You can run XCUITest framework-based tests in this mode.   VIDEO_ONLY: You can view the screen, but cannot touch or rotate it. You can run XCUITest framework-based tests and watch the screen in this mode.  ",
  "clientId": "Unique identifier for the client. If you want access to multiple devices on the same client, you should pass the same clientId value in each call to CreateRemoteAccessSession. This identifier is required only if remoteDebugEnabled is set to true. Remote debugging is no longer supported.",
  "sshPublicKey": "Ignored. The public key of the ssh key pair you want to use for connecting to remote devices in your remote debugging session. This key is required only if remoteDebugEnabled is set to true. Remote debugging is no longer supported.",
  "configuration": "The configuration information for the remote access session request."
}
"""
CreateRemoteAccessSession(args) = device_farm("CreateRemoteAccessSession", args)

"""
    GetAccountSettings()

Returns the number of unmetered iOS or unmetered Android devices that have been purchased by the account.
"""
GetAccountSettings() = device_farm("GetAccountSettings")
GetAccountSettings(args) = device_farm("GetAccountSettings", args)

"""
    GetNetworkProfile()

Returns information about a network profile.

Required Parameters
{
  "arn": "The ARN of the network profile to return information about."
}
"""
GetNetworkProfile(args) = device_farm("GetNetworkProfile", args)

"""
    ListTests()

Gets information about tests in a given test suite.

Required Parameters
{
  "arn": "The test suite's Amazon Resource Name (ARN)."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListTests(args) = device_farm("ListTests", args)

"""
    CreateProject()

Creates a project.

Required Parameters
{
  "name": "The project's name."
}

Optional Parameters
{
  "defaultJobTimeoutMinutes": "Sets the execution timeout value (in minutes) for a project. All test runs in this project use the specified execution timeout value unless overridden when scheduling a run."
}
"""
CreateProject(args) = device_farm("CreateProject", args)

"""
    GetTestGridProject()

Retrieves information about a Selenium testing project.

Required Parameters
{
  "projectArn": "The ARN of the Selenium testing project, from either CreateTestGridProject or ListTestGridProjects."
}
"""
GetTestGridProject(args) = device_farm("GetTestGridProject", args)

"""
    ListProjects()

Gets information about projects.

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list.",
  "arn": "Optional. If no Amazon Resource Name (ARN) is specified, then AWS Device Farm returns a list of all projects for the AWS account. You can also specify a project ARN."
}
"""
ListProjects() = device_farm("ListProjects")
ListProjects(args) = device_farm("ListProjects", args)

"""
    StopRun()

Initiates a stop request for the current test run. AWS Device Farm immediately stops the run on devices where tests have not started. You are not billed for these devices. On devices where tests have started executing, setup suite and teardown suite tests run to completion on those devices. You are billed for setup, teardown, and any tests that were in progress or already completed.

Required Parameters
{
  "arn": "Represents the Amazon Resource Name (ARN) of the Device Farm run to stop."
}
"""
StopRun(args) = device_farm("StopRun", args)

"""
    GetTestGridSession()

A session is an instance of a browser created through a RemoteWebDriver with the URL from CreateTestGridUrlResult url. You can use the following to look up sessions:   The session ARN (GetTestGridSessionRequest sessionArn).   The project ARN and a session ID (GetTestGridSessionRequest projectArn and GetTestGridSessionRequest sessionId).   

Optional Parameters
{
  "sessionId": "An ID associated with this session.",
  "sessionArn": "An ARN that uniquely identifies a TestGridSession.",
  "projectArn": "The ARN for the project that this session belongs to. See CreateTestGridProject and ListTestGridProjects."
}
"""
GetTestGridSession() = device_farm("GetTestGridSession")
GetTestGridSession(args) = device_farm("GetTestGridSession", args)

"""
    GetJob()

Gets information about a job.

Required Parameters
{
  "arn": "The job's ARN."
}
"""
GetJob(args) = device_farm("GetJob", args)

"""
    UpdateVPCEConfiguration()

Updates information about an Amazon Virtual Private Cloud (VPC) endpoint configuration.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the VPC endpoint configuration you want to update."
}

Optional Parameters
{
  "vpceConfigurationDescription": "An optional description that provides details about your VPC endpoint configuration.",
  "vpceConfigurationName": "The friendly name you give to your VPC endpoint configuration to manage your configurations more easily.",
  "serviceDnsName": "The DNS (domain) name used to connect to your private service in your VPC. The DNS name must not already be in use on the internet.",
  "vpceServiceName": "The name of the VPC endpoint service running in your AWS account that you want Device Farm to test."
}
"""
UpdateVPCEConfiguration(args) = device_farm("UpdateVPCEConfiguration", args)

"""
    DeleteTestGridProject()

 Deletes a Selenium testing project and all content generated under it.   You cannot undo this operation.   You cannot delete a project if it has active sessions. 

Required Parameters
{
  "projectArn": "The ARN of the project to delete, from CreateTestGridProject or ListTestGridProjects."
}
"""
DeleteTestGridProject(args) = device_farm("DeleteTestGridProject", args)

"""
    InstallToRemoteAccessSession()

Installs an application to the device in a remote access session. For Android applications, the file must be in .apk format. For iOS applications, the file must be in .ipa format.

Required Parameters
{
  "appArn": "The ARN of the app about which you are requesting information.",
  "remoteAccessSessionArn": "The Amazon Resource Name (ARN) of the remote access session about which you are requesting information."
}
"""
InstallToRemoteAccessSession(args) = device_farm("InstallToRemoteAccessSession", args)

"""
    DeleteRun()

Deletes the run, given the run ARN.  Deleting this resource does not stop an in-progress run.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) for the run to delete."
}
"""
DeleteRun(args) = device_farm("DeleteRun", args)

"""
    GetProject()

Gets information about a project.

Required Parameters
{
  "arn": "The project's ARN."
}
"""
GetProject(args) = device_farm("GetProject", args)

"""
    ListJobs()

Gets information about jobs for a given test run.

Required Parameters
{
  "arn": "The run's Amazon Resource Name (ARN)."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListJobs(args) = device_farm("ListJobs", args)

"""
    ListUniqueProblems()

Gets information about unique problems, such as exceptions or crashes. Unique problems are defined as a single instance of an error across a run, job, or suite. For example, if a call in your application consistently raises an exception (OutOfBoundsException in MyActivity.java:386), ListUniqueProblems returns a single entry instead of many individual entries for that exception.

Required Parameters
{
  "arn": "The unique problems' ARNs."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListUniqueProblems(args) = device_farm("ListUniqueProblems", args)

"""
    ListArtifacts()

Gets information about artifacts.

Required Parameters
{
  "type": "The artifacts' type. Allowed values include:   FILE   LOG   SCREENSHOT  ",
  "arn": "The run, job, suite, or test ARN."
}

Optional Parameters
{
  "nextToken": "An identifier that was returned from the previous call to this operation, which can be used to return the next set of items in the list."
}
"""
ListArtifacts(args) = device_farm("ListArtifacts", args)

"""
    StopRemoteAccessSession()

Ends a specified remote access session.

Required Parameters
{
  "arn": "The Amazon Resource Name (ARN) of the remote access session to stop."
}
"""
StopRemoteAccessSession(args) = device_farm("StopRemoteAccessSession", args)