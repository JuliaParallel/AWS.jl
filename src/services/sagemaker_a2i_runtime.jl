# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
include("_utilities.jl")
using Compat
using UUIDs
using .AWSServices: sagemaker_a2i_runtime

"""
    DeleteHumanLoop()

Deletes the specified human loop for a flow definition.

# Required Parameters
- `HumanLoopName`: The name of the human loop that you want to delete.

"""
DeleteHumanLoop(HumanLoopName) = sagemaker_a2i_runtime("DELETE", "/human-loops/$(HumanLoopName)")
DeleteHumanLoop(HumanLoopName, args::AbstractDict{String, <:Any}) = sagemaker_a2i_runtime("DELETE", "/human-loops/$(HumanLoopName)", args)

"""
    DescribeHumanLoop()

Returns information about the specified human loop.

# Required Parameters
- `HumanLoopName`: The name of the human loop that you want information about.

"""
DescribeHumanLoop(HumanLoopName) = sagemaker_a2i_runtime("GET", "/human-loops/$(HumanLoopName)")
DescribeHumanLoop(HumanLoopName, args::AbstractDict{String, <:Any}) = sagemaker_a2i_runtime("GET", "/human-loops/$(HumanLoopName)", args)

"""
    ListHumanLoops()

Returns information about human loops, given the specified parameters. If a human loop was deleted, it will not be included.

# Required Parameters
- `FlowDefinitionArn`: The Amazon Resource Name (ARN) of a flow definition.

# Optional Parameters
- `CreationTimeAfter`: (Optional) The timestamp of the date when you want the human loops to begin in ISO 8601 format. For example, 2020-02-24.
- `CreationTimeBefore`: (Optional) The timestamp of the date before which you want the human loops to begin in ISO 8601 format. For example, 2020-02-24.
- `MaxResults`: The total number of items to return. If the total number of available items is more than the value specified in MaxResults, then a NextToken is returned in the output. You can use this token to display the next page of results. 
- `NextToken`: A token to display the next page of results.
- `SortOrder`: Optional. The order for displaying results. Valid values: Ascending and Descending.
"""
ListHumanLoops(FlowDefinitionArn) = sagemaker_a2i_runtime("GET", "/human-loops", Dict{String, Any}("FlowDefinitionArn"=>FlowDefinitionArn))
ListHumanLoops(FlowDefinitionArn, args::AbstractDict{String, <:Any}) = sagemaker_a2i_runtime("GET", "/human-loops", Dict{String, Any}("FlowDefinitionArn"=>FlowDefinitionArn, args...))

"""
    StartHumanLoop()

Starts a human loop, provided that at least one activation condition is met.

# Required Parameters
- `FlowDefinitionArn`: The Amazon Resource Name (ARN) of the flow definition associated with this human loop.
- `HumanLoopInput`: An object that contains information about the human loop.
- `HumanLoopName`: The name of the human loop.

# Optional Parameters
- `DataAttributes`: Attributes of the specified data. Use DataAttributes to specify if your data is free of personally identifiable information and/or free of adult content.
"""
StartHumanLoop(FlowDefinitionArn, HumanLoopInput, HumanLoopName) = sagemaker_a2i_runtime("POST", "/human-loops", Dict{String, Any}("FlowDefinitionArn"=>FlowDefinitionArn, "HumanLoopInput"=>HumanLoopInput, "HumanLoopName"=>HumanLoopName))
StartHumanLoop(FlowDefinitionArn, HumanLoopInput, HumanLoopName, args::AbstractDict{String, <:Any}) = sagemaker_a2i_runtime("POST", "/human-loops", Dict{String, Any}("FlowDefinitionArn"=>FlowDefinitionArn, "HumanLoopInput"=>HumanLoopInput, "HumanLoopName"=>HumanLoopName, args...))

"""
    StopHumanLoop()

Stops the specified human loop.

# Required Parameters
- `HumanLoopName`: The name of the human loop that you want to stop.

"""
StopHumanLoop(HumanLoopName) = sagemaker_a2i_runtime("POST", "/human-loops/stop", Dict{String, Any}("HumanLoopName"=>HumanLoopName))
StopHumanLoop(HumanLoopName, args::AbstractDict{String, <:Any}) = sagemaker_a2i_runtime("POST", "/human-loops/stop", Dict{String, Any}("HumanLoopName"=>HumanLoopName, args...))
