using AWS
using AWS: AWSCredentials
using AWS: AWSServices
using AWS.AWSExceptions: AWSException
using AWS.AWSMetadataUtilities: _documentation_cleaning, _filter_latest_service_version,
    _generate_low_level_definition, _generate_high_level_definition, _generate_high_level_definitions,
    _get_aws_sdk_js_files, _get_service_and_version, _get_function_parameters,
    InvalidFileName, ProtocolNotDefined
using Dates
using HTTP
using JSON
using OrderedCollections: OrderedDict
using Mocking
using Retry
using SymDict
using Test
using UUIDs

Mocking.activate()

@testset "AWS.jl" begin
    include("AWS.jl")
    #include("AWSCredentials.jl")  # TODO: Uncomment after all request types are complete
    include("AWSExceptions.jl")
    include("AWSMetadataUtilities.jl")
end
