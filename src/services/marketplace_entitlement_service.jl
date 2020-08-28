# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: marketplace_entitlement_service

using Compat
using UUIDs
"""
    GetEntitlements()

GetEntitlements retrieves entitlement values for a given product. The results can be filtered based on customer identifier or product dimensions.

# Required Parameters
- `ProductCode`: Product code is used to uniquely identify a product in AWS Marketplace. The product code will be provided by AWS Marketplace when the product listing is created.

# Optional Parameters
- `Filter`: Filter is used to return entitlements for a specific customer or for a specific dimension. Filters are described as keys mapped to a lists of values. Filtered requests are unioned for each value in the value list, and then intersected for each filter key.
- `MaxResults`: The maximum number of items to retrieve from the GetEntitlements operation. For pagination, use the NextToken field in subsequent calls to GetEntitlements.
- `NextToken`: For paginated calls to GetEntitlements, pass the NextToken from the previous GetEntitlementsResult.
"""

get_entitlements(ProductCode; aws_config::AWSConfig=global_aws_config()) = marketplace_entitlement_service("GetEntitlements", Dict{String, Any}("ProductCode"=>ProductCode); aws_config=aws_config)
get_entitlements(ProductCode, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = marketplace_entitlement_service("GetEntitlements", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ProductCode"=>ProductCode), args)); aws_config=aws_config)
