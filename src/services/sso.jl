# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: sso

using Compat
using UUIDs
"""
    GetRoleCredentials()

Returns the STS short-term credentials for a given role name that is assigned to the user.

# Required Parameters
- `account_id`: The identifier for the AWS account that is assigned to the user.
- `role_name`: The friendly name of the role that is assigned to the user.
- `x-amz-sso_bearer_token`: The token issued by the CreateToken API call. For more information, see CreateToken in the AWS SSO OIDC API Reference Guide.

"""
GetRoleCredentials(account_id, role_name, x_amz_sso_bearer_token; aws::AWSConfig=AWS.aws_config) = sso("GET", "/federation/credentials", Dict{String, Any}("account_id"=>account_id, "role_name"=>role_name, "headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)); aws=aws)
GetRoleCredentials(account_id, role_name, x_amz_sso_bearer_token, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = sso("GET", "/federation/credentials", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("account_id"=>account_id, "role_name"=>role_name, "headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)), args)); aws=aws)

"""
    ListAccountRoles()

Lists all roles that are assigned to the user for a given AWS account.

# Required Parameters
- `account_id`: The identifier for the AWS account that is assigned to the user.
- `x-amz-sso_bearer_token`: The token issued by the CreateToken API call. For more information, see CreateToken in the AWS SSO OIDC API Reference Guide.

# Optional Parameters
- `max_result`: The number of items that clients can request per page.
- `next_token`: The page token from the previous response output when you request subsequent pages.
"""
ListAccountRoles(account_id, x_amz_sso_bearer_token; aws::AWSConfig=AWS.aws_config) = sso("GET", "/assignment/roles", Dict{String, Any}("account_id"=>account_id, "headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)); aws=aws)
ListAccountRoles(account_id, x_amz_sso_bearer_token, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = sso("GET", "/assignment/roles", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("account_id"=>account_id, "headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)), args)); aws=aws)

"""
    ListAccounts()

Lists all AWS accounts assigned to the user. These AWS accounts are assigned by the administrator of the account. For more information, see Assign User Access in the AWS SSO User Guide. This operation returns a paginated response.

# Required Parameters
- `x-amz-sso_bearer_token`: The token issued by the CreateToken API call. For more information, see CreateToken in the AWS SSO OIDC API Reference Guide.

# Optional Parameters
- `max_result`: This is the number of items clients can request per page.
- `next_token`: (Optional) When requesting subsequent pages, this is the page token from the previous response output.
"""
ListAccounts(x_amz_sso_bearer_token; aws::AWSConfig=AWS.aws_config) = sso("GET", "/assignment/accounts", Dict{String, Any}("headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)); aws=aws)
ListAccounts(x_amz_sso_bearer_token, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = sso("GET", "/assignment/accounts", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)), args)); aws=aws)

"""
    Logout()

Removes the client- and server-side session that is associated with the user.

# Required Parameters
- `x-amz-sso_bearer_token`: The token issued by the CreateToken API call. For more information, see CreateToken in the AWS SSO OIDC API Reference Guide.

"""
Logout(x_amz_sso_bearer_token; aws::AWSConfig=AWS.aws_config) = sso("POST", "/logout", Dict{String, Any}("headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)); aws=aws)
Logout(x_amz_sso_bearer_token, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = sso("POST", "/logout", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("headers"=>Dict{String, Any}("x-amz-sso_bearer_token"=>x_amz_sso_bearer_token)), args)); aws=aws)
