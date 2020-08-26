# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: route53resolver

using Compat
using UUIDs
"""
    AssociateResolverEndpointIpAddress()

Adds IP addresses to an inbound or an outbound resolver endpoint. If you want to adding more than one IP address, submit one AssociateResolverEndpointIpAddress request for each IP address. To remove an IP address from an endpoint, see DisassociateResolverEndpointIpAddress.

# Required Parameters
- `IpAddress`: Either the IPv4 address that you want to add to a resolver endpoint or a subnet ID. If you specify a subnet ID, Resolver chooses an IP address for you from the available IPs in the specified subnet.
- `ResolverEndpointId`: The ID of the resolver endpoint that you want to associate IP addresses with.

"""

associate_resolver_endpoint_ip_address(IpAddress, ResolverEndpointId; aws_config::AWSConfig=global_aws_config()) = route53resolver("AssociateResolverEndpointIpAddress", Dict{String, Any}("IpAddress"=>IpAddress, "ResolverEndpointId"=>ResolverEndpointId); aws_config=aws_config)
associate_resolver_endpoint_ip_address(IpAddress, ResolverEndpointId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("AssociateResolverEndpointIpAddress", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("IpAddress"=>IpAddress, "ResolverEndpointId"=>ResolverEndpointId), args)); aws_config=aws_config)

"""
    AssociateResolverRule()

Associates a resolver rule with a VPC. When you associate a rule with a VPC, Resolver forwards all DNS queries for the domain name that is specified in the rule and that originate in the VPC. The queries are forwarded to the IP addresses for the DNS resolvers that are specified in the rule. For more information about rules, see CreateResolverRule. 

# Required Parameters
- `ResolverRuleId`: The ID of the resolver rule that you want to associate with the VPC. To list the existing resolver rules, use ListResolverRules.
- `VPCId`: The ID of the VPC that you want to associate the resolver rule with.

# Optional Parameters
- `Name`: A name for the association that you're creating between a resolver rule and a VPC.
"""

associate_resolver_rule(ResolverRuleId, VPCId; aws_config::AWSConfig=global_aws_config()) = route53resolver("AssociateResolverRule", Dict{String, Any}("ResolverRuleId"=>ResolverRuleId, "VPCId"=>VPCId); aws_config=aws_config)
associate_resolver_rule(ResolverRuleId, VPCId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("AssociateResolverRule", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverRuleId"=>ResolverRuleId, "VPCId"=>VPCId), args)); aws_config=aws_config)

"""
    CreateResolverEndpoint()

Creates a resolver endpoint. There are two types of resolver endpoints, inbound and outbound:   An inbound resolver endpoint forwards DNS queries to the DNS service for a VPC from your network or another VPC.   An outbound resolver endpoint forwards DNS queries from the DNS service for a VPC to your network or another VPC.  

# Required Parameters
- `CreatorRequestId`: A unique string that identifies the request and that allows failed requests to be retried without the risk of executing the operation twice. CreatorRequestId can be any unique string, for example, a date/time stamp. 
- `Direction`: Specify the applicable value:    INBOUND: Resolver forwards DNS queries to the DNS service for a VPC from your network or another VPC    OUTBOUND: Resolver forwards DNS queries from the DNS service for a VPC to your network or another VPC  
- `IpAddresses`: The subnets and IP addresses in your VPC that you want DNS queries to pass through on the way from your VPCs to your network (for outbound endpoints) or on the way from your network to your VPCs (for inbound resolver endpoints). 
- `SecurityGroupIds`: The ID of one or more security groups that you want to use to control access to this VPC. The security group that you specify must include one or more inbound rules (for inbound resolver endpoints) or outbound rules (for outbound resolver endpoints).

# Optional Parameters
- `Name`: A friendly name that lets you easily find a configuration in the Resolver dashboard in the Route 53 console.
- `Tags`: A list of the tag keys and values that you want to associate with the endpoint.
"""

create_resolver_endpoint(CreatorRequestId, Direction, IpAddresses, SecurityGroupIds; aws_config::AWSConfig=global_aws_config()) = route53resolver("CreateResolverEndpoint", Dict{String, Any}("CreatorRequestId"=>CreatorRequestId, "Direction"=>Direction, "IpAddresses"=>IpAddresses, "SecurityGroupIds"=>SecurityGroupIds); aws_config=aws_config)
create_resolver_endpoint(CreatorRequestId, Direction, IpAddresses, SecurityGroupIds, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("CreateResolverEndpoint", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("CreatorRequestId"=>CreatorRequestId, "Direction"=>Direction, "IpAddresses"=>IpAddresses, "SecurityGroupIds"=>SecurityGroupIds), args)); aws_config=aws_config)

"""
    CreateResolverRule()

For DNS queries that originate in your VPCs, specifies which resolver endpoint the queries pass through, one domain name that you want to forward to your network, and the IP addresses of the DNS resolvers in your network.

# Required Parameters
- `CreatorRequestId`: A unique string that identifies the request and that allows failed requests to be retried without the risk of executing the operation twice. CreatorRequestId can be any unique string, for example, a date/time stamp. 
- `DomainName`: DNS queries for this domain name are forwarded to the IP addresses that you specify in TargetIps. If a query matches multiple resolver rules (example.com and www.example.com), outbound DNS queries are routed using the resolver rule that contains the most specific domain name (www.example.com).
- `RuleType`: Specify FORWARD. Other resolver rule types aren't supported.

# Optional Parameters
- `Name`: A friendly name that lets you easily find a rule in the Resolver dashboard in the Route 53 console.
- `ResolverEndpointId`: The ID of the outbound resolver endpoint that you want to use to route DNS queries to the IP addresses that you specify in TargetIps.
- `Tags`: A list of the tag keys and values that you want to associate with the endpoint.
- `TargetIps`: The IPs that you want Resolver to forward DNS queries to. You can specify only IPv4 addresses. Separate IP addresses with a comma.
"""

create_resolver_rule(CreatorRequestId, DomainName, RuleType; aws_config::AWSConfig=global_aws_config()) = route53resolver("CreateResolverRule", Dict{String, Any}("CreatorRequestId"=>CreatorRequestId, "DomainName"=>DomainName, "RuleType"=>RuleType); aws_config=aws_config)
create_resolver_rule(CreatorRequestId, DomainName, RuleType, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("CreateResolverRule", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("CreatorRequestId"=>CreatorRequestId, "DomainName"=>DomainName, "RuleType"=>RuleType), args)); aws_config=aws_config)

"""
    DeleteResolverEndpoint()

Deletes a resolver endpoint. The effect of deleting a resolver endpoint depends on whether it's an inbound or an outbound resolver endpoint:    Inbound: DNS queries from your network or another VPC are no longer routed to the DNS service for the specified VPC.    Outbound: DNS queries from a VPC are no longer routed to your network or to another VPC.  

# Required Parameters
- `ResolverEndpointId`: The ID of the resolver endpoint that you want to delete.

"""

delete_resolver_endpoint(ResolverEndpointId; aws_config::AWSConfig=global_aws_config()) = route53resolver("DeleteResolverEndpoint", Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId); aws_config=aws_config)
delete_resolver_endpoint(ResolverEndpointId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("DeleteResolverEndpoint", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId), args)); aws_config=aws_config)

"""
    DeleteResolverRule()

Deletes a resolver rule. Before you can delete a resolver rule, you must disassociate it from all the VPCs that you associated the resolver rule with. For more infomation, see DisassociateResolverRule.

# Required Parameters
- `ResolverRuleId`: The ID of the resolver rule that you want to delete.

"""

delete_resolver_rule(ResolverRuleId; aws_config::AWSConfig=global_aws_config()) = route53resolver("DeleteResolverRule", Dict{String, Any}("ResolverRuleId"=>ResolverRuleId); aws_config=aws_config)
delete_resolver_rule(ResolverRuleId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("DeleteResolverRule", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverRuleId"=>ResolverRuleId), args)); aws_config=aws_config)

"""
    DisassociateResolverEndpointIpAddress()

Removes IP addresses from an inbound or an outbound resolver endpoint. If you want to remove more than one IP address, submit one DisassociateResolverEndpointIpAddress request for each IP address. To add an IP address to an endpoint, see AssociateResolverEndpointIpAddress.

# Required Parameters
- `IpAddress`: The IPv4 address that you want to remove from a resolver endpoint.
- `ResolverEndpointId`: The ID of the resolver endpoint that you want to disassociate an IP address from.

"""

disassociate_resolver_endpoint_ip_address(IpAddress, ResolverEndpointId; aws_config::AWSConfig=global_aws_config()) = route53resolver("DisassociateResolverEndpointIpAddress", Dict{String, Any}("IpAddress"=>IpAddress, "ResolverEndpointId"=>ResolverEndpointId); aws_config=aws_config)
disassociate_resolver_endpoint_ip_address(IpAddress, ResolverEndpointId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("DisassociateResolverEndpointIpAddress", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("IpAddress"=>IpAddress, "ResolverEndpointId"=>ResolverEndpointId), args)); aws_config=aws_config)

"""
    DisassociateResolverRule()

Removes the association between a specified resolver rule and a specified VPC.  If you disassociate a resolver rule from a VPC, Resolver stops forwarding DNS queries for the domain name that you specified in the resolver rule.  

# Required Parameters
- `ResolverRuleId`: The ID of the resolver rule that you want to disassociate from the specified VPC.
- `VPCId`: The ID of the VPC that you want to disassociate the resolver rule from.

"""

disassociate_resolver_rule(ResolverRuleId, VPCId; aws_config::AWSConfig=global_aws_config()) = route53resolver("DisassociateResolverRule", Dict{String, Any}("ResolverRuleId"=>ResolverRuleId, "VPCId"=>VPCId); aws_config=aws_config)
disassociate_resolver_rule(ResolverRuleId, VPCId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("DisassociateResolverRule", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverRuleId"=>ResolverRuleId, "VPCId"=>VPCId), args)); aws_config=aws_config)

"""
    GetResolverEndpoint()

Gets information about a specified resolver endpoint, such as whether it's an inbound or an outbound resolver endpoint, and the current status of the endpoint.

# Required Parameters
- `ResolverEndpointId`: The ID of the resolver endpoint that you want to get information about.

"""

get_resolver_endpoint(ResolverEndpointId; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverEndpoint", Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId); aws_config=aws_config)
get_resolver_endpoint(ResolverEndpointId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverEndpoint", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId), args)); aws_config=aws_config)

"""
    GetResolverRule()

Gets information about a specified resolver rule, such as the domain name that the rule forwards DNS queries for and the ID of the outbound resolver endpoint that the rule is associated with.

# Required Parameters
- `ResolverRuleId`: The ID of the resolver rule that you want to get information about.

"""

get_resolver_rule(ResolverRuleId; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverRule", Dict{String, Any}("ResolverRuleId"=>ResolverRuleId); aws_config=aws_config)
get_resolver_rule(ResolverRuleId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverRule", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverRuleId"=>ResolverRuleId), args)); aws_config=aws_config)

"""
    GetResolverRuleAssociation()

Gets information about an association between a specified resolver rule and a VPC. You associate a resolver rule and a VPC using AssociateResolverRule. 

# Required Parameters
- `ResolverRuleAssociationId`: The ID of the resolver rule association that you want to get information about.

"""

get_resolver_rule_association(ResolverRuleAssociationId; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverRuleAssociation", Dict{String, Any}("ResolverRuleAssociationId"=>ResolverRuleAssociationId); aws_config=aws_config)
get_resolver_rule_association(ResolverRuleAssociationId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverRuleAssociation", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverRuleAssociationId"=>ResolverRuleAssociationId), args)); aws_config=aws_config)

"""
    GetResolverRulePolicy()

Gets information about a resolver rule policy. A resolver rule policy specifies the Resolver operations and resources that you want to allow another AWS account to be able to use. 

# Required Parameters
- `Arn`: The ID of the resolver rule policy that you want to get information about.

"""

get_resolver_rule_policy(Arn; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverRulePolicy", Dict{String, Any}("Arn"=>Arn); aws_config=aws_config)
get_resolver_rule_policy(Arn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("GetResolverRulePolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Arn"=>Arn), args)); aws_config=aws_config)

"""
    ListResolverEndpointIpAddresses()

Gets the IP addresses for a specified resolver endpoint.

# Required Parameters
- `ResolverEndpointId`: The ID of the resolver endpoint that you want to get IP addresses for.

# Optional Parameters
- `MaxResults`: The maximum number of IP addresses that you want to return in the response to a ListResolverEndpointIpAddresses request. If you don't specify a value for MaxResults, Resolver returns up to 100 IP addresses. 
- `NextToken`: For the first ListResolverEndpointIpAddresses request, omit this value. If the specified resolver endpoint has more than MaxResults IP addresses, you can submit another ListResolverEndpointIpAddresses request to get the next group of IP addresses. In the next request, specify the value of NextToken from the previous response. 
"""

list_resolver_endpoint_ip_addresses(ResolverEndpointId; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverEndpointIpAddresses", Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId); aws_config=aws_config)
list_resolver_endpoint_ip_addresses(ResolverEndpointId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverEndpointIpAddresses", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId), args)); aws_config=aws_config)

"""
    ListResolverEndpoints()

Lists all the resolver endpoints that were created using the current AWS account.

# Optional Parameters
- `Filters`: An optional specification to return a subset of resolver endpoints, such as all inbound resolver endpoints.  If you submit a second or subsequent ListResolverEndpoints request and specify the NextToken parameter, you must use the same values for Filters, if any, as in the previous request. 
- `MaxResults`: The maximum number of resolver endpoints that you want to return in the response to a ListResolverEndpoints request. If you don't specify a value for MaxResults, Resolver returns up to 100 resolver endpoints. 
- `NextToken`: For the first ListResolverEndpoints request, omit this value. If you have more than MaxResults resolver endpoints, you can submit another ListResolverEndpoints request to get the next group of resolver endpoints. In the next request, specify the value of NextToken from the previous response. 
"""

list_resolver_endpoints(; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverEndpoints"; aws_config=aws_config)
list_resolver_endpoints(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverEndpoints", args; aws_config=aws_config)

"""
    ListResolverRuleAssociations()

Lists the associations that were created between resolver rules and VPCs using the current AWS account.

# Optional Parameters
- `Filters`: An optional specification to return a subset of resolver rules, such as resolver rules that are associated with the same VPC ID.  If you submit a second or subsequent ListResolverRuleAssociations request and specify the NextToken parameter, you must use the same values for Filters, if any, as in the previous request. 
- `MaxResults`: The maximum number of rule associations that you want to return in the response to a ListResolverRuleAssociations request. If you don't specify a value for MaxResults, Resolver returns up to 100 rule associations. 
- `NextToken`: For the first ListResolverRuleAssociation request, omit this value. If you have more than MaxResults rule associations, you can submit another ListResolverRuleAssociation request to get the next group of rule associations. In the next request, specify the value of NextToken from the previous response. 
"""

list_resolver_rule_associations(; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverRuleAssociations"; aws_config=aws_config)
list_resolver_rule_associations(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverRuleAssociations", args; aws_config=aws_config)

"""
    ListResolverRules()

Lists the resolver rules that were created using the current AWS account.

# Optional Parameters
- `Filters`: An optional specification to return a subset of resolver rules, such as all resolver rules that are associated with the same resolver endpoint.  If you submit a second or subsequent ListResolverRules request and specify the NextToken parameter, you must use the same values for Filters, if any, as in the previous request. 
- `MaxResults`: The maximum number of resolver rules that you want to return in the response to a ListResolverRules request. If you don't specify a value for MaxResults, Resolver returns up to 100 resolver rules.
- `NextToken`: For the first ListResolverRules request, omit this value. If you have more than MaxResults resolver rules, you can submit another ListResolverRules request to get the next group of resolver rules. In the next request, specify the value of NextToken from the previous response. 
"""

list_resolver_rules(; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverRules"; aws_config=aws_config)
list_resolver_rules(args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListResolverRules", args; aws_config=aws_config)

"""
    ListTagsForResource()

Lists the tags that you associated with the specified resource.

# Required Parameters
- `ResourceArn`: The Amazon Resource Name (ARN) for the resource that you want to list tags for.

# Optional Parameters
- `MaxResults`: The maximum number of tags that you want to return in the response to a ListTagsForResource request. If you don't specify a value for MaxResults, Resolver returns up to 100 tags.
- `NextToken`: For the first ListTagsForResource request, omit this value. If you have more than MaxResults tags, you can submit another ListTagsForResource request to get the next group of tags for the resource. In the next request, specify the value of NextToken from the previous response. 
"""

list_tags_for_resource(ResourceArn; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListTagsForResource", Dict{String, Any}("ResourceArn"=>ResourceArn); aws_config=aws_config)
list_tags_for_resource(ResourceArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("ListTagsForResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResourceArn"=>ResourceArn), args)); aws_config=aws_config)

"""
    PutResolverRulePolicy()

Specifies the Resolver operations and resources that you want to allow another AWS account to be able to use.

# Required Parameters
- `Arn`: The Amazon Resource Name (ARN) of the account that you want to grant permissions to.
- `ResolverRulePolicy`: An AWS Identity and Access Management policy statement that lists the permissions that you want to grant to another AWS account.

"""

put_resolver_rule_policy(Arn, ResolverRulePolicy; aws_config::AWSConfig=global_aws_config()) = route53resolver("PutResolverRulePolicy", Dict{String, Any}("Arn"=>Arn, "ResolverRulePolicy"=>ResolverRulePolicy); aws_config=aws_config)
put_resolver_rule_policy(Arn, ResolverRulePolicy, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("PutResolverRulePolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Arn"=>Arn, "ResolverRulePolicy"=>ResolverRulePolicy), args)); aws_config=aws_config)

"""
    TagResource()

Adds one or more tags to a specified resource.

# Required Parameters
- `ResourceArn`: The Amazon Resource Name (ARN) for the resource that you want to add tags to. To get the ARN for a resource, use the applicable Get or List command:     GetResolverEndpoint     GetResolverRule     GetResolverRuleAssociation     ListResolverEndpoints     ListResolverRuleAssociations     ListResolverRules   
- `Tags`: The tags that you want to add to the specified resource.

"""

tag_resource(ResourceArn, Tags; aws_config::AWSConfig=global_aws_config()) = route53resolver("TagResource", Dict{String, Any}("ResourceArn"=>ResourceArn, "Tags"=>Tags); aws_config=aws_config)
tag_resource(ResourceArn, Tags, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("TagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResourceArn"=>ResourceArn, "Tags"=>Tags), args)); aws_config=aws_config)

"""
    UntagResource()

Removes one or more tags from a specified resource.

# Required Parameters
- `ResourceArn`: The Amazon Resource Name (ARN) for the resource that you want to remove tags from. To get the ARN for a resource, use the applicable Get or List command:     GetResolverEndpoint     GetResolverRule     GetResolverRuleAssociation     ListResolverEndpoints     ListResolverRuleAssociations     ListResolverRules   
- `TagKeys`: The tags that you want to remove to the specified resource.

"""

untag_resource(ResourceArn, TagKeys; aws_config::AWSConfig=global_aws_config()) = route53resolver("UntagResource", Dict{String, Any}("ResourceArn"=>ResourceArn, "TagKeys"=>TagKeys); aws_config=aws_config)
untag_resource(ResourceArn, TagKeys, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("UntagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResourceArn"=>ResourceArn, "TagKeys"=>TagKeys), args)); aws_config=aws_config)

"""
    UpdateResolverEndpoint()

Updates the name of an inbound or an outbound resolver endpoint. 

# Required Parameters
- `ResolverEndpointId`: The ID of the resolver endpoint that you want to update.

# Optional Parameters
- `Name`: The name of the resolver endpoint that you want to update.
"""

update_resolver_endpoint(ResolverEndpointId; aws_config::AWSConfig=global_aws_config()) = route53resolver("UpdateResolverEndpoint", Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId); aws_config=aws_config)
update_resolver_endpoint(ResolverEndpointId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("UpdateResolverEndpoint", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ResolverEndpointId"=>ResolverEndpointId), args)); aws_config=aws_config)

"""
    UpdateResolverRule()

Updates settings for a specified resolver rule. ResolverRuleId is required, and all other parameters are optional. If you don't specify a parameter, it retains its current value.

# Required Parameters
- `Config`: The new settings for the resolver rule.
- `ResolverRuleId`: The ID of the resolver rule that you want to update.

"""

update_resolver_rule(Config, ResolverRuleId; aws_config::AWSConfig=global_aws_config()) = route53resolver("UpdateResolverRule", Dict{String, Any}("Config"=>Config, "ResolverRuleId"=>ResolverRuleId); aws_config=aws_config)
update_resolver_rule(Config, ResolverRuleId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = route53resolver("UpdateResolverRule", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Config"=>Config, "ResolverRuleId"=>ResolverRuleId), args)); aws_config=aws_config)
