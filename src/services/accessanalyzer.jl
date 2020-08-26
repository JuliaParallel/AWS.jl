# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: accessanalyzer

using Compat
using UUIDs
"""
    CreateAnalyzer()

Creates an analyzer for your account.

# Required Parameters
- `analyzerName`: The name of the analyzer to create.
- `type`: The type of analyzer to create. Only ACCOUNT analyzers are supported. You can create only one analyzer per account per Region.

# Optional Parameters
- `archiveRules`: Specifies the archive rules to add for the analyzer. Archive rules automatically archive findings that meet the criteria you define for the rule.
- `clientToken`: A client token.
- `tags`: The tags to apply to the analyzer.
"""

create_analyzer(analyzerName, type; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/analyzer", Dict{String, Any}("analyzerName"=>analyzerName, "type"=>type, "clientToken"=>string(uuid4())); aws_config=aws_config)
create_analyzer(analyzerName, type, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/analyzer", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("analyzerName"=>analyzerName, "type"=>type, "clientToken"=>string(uuid4())), args)); aws_config=aws_config)

"""
    CreateArchiveRule()

Creates an archive rule for the specified analyzer. Archive rules automatically archive findings that meet the criteria you define when you create the rule.

# Required Parameters
- `analyzerName`: The name of the created analyzer.
- `filter`: The criteria for the rule.
- `ruleName`: The name of the rule to create.

# Optional Parameters
- `clientToken`: A client token.
"""

create_archive_rule(analyzerName, filter, ruleName; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/analyzer/$(analyzerName)/archive-rule", Dict{String, Any}("filter"=>filter, "ruleName"=>ruleName, "clientToken"=>string(uuid4())); aws_config=aws_config)
create_archive_rule(analyzerName, filter, ruleName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/analyzer/$(analyzerName)/archive-rule", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("filter"=>filter, "ruleName"=>ruleName, "clientToken"=>string(uuid4())), args)); aws_config=aws_config)

"""
    DeleteAnalyzer()

Deletes the specified analyzer. When you delete an analyzer, Access Analyzer is disabled for the account in the current or specific Region. All findings that were generated by the analyzer are deleted. You cannot undo this action.

# Required Parameters
- `analyzerName`: The name of the analyzer to delete.

# Optional Parameters
- `clientToken`: A client token.
"""

delete_analyzer(analyzerName; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("DELETE", "/analyzer/$(analyzerName)", Dict{String, Any}("clientToken"=>string(uuid4())); aws_config=aws_config)
delete_analyzer(analyzerName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("DELETE", "/analyzer/$(analyzerName)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("clientToken"=>string(uuid4())), args)); aws_config=aws_config)

"""
    DeleteArchiveRule()

Deletes the specified archive rule.

# Required Parameters
- `analyzerName`: The name of the analyzer that associated with the archive rule to delete.
- `ruleName`: The name of the rule to delete.

# Optional Parameters
- `clientToken`: A client token.
"""

delete_archive_rule(analyzerName, ruleName; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("DELETE", "/analyzer/$(analyzerName)/archive-rule/$(ruleName)", Dict{String, Any}("clientToken"=>string(uuid4())); aws_config=aws_config)
delete_archive_rule(analyzerName, ruleName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("DELETE", "/analyzer/$(analyzerName)/archive-rule/$(ruleName)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("clientToken"=>string(uuid4())), args)); aws_config=aws_config)

"""
    GetAnalyzedResource()

Retrieves information about a resource that was analyzed.

# Required Parameters
- `analyzerArn`: The ARN of the analyzer to retrieve information from.
- `resourceArn`: The ARN of the resource to retrieve information about.

"""

get_analyzed_resource(analyzerArn, resourceArn; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzed-resource", Dict{String, Any}("analyzerArn"=>analyzerArn, "resourceArn"=>resourceArn); aws_config=aws_config)
get_analyzed_resource(analyzerArn, resourceArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzed-resource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("analyzerArn"=>analyzerArn, "resourceArn"=>resourceArn), args)); aws_config=aws_config)

"""
    GetAnalyzer()

Retrieves information about the specified analyzer.

# Required Parameters
- `analyzerName`: The name of the analyzer retrieved.

"""

get_analyzer(analyzerName; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer/$(analyzerName)"; aws_config=aws_config)
get_analyzer(analyzerName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer/$(analyzerName)", args; aws_config=aws_config)

"""
    GetArchiveRule()

Retrieves information about an archive rule.

# Required Parameters
- `analyzerName`: The name of the analyzer to retrieve rules from.
- `ruleName`: The name of the rule to retrieve.

"""

get_archive_rule(analyzerName, ruleName; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer/$(analyzerName)/archive-rule/$(ruleName)"; aws_config=aws_config)
get_archive_rule(analyzerName, ruleName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer/$(analyzerName)/archive-rule/$(ruleName)", args; aws_config=aws_config)

"""
    GetFinding()

Retrieves information about the specified finding.

# Required Parameters
- `analyzerArn`: The ARN of the analyzer that generated the finding.
- `id`: The ID of the finding to retrieve.

"""

get_finding(analyzerArn, id; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/finding/$(id)", Dict{String, Any}("analyzerArn"=>analyzerArn); aws_config=aws_config)
get_finding(analyzerArn, id, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/finding/$(id)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("analyzerArn"=>analyzerArn), args)); aws_config=aws_config)

"""
    ListAnalyzedResources()

Retrieves a list of resources of the specified type that have been analyzed by the specified analyzer..

# Required Parameters
- `analyzerArn`: The ARN of the analyzer to retrieve a list of analyzed resources from.

# Optional Parameters
- `maxResults`: The maximum number of results to return in the response.
- `nextToken`: A token used for pagination of results returned.
- `resourceType`: The type of resource.
"""

list_analyzed_resources(analyzerArn; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/analyzed-resource", Dict{String, Any}("analyzerArn"=>analyzerArn); aws_config=aws_config)
list_analyzed_resources(analyzerArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/analyzed-resource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("analyzerArn"=>analyzerArn), args)); aws_config=aws_config)

"""
    ListAnalyzers()

Retrieves a list of analyzers.

# Optional Parameters
- `maxResults`: The maximum number of results to return in the response.
- `nextToken`: A token used for pagination of results returned.
- `type`: The type of analyzer.
"""

list_analyzers(; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer"; aws_config=aws_config)
list_analyzers(args::AbstractDict{String, Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer", args; aws_config=aws_config)

"""
    ListArchiveRules()

Retrieves a list of archive rules created for the specified analyzer.

# Required Parameters
- `analyzerName`: The name of the analyzer to retrieve rules from.

# Optional Parameters
- `maxResults`: The maximum number of results to return in the request.
- `nextToken`: A token used for pagination of results returned.
"""

list_archive_rules(analyzerName; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer/$(analyzerName)/archive-rule"; aws_config=aws_config)
list_archive_rules(analyzerName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/analyzer/$(analyzerName)/archive-rule", args; aws_config=aws_config)

"""
    ListFindings()

Retrieves a list of findings generated by the specified analyzer.

# Required Parameters
- `analyzerArn`: The ARN of the analyzer to retrieve findings from.

# Optional Parameters
- `filter`: A filter to match for the findings to return.
- `maxResults`: The maximum number of results to return in the response.
- `nextToken`: A token used for pagination of results returned.
- `sort`: The sort order for the findings returned.
"""

list_findings(analyzerArn; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/finding", Dict{String, Any}("analyzerArn"=>analyzerArn); aws_config=aws_config)
list_findings(analyzerArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/finding", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("analyzerArn"=>analyzerArn), args)); aws_config=aws_config)

"""
    ListTagsForResource()

Retrieves a list of tags applied to the specified resource.

# Required Parameters
- `resourceArn`: The ARN of the resource to retrieve tags from.

"""

list_tags_for_resource(resourceArn; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/tags/$(resourceArn)"; aws_config=aws_config)
list_tags_for_resource(resourceArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("GET", "/tags/$(resourceArn)", args; aws_config=aws_config)

"""
    StartResourceScan()

Immediately starts a scan of the policies applied to the specified resource.

# Required Parameters
- `analyzerArn`: The ARN of the analyzer to use to scan the policies applied to the specified resource.
- `resourceArn`: The ARN of the resource to scan.

"""

start_resource_scan(analyzerArn, resourceArn; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/resource/scan", Dict{String, Any}("analyzerArn"=>analyzerArn, "resourceArn"=>resourceArn); aws_config=aws_config)
start_resource_scan(analyzerArn, resourceArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/resource/scan", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("analyzerArn"=>analyzerArn, "resourceArn"=>resourceArn), args)); aws_config=aws_config)

"""
    TagResource()

Adds a tag to the specified resource.

# Required Parameters
- `resourceArn`: The ARN of the resource to add the tag to.
- `tags`: The tags to add to the resource.

"""

tag_resource(resourceArn, tags; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/tags/$(resourceArn)", Dict{String, Any}("tags"=>tags); aws_config=aws_config)
tag_resource(resourceArn, tags, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("POST", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tags"=>tags), args)); aws_config=aws_config)

"""
    UntagResource()

Removes a tag from the specified resource.

# Required Parameters
- `resourceArn`: The ARN of the resource to remove the tag from.
- `tagKeys`: The key for the tag to add.

"""

untag_resource(resourceArn, tagKeys; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys); aws_config=aws_config)
untag_resource(resourceArn, tagKeys, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("DELETE", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tagKeys"=>tagKeys), args)); aws_config=aws_config)

"""
    UpdateArchiveRule()

Updates the criteria and values for the specified archive rule.

# Required Parameters
- `analyzerName`: The name of the analyzer to update the archive rules for.
- `filter`: A filter to match for the rules to update. Only rules that match the filter are updated.
- `ruleName`: The name of the rule to update.

# Optional Parameters
- `clientToken`: A client token.
"""

update_archive_rule(analyzerName, filter, ruleName; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/analyzer/$(analyzerName)/archive-rule/$(ruleName)", Dict{String, Any}("filter"=>filter, "clientToken"=>string(uuid4())); aws_config=aws_config)
update_archive_rule(analyzerName, filter, ruleName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/analyzer/$(analyzerName)/archive-rule/$(ruleName)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("filter"=>filter, "clientToken"=>string(uuid4())), args)); aws_config=aws_config)

"""
    UpdateFindings()

Updates the status for the specified findings.

# Required Parameters
- `analyzerArn`: The ARN of the analyzer that generated the findings to update.
- `status`: The state represents the action to take to update the finding Status. Use ARCHIVE to change an Active finding to an Archived finding. Use ACTIVE to change an Archived finding to an Active finding.

# Optional Parameters
- `clientToken`: A client token.
- `ids`: The IDs of the findings to update.
- `resourceArn`: The ARN of the resource identified in the finding.
"""

update_findings(analyzerArn, status; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/finding", Dict{String, Any}("analyzerArn"=>analyzerArn, "status"=>status, "clientToken"=>string(uuid4())); aws_config=aws_config)
update_findings(analyzerArn, status, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = accessanalyzer("PUT", "/finding", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("analyzerArn"=>analyzerArn, "status"=>status, "clientToken"=>string(uuid4())), args)); aws_config=aws_config)
