# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
include("_utilities.jl")
using Compat
using UUIDs
using .AWSServices: marketplace_catalog

"""
    CancelChangeSet()

Used to cancel an open change request. Must be sent before the status of the request changes to APPLYING, the final stage of completing your change request. You can describe a change during the 60-day request history retention period for API calls.

# Required Parameters
- `catalog`: Required. The catalog related to the request. Fixed value: AWSMarketplace.
- `changeSetId`: Required. The unique identifier of the StartChangeSet request that you want to cancel.

"""
CancelChangeSet(catalog, changeSetId) = marketplace_catalog("PATCH", "/CancelChangeSet", Dict{String, Any}("catalog"=>catalog, "changeSetId"=>changeSetId))
CancelChangeSet(catalog, changeSetId, args::AbstractDict{String, <:Any}) = marketplace_catalog("PATCH", "/CancelChangeSet", Dict{String, Any}("catalog"=>catalog, "changeSetId"=>changeSetId, args...))

"""
    DescribeChangeSet()

Provides information about a given change set.

# Required Parameters
- `catalog`: Required. The catalog related to the request. Fixed value: AWSMarketplace 
- `changeSetId`: Required. The unique identifier for the StartChangeSet request that you want to describe the details for.

"""
DescribeChangeSet(catalog, changeSetId) = marketplace_catalog("GET", "/DescribeChangeSet", Dict{String, Any}("catalog"=>catalog, "changeSetId"=>changeSetId))
DescribeChangeSet(catalog, changeSetId, args::AbstractDict{String, <:Any}) = marketplace_catalog("GET", "/DescribeChangeSet", Dict{String, Any}("catalog"=>catalog, "changeSetId"=>changeSetId, args...))

"""
    DescribeEntity()

Returns the metadata and content of the entity.

# Required Parameters
- `catalog`: Required. The catalog related to the request. Fixed value: AWSMarketplace 
- `entityId`: Required. The unique ID of the entity to describe.

"""
DescribeEntity(catalog, entityId) = marketplace_catalog("GET", "/DescribeEntity", Dict{String, Any}("catalog"=>catalog, "entityId"=>entityId))
DescribeEntity(catalog, entityId, args::AbstractDict{String, <:Any}) = marketplace_catalog("GET", "/DescribeEntity", Dict{String, Any}("catalog"=>catalog, "entityId"=>entityId, args...))

"""
    ListChangeSets()

Returns the list of change sets owned by the account being used to make the call. You can filter this list by providing any combination of entityId, ChangeSetName, and status. If you provide more than one filter, the API operation applies a logical AND between the filters. You can describe a change during the 60-day request history retention period for API calls.

# Required Parameters
- `Catalog`: The catalog related to the request. Fixed value: AWSMarketplace 

# Optional Parameters
- `FilterList`: An array of filter objects.
- `MaxResults`: The maximum number of results returned by a single call. This value must be provided in the next call to retrieve the next set of results. By default, this value is 20.
- `NextToken`: The token value retrieved from a previous call to access the next page of results.
- `Sort`: An object that contains two attributes, SortBy and SortOrder.
"""
ListChangeSets(Catalog) = marketplace_catalog("POST", "/ListChangeSets", Dict{String, Any}("Catalog"=>Catalog))
ListChangeSets(Catalog, args::AbstractDict{String, <:Any}) = marketplace_catalog("POST", "/ListChangeSets", Dict{String, Any}("Catalog"=>Catalog, args...))

"""
    ListEntities()

Provides the list of entities of a given type.

# Required Parameters
- `Catalog`: The catalog related to the request. Fixed value: AWSMarketplace 
- `EntityType`: The type of entities to retrieve.

# Optional Parameters
- `FilterList`: An array of filter objects. Each filter object contains two attributes, filterName and filterValues.
- `MaxResults`: Specifies the upper limit of the elements on a single page. If a value isn't provided, the default value is 20.
- `NextToken`: The value of the next token, if it exists. Null if there are no more results.
- `Sort`: An object that contains two attributes, SortBy and SortOrder.
"""
ListEntities(Catalog, EntityType) = marketplace_catalog("POST", "/ListEntities", Dict{String, Any}("Catalog"=>Catalog, "EntityType"=>EntityType))
ListEntities(Catalog, EntityType, args::AbstractDict{String, <:Any}) = marketplace_catalog("POST", "/ListEntities", Dict{String, Any}("Catalog"=>Catalog, "EntityType"=>EntityType, args...))

"""
    StartChangeSet()

This operation allows you to request changes for your entities. Within a single ChangeSet, you cannot start the same change type against the same entity multiple times. Additionally, when a ChangeSet is running, all the entities targeted by the different changes are locked until the ChangeSet has completed (either succeeded, cancelled, or failed). If you try to start a ChangeSet containing a change against an entity that is already locked, you will receive a ResourceInUseException. For example, you cannot start the ChangeSet described in the example below because it contains two changes to execute the same change type (AddRevisions) against the same entity (entity-id@1).

# Required Parameters
- `Catalog`: The catalog related to the request. Fixed value: AWSMarketplace 
- `ChangeSet`: Array of change object.

# Optional Parameters
- `ChangeSetName`: Optional case sensitive string of up to 100 ASCII characters. The change set name can be used to filter the list of change sets. 
- `ClientRequestToken`: A unique token to identify the request to ensure idempotency.
"""
StartChangeSet(Catalog, ChangeSet) = marketplace_catalog("POST", "/StartChangeSet", Dict{String, Any}("Catalog"=>Catalog, "ChangeSet"=>ChangeSet))
StartChangeSet(Catalog, ChangeSet, args::AbstractDict{String, <:Any}) = marketplace_catalog("POST", "/StartChangeSet", Dict{String, Any}("Catalog"=>Catalog, "ChangeSet"=>ChangeSet, args...))
