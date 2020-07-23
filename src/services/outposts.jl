# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
using Compat
using .AWSServices: outposts

"""
    CreateOutpost()

Creates an Outpost.

Required Parameters
SiteId => 

Optional Parameters
AvailabilityZone => 
AvailabilityZoneId => 
Description => 
Name => 
"""
CreateOutpost(SiteId) = outposts("POST", "/outposts", Dict{String, Any}("SiteId"=>SiteId))
CreateOutpost(SiteId, args::AbstractDict{String, <: Any}) = outposts("POST", "/outposts", Dict{String, Any}("SiteId"=>SiteId, args...))
CreateOutpost(a...; b...) = CreateOutpost(a..., b)

"""
    DeleteOutpost()

Deletes the Outpost.

Required Parameters
OutpostId => 

"""
DeleteOutpost(OutpostId) = outposts("DELETE", "/outposts/$(OutpostId)")
DeleteOutpost(OutpostId, args::AbstractDict{String, <: Any}) = outposts("DELETE", "/outposts/$(OutpostId)", args)
DeleteOutpost(a...; b...) = DeleteOutpost(a..., b)

"""
    DeleteSite()

Deletes the site.

Required Parameters
SiteId => 

"""
DeleteSite(SiteId) = outposts("DELETE", "/sites/$(SiteId)")
DeleteSite(SiteId, args::AbstractDict{String, <: Any}) = outposts("DELETE", "/sites/$(SiteId)", args)
DeleteSite(a...; b...) = DeleteSite(a..., b)

"""
    GetOutpost()

Gets information about the specified Outpost.

Required Parameters
OutpostId => 

"""
GetOutpost(OutpostId) = outposts("GET", "/outposts/$(OutpostId)")
GetOutpost(OutpostId, args::AbstractDict{String, <: Any}) = outposts("GET", "/outposts/$(OutpostId)", args)
GetOutpost(a...; b...) = GetOutpost(a..., b)

"""
    GetOutpostInstanceTypes()

Lists the instance types for the specified Outpost.

Required Parameters
OutpostId => 

Optional Parameters
MaxResults => 
NextToken => 
"""
GetOutpostInstanceTypes(OutpostId) = outposts("GET", "/outposts/$(OutpostId)/instanceTypes")
GetOutpostInstanceTypes(OutpostId, args::AbstractDict{String, <: Any}) = outposts("GET", "/outposts/$(OutpostId)/instanceTypes", args)
GetOutpostInstanceTypes(a...; b...) = GetOutpostInstanceTypes(a..., b)

"""
    ListOutposts()

List the Outposts for your AWS account.

Optional Parameters
MaxResults => 
NextToken => 
"""
ListOutposts() = outposts("GET", "/outposts")
ListOutposts(args::AbstractDict{String, Any}) = outposts("GET", "/outposts", args)
ListOutposts(a...; b...) = ListOutposts(a..., b)

"""
    ListSites()

Lists the sites for the specified AWS account.

Optional Parameters
MaxResults => 
NextToken => 
"""
ListSites() = outposts("GET", "/sites")
ListSites(args::AbstractDict{String, Any}) = outposts("GET", "/sites", args)
ListSites(a...; b...) = ListSites(a..., b)
