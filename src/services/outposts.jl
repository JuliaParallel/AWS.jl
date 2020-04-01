include("../AWSServices.jl")
using .AWSServices: outposts

"""
    DeleteOutpost()

Deletes the Outpost.

Required Parameters
{
  "OutpostId": ""
}
"""
DeleteOutpost(args) = outposts("DELETE", "/outposts/{OutpostId}", args)

"""
    GetOutpost()

Gets information about the specified Outpost.

Required Parameters
{
  "OutpostId": ""
}
"""
GetOutpost(args) = outposts("GET", "/outposts/{OutpostId}", args)

"""
    CreateOutpost()

Creates an Outpost.

Required Parameters
{
  "SiteId": ""
}

Optional Parameters
{
  "Description": "",
  "AvailabilityZone": "",
  "AvailabilityZoneId": "",
  "Name": ""
}
"""
CreateOutpost(args) = outposts("POST", "/outposts", args)

"""
    DeleteSite()

Deletes the site.

Required Parameters
{
  "SiteId": ""
}
"""
DeleteSite(args) = outposts("DELETE", "/sites/{SiteId}", args)

"""
    ListSites()

Lists the sites for the specified AWS account.

Optional Parameters
{
  "MaxResults": "",
  "NextToken": ""
}
"""
ListSites() = outposts("GET", "/sites")
ListSites(args) = outposts("GET", "/sites", args)

"""
    GetOutpostInstanceTypes()

Lists the instance types for the specified Outpost.

Required Parameters
{
  "OutpostId": ""
}

Optional Parameters
{
  "MaxResults": "",
  "NextToken": ""
}
"""
GetOutpostInstanceTypes(args) = outposts("GET", "/outposts/{OutpostId}/instanceTypes", args)

"""
    ListOutposts()

List the Outposts for your AWS account.

Optional Parameters
{
  "MaxResults": "",
  "NextToken": ""
}
"""
ListOutposts() = outposts("GET", "/outposts")
ListOutposts(args) = outposts("GET", "/outposts", args)