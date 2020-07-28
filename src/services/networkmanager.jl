# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
include("_utilities.jl")
using Compat
using UUIDs
using .AWSServices: networkmanager

"""
    AssociateCustomerGateway()

Associates a customer gateway with a device and optionally, with a link. If you specify a link, it must be associated with the specified device.  You can only associate customer gateways that are connected to a VPN attachment on a transit gateway. The transit gateway must be registered in your global network. When you register a transit gateway, customer gateways that are connected to the transit gateway are automatically included in the global network. To list customer gateways that are connected to a transit gateway, use the DescribeVpnConnections EC2 API and filter by transit-gateway-id. You cannot associate a customer gateway with more than one device and link. 

# Required Parameters
- `CustomerGatewayArn`: The Amazon Resource Name (ARN) of the customer gateway. For more information, see Resources Defined by Amazon EC2.
- `DeviceId`: The ID of the device.
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `LinkId`: The ID of the link.
"""
AssociateCustomerGateway(CustomerGatewayArn, DeviceId, globalNetworkId) = networkmanager("POST", "/global-networks/$(globalNetworkId)/customer-gateway-associations", Dict{String, Any}("CustomerGatewayArn"=>CustomerGatewayArn, "DeviceId"=>DeviceId))
AssociateCustomerGateway(CustomerGatewayArn, DeviceId, globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("POST", "/global-networks/$(globalNetworkId)/customer-gateway-associations", Dict{String, Any}("CustomerGatewayArn"=>CustomerGatewayArn, "DeviceId"=>DeviceId, args...))

"""
    AssociateLink()

Associates a link to a device. A device can be associated to multiple links and a link can be associated to multiple devices. The device and link must be in the same global network and the same site.

# Required Parameters
- `DeviceId`: The ID of the device.
- `LinkId`: The ID of the link.
- `globalNetworkId`: The ID of the global network.

"""
AssociateLink(DeviceId, LinkId, globalNetworkId) = networkmanager("POST", "/global-networks/$(globalNetworkId)/link-associations", Dict{String, Any}("DeviceId"=>DeviceId, "LinkId"=>LinkId))
AssociateLink(DeviceId, LinkId, globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("POST", "/global-networks/$(globalNetworkId)/link-associations", Dict{String, Any}("DeviceId"=>DeviceId, "LinkId"=>LinkId, args...))

"""
    CreateDevice()

Creates a new device in a global network. If you specify both a site ID and a location, the location of the site is used for visualization in the Network Manager console.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `Description`: A description of the device. Length Constraints: Maximum length of 256 characters.
- `Location`: The location of the device.
- `Model`: The model of the device. Length Constraints: Maximum length of 128 characters.
- `SerialNumber`: The serial number of the device. Length Constraints: Maximum length of 128 characters.
- `SiteId`: The ID of the site.
- `Tags`: The tags to apply to the resource during creation.
- `Type`: The type of the device.
- `Vendor`: The vendor of the device. Length Constraints: Maximum length of 128 characters.
"""
CreateDevice(globalNetworkId) = networkmanager("POST", "/global-networks/$(globalNetworkId)/devices")
CreateDevice(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("POST", "/global-networks/$(globalNetworkId)/devices", args)

"""
    CreateGlobalNetwork()

Creates a new, empty global network.

# Optional Parameters
- `Description`: A description of the global network. Length Constraints: Maximum length of 256 characters.
- `Tags`: The tags to apply to the resource during creation.
"""
CreateGlobalNetwork() = networkmanager("POST", "/global-networks")
CreateGlobalNetwork(args::AbstractDict{String, Any}) = networkmanager("POST", "/global-networks", args)

"""
    CreateLink()

Creates a new link for a specified site.

# Required Parameters
- `Bandwidth`:  The upload speed and download speed in Mbps. 
- `SiteId`: The ID of the site.
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `Description`: A description of the link. Length Constraints: Maximum length of 256 characters.
- `Provider`: The provider of the link. Constraints: Cannot include the following characters: |   ^ Length Constraints: Maximum length of 128 characters.
- `Tags`: The tags to apply to the resource during creation.
- `Type`: The type of the link. Constraints: Cannot include the following characters: |   ^ Length Constraints: Maximum length of 128 characters.
"""
CreateLink(Bandwidth, SiteId, globalNetworkId) = networkmanager("POST", "/global-networks/$(globalNetworkId)/links", Dict{String, Any}("Bandwidth"=>Bandwidth, "SiteId"=>SiteId))
CreateLink(Bandwidth, SiteId, globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("POST", "/global-networks/$(globalNetworkId)/links", Dict{String, Any}("Bandwidth"=>Bandwidth, "SiteId"=>SiteId, args...))

"""
    CreateSite()

Creates a new site in a global network.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `Description`: A description of your site. Length Constraints: Maximum length of 256 characters.
- `Location`: The site location. This information is used for visualization in the Network Manager console. If you specify the address, the latitude and longitude are automatically calculated.    Address: The physical address of the site.    Latitude: The latitude of the site.     Longitude: The longitude of the site.  
- `Tags`: The tags to apply to the resource during creation.
"""
CreateSite(globalNetworkId) = networkmanager("POST", "/global-networks/$(globalNetworkId)/sites")
CreateSite(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("POST", "/global-networks/$(globalNetworkId)/sites", args)

"""
    DeleteDevice()

Deletes an existing device. You must first disassociate the device from any links and customer gateways.

# Required Parameters
- `deviceId`: The ID of the device.
- `globalNetworkId`: The ID of the global network.

"""
DeleteDevice(deviceId, globalNetworkId) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/devices/$(deviceId)")
DeleteDevice(deviceId, globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/devices/$(deviceId)", args)

"""
    DeleteGlobalNetwork()

Deletes an existing global network. You must first delete all global network objects (devices, links, and sites) and deregister all transit gateways.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

"""
DeleteGlobalNetwork(globalNetworkId) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)")
DeleteGlobalNetwork(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)", args)

"""
    DeleteLink()

Deletes an existing link. You must first disassociate the link from any devices and customer gateways.

# Required Parameters
- `globalNetworkId`: The ID of the global network.
- `linkId`: The ID of the link.

"""
DeleteLink(globalNetworkId, linkId) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/links/$(linkId)")
DeleteLink(globalNetworkId, linkId, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/links/$(linkId)", args)

"""
    DeleteSite()

Deletes an existing site. The site cannot be associated with any device or link.

# Required Parameters
- `globalNetworkId`: The ID of the global network.
- `siteId`: The ID of the site.

"""
DeleteSite(globalNetworkId, siteId) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/sites/$(siteId)")
DeleteSite(globalNetworkId, siteId, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/sites/$(siteId)", args)

"""
    DeregisterTransitGateway()

Deregisters a transit gateway from your global network. This action does not delete your transit gateway, or modify any of its attachments. This action removes any customer gateway associations.

# Required Parameters
- `globalNetworkId`: The ID of the global network.
- `transitGatewayArn`: The Amazon Resource Name (ARN) of the transit gateway.

"""
DeregisterTransitGateway(globalNetworkId, transitGatewayArn) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/transit-gateway-registrations/$(transitGatewayArn)")
DeregisterTransitGateway(globalNetworkId, transitGatewayArn, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/transit-gateway-registrations/$(transitGatewayArn)", args)

"""
    DescribeGlobalNetworks()

Describes one or more global networks. By default, all global networks are described. To describe the objects in your global network, you must use the appropriate Get* action. For example, to list the transit gateways in your global network, use GetTransitGatewayRegistrations.

# Optional Parameters
- `globalNetworkIds`: The IDs of one or more global networks. The maximum is 10.
- `maxResults`: The maximum number of results to return.
- `nextToken`: The token for the next page of results.
"""
DescribeGlobalNetworks() = networkmanager("GET", "/global-networks")
DescribeGlobalNetworks(args::AbstractDict{String, Any}) = networkmanager("GET", "/global-networks", args)

"""
    DisassociateCustomerGateway()

Disassociates a customer gateway from a device and a link.

# Required Parameters
- `customerGatewayArn`: The Amazon Resource Name (ARN) of the customer gateway. For more information, see Resources Defined by Amazon EC2.
- `globalNetworkId`: The ID of the global network.

"""
DisassociateCustomerGateway(customerGatewayArn, globalNetworkId) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/customer-gateway-associations/$(customerGatewayArn)")
DisassociateCustomerGateway(customerGatewayArn, globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/customer-gateway-associations/$(customerGatewayArn)", args)

"""
    DisassociateLink()

Disassociates an existing device from a link. You must first disassociate any customer gateways that are associated with the link.

# Required Parameters
- `deviceId`: The ID of the device.
- `globalNetworkId`: The ID of the global network.
- `linkId`: The ID of the link.

"""
DisassociateLink(deviceId, globalNetworkId, linkId) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/link-associations", Dict{String, Any}("deviceId"=>deviceId, "linkId"=>linkId))
DisassociateLink(deviceId, globalNetworkId, linkId, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/global-networks/$(globalNetworkId)/link-associations", Dict{String, Any}("deviceId"=>deviceId, "linkId"=>linkId, args...))

"""
    GetCustomerGatewayAssociations()

Gets the association information for customer gateways that are associated with devices and links in your global network.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `customerGatewayArns`: One or more customer gateway Amazon Resource Names (ARNs). For more information, see Resources Defined by Amazon EC2. The maximum is 10.
- `maxResults`: The maximum number of results to return.
- `nextToken`: The token for the next page of results.
"""
GetCustomerGatewayAssociations(globalNetworkId) = networkmanager("GET", "/global-networks/$(globalNetworkId)/customer-gateway-associations")
GetCustomerGatewayAssociations(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("GET", "/global-networks/$(globalNetworkId)/customer-gateway-associations", args)

"""
    GetDevices()

Gets information about one or more of your devices in a global network.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `deviceIds`: One or more device IDs. The maximum is 10.
- `maxResults`: The maximum number of results to return.
- `nextToken`: The token for the next page of results.
- `siteId`: The ID of the site.
"""
GetDevices(globalNetworkId) = networkmanager("GET", "/global-networks/$(globalNetworkId)/devices")
GetDevices(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("GET", "/global-networks/$(globalNetworkId)/devices", args)

"""
    GetLinkAssociations()

Gets the link associations for a device or a link. Either the device ID or the link ID must be specified.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `deviceId`: The ID of the device.
- `linkId`: The ID of the link.
- `maxResults`: The maximum number of results to return.
- `nextToken`: The token for the next page of results.
"""
GetLinkAssociations(globalNetworkId) = networkmanager("GET", "/global-networks/$(globalNetworkId)/link-associations")
GetLinkAssociations(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("GET", "/global-networks/$(globalNetworkId)/link-associations", args)

"""
    GetLinks()

Gets information about one or more links in a specified global network. If you specify the site ID, you cannot specify the type or provider in the same request. You can specify the type and provider in the same request.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `linkIds`: One or more link IDs. The maximum is 10.
- `maxResults`: The maximum number of results to return.
- `nextToken`: The token for the next page of results.
- `provider`: The link provider.
- `siteId`: The ID of the site.
- `type`: The link type.
"""
GetLinks(globalNetworkId) = networkmanager("GET", "/global-networks/$(globalNetworkId)/links")
GetLinks(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("GET", "/global-networks/$(globalNetworkId)/links", args)

"""
    GetSites()

Gets information about one or more of your sites in a global network.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `maxResults`: The maximum number of results to return.
- `nextToken`: The token for the next page of results.
- `siteIds`: One or more site IDs. The maximum is 10.
"""
GetSites(globalNetworkId) = networkmanager("GET", "/global-networks/$(globalNetworkId)/sites")
GetSites(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("GET", "/global-networks/$(globalNetworkId)/sites", args)

"""
    GetTransitGatewayRegistrations()

Gets information about the transit gateway registrations in a specified global network.

# Required Parameters
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `maxResults`: The maximum number of results to return.
- `nextToken`: The token for the next page of results.
- `transitGatewayArns`: The Amazon Resource Names (ARNs) of one or more transit gateways. The maximum is 10.
"""
GetTransitGatewayRegistrations(globalNetworkId) = networkmanager("GET", "/global-networks/$(globalNetworkId)/transit-gateway-registrations")
GetTransitGatewayRegistrations(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("GET", "/global-networks/$(globalNetworkId)/transit-gateway-registrations", args)

"""
    ListTagsForResource()

Lists the tags for a specified resource.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the resource.

"""
ListTagsForResource(resourceArn) = networkmanager("GET", "/tags/$(resourceArn)")
ListTagsForResource(resourceArn, args::AbstractDict{String, <:Any}) = networkmanager("GET", "/tags/$(resourceArn)", args)

"""
    RegisterTransitGateway()

Registers a transit gateway in your global network. The transit gateway can be in any AWS Region, but it must be owned by the same AWS account that owns the global network. You cannot register a transit gateway in more than one global network.

# Required Parameters
- `TransitGatewayArn`: The Amazon Resource Name (ARN) of the transit gateway. For more information, see Resources Defined by Amazon EC2.
- `globalNetworkId`: The ID of the global network.

"""
RegisterTransitGateway(TransitGatewayArn, globalNetworkId) = networkmanager("POST", "/global-networks/$(globalNetworkId)/transit-gateway-registrations", Dict{String, Any}("TransitGatewayArn"=>TransitGatewayArn))
RegisterTransitGateway(TransitGatewayArn, globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("POST", "/global-networks/$(globalNetworkId)/transit-gateway-registrations", Dict{String, Any}("TransitGatewayArn"=>TransitGatewayArn, args...))

"""
    TagResource()

Tags a specified resource.

# Required Parameters
- `Tags`: The tags to apply to the specified resource.
- `resourceArn`: The Amazon Resource Name (ARN) of the resource.

"""
TagResource(Tags, resourceArn) = networkmanager("POST", "/tags/$(resourceArn)", Dict{String, Any}("Tags"=>Tags))
TagResource(Tags, resourceArn, args::AbstractDict{String, <:Any}) = networkmanager("POST", "/tags/$(resourceArn)", Dict{String, Any}("Tags"=>Tags, args...))

"""
    UntagResource()

Removes tags from a specified resource.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the resource.
- `tagKeys`: The tag keys to remove from the specified resource.

"""
UntagResource(resourceArn, tagKeys) = networkmanager("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys))
UntagResource(resourceArn, tagKeys, args::AbstractDict{String, <:Any}) = networkmanager("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys, args...))

"""
    UpdateDevice()

Updates the details for an existing device. To remove information for any of the parameters, specify an empty string.

# Required Parameters
- `deviceId`: The ID of the device.
- `globalNetworkId`: The ID of the global network.

# Optional Parameters
- `Description`: A description of the device. Length Constraints: Maximum length of 256 characters.
- `Location`: 
- `Model`: The model of the device. Length Constraints: Maximum length of 128 characters.
- `SerialNumber`: The serial number of the device. Length Constraints: Maximum length of 128 characters.
- `SiteId`: The ID of the site.
- `Type`: The type of the device.
- `Vendor`: The vendor of the device. Length Constraints: Maximum length of 128 characters.
"""
UpdateDevice(deviceId, globalNetworkId) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)/devices/$(deviceId)")
UpdateDevice(deviceId, globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)/devices/$(deviceId)", args)

"""
    UpdateGlobalNetwork()

Updates an existing global network. To remove information for any of the parameters, specify an empty string.

# Required Parameters
- `globalNetworkId`: The ID of your global network.

# Optional Parameters
- `Description`: A description of the global network. Length Constraints: Maximum length of 256 characters.
"""
UpdateGlobalNetwork(globalNetworkId) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)")
UpdateGlobalNetwork(globalNetworkId, args::AbstractDict{String, <:Any}) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)", args)

"""
    UpdateLink()

Updates the details for an existing link. To remove information for any of the parameters, specify an empty string.

# Required Parameters
- `globalNetworkId`: The ID of the global network.
- `linkId`: The ID of the link.

# Optional Parameters
- `Bandwidth`: The upload and download speed in Mbps. 
- `Description`: A description of the link. Length Constraints: Maximum length of 256 characters.
- `Provider`: The provider of the link. Length Constraints: Maximum length of 128 characters.
- `Type`: The type of the link. Length Constraints: Maximum length of 128 characters.
"""
UpdateLink(globalNetworkId, linkId) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)/links/$(linkId)")
UpdateLink(globalNetworkId, linkId, args::AbstractDict{String, <:Any}) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)/links/$(linkId)", args)

"""
    UpdateSite()

Updates the information for an existing site. To remove information for any of the parameters, specify an empty string.

# Required Parameters
- `globalNetworkId`: The ID of the global network.
- `siteId`: The ID of your site.

# Optional Parameters
- `Description`: A description of your site. Length Constraints: Maximum length of 256 characters.
- `Location`: The site location:    Address: The physical address of the site.    Latitude: The latitude of the site.     Longitude: The longitude of the site.  
"""
UpdateSite(globalNetworkId, siteId) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)/sites/$(siteId)")
UpdateSite(globalNetworkId, siteId, args::AbstractDict{String, <:Any}) = networkmanager("PATCH", "/global-networks/$(globalNetworkId)/sites/$(siteId)", args)
