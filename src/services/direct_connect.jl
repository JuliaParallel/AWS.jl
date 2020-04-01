include("../AWSServices.jl")
using .AWSServices: direct_connect

"""
    AllocatePrivateVirtualInterface()

Provisions a private virtual interface to be owned by the specified AWS account. Virtual interfaces created using this action must be confirmed by the owner using ConfirmPrivateVirtualInterface. Until then, the virtual interface is in the Confirming state and is not available to handle traffic.

Required Parameters
{
  "connectionId": "The ID of the connection on which the private virtual interface is provisioned.",
  "newPrivateVirtualInterfaceAllocation": "Information about the private virtual interface.",
  "ownerAccount": "The ID of the AWS account that owns the virtual private interface."
}
"""
AllocatePrivateVirtualInterface(args) = direct_connect("AllocatePrivateVirtualInterface", args)

"""
    DeleteVirtualInterface()

Deletes a virtual interface.

Required Parameters
{
  "virtualInterfaceId": "The ID of the virtual interface."
}
"""
DeleteVirtualInterface(args) = direct_connect("DeleteVirtualInterface", args)

"""
    AssociateHostedConnection()

Associates a hosted connection and its virtual interfaces with a link aggregation group (LAG) or interconnect. If the target interconnect or LAG has an existing hosted connection with a conflicting VLAN number or IP address, the operation fails. This action temporarily interrupts the hosted connection's connectivity to AWS as it is being migrated.  Intended for use by AWS Direct Connect Partners only. 

Required Parameters
{
  "connectionId": "The ID of the hosted connection.",
  "parentConnectionId": "The ID of the interconnect or the LAG."
}
"""
AssociateHostedConnection(args) = direct_connect("AssociateHostedConnection", args)

"""
    AssociateConnectionWithLag()

Associates an existing connection with a link aggregation group (LAG). The connection is interrupted and re-established as a member of the LAG (connectivity to AWS is interrupted). The connection must be hosted on the same AWS Direct Connect endpoint as the LAG, and its bandwidth must match the bandwidth for the LAG. You can re-associate a connection that's currently associated with a different LAG; however, if removing the connection would cause the original LAG to fall below its setting for minimum number of operational connections, the request fails. Any virtual interfaces that are directly associated with the connection are automatically re-associated with the LAG. If the connection was originally associated with a different LAG, the virtual interfaces remain associated with the original LAG. For interconnects, any hosted connections are automatically re-associated with the LAG. If the interconnect was originally associated with a different LAG, the hosted connections remain associated with the original LAG.

Required Parameters
{
  "connectionId": "The ID of the connection.",
  "lagId": "The ID of the LAG with which to associate the connection."
}
"""
AssociateConnectionWithLag(args) = direct_connect("AssociateConnectionWithLag", args)

"""
    DescribeDirectConnectGatewayAttachments()

Lists the attachments between your Direct Connect gateways and virtual interfaces. You must specify a Direct Connect gateway, a virtual interface, or both. If you specify a Direct Connect gateway, the response contains all virtual interfaces attached to the Direct Connect gateway. If you specify a virtual interface, the response contains all Direct Connect gateways attached to the virtual interface. If you specify both, the response contains the attachment between the Direct Connect gateway and the virtual interface.

Optional Parameters
{
  "virtualInterfaceId": "The ID of the virtual interface.",
  "maxResults": "The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned nextToken value. If MaxResults is given a value larger than 100, only 100 results are returned.",
  "nextToken": "The token provided in the previous call to retrieve the next page.",
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}
"""
DescribeDirectConnectGatewayAttachments() = direct_connect("DescribeDirectConnectGatewayAttachments")
DescribeDirectConnectGatewayAttachments(args) = direct_connect("DescribeDirectConnectGatewayAttachments", args)

"""
    DeleteDirectConnectGateway()

Deletes the specified Direct Connect gateway. You must first delete all virtual interfaces that are attached to the Direct Connect gateway and disassociate all virtual private gateways associated with the Direct Connect gateway.

Required Parameters
{
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}
"""
DeleteDirectConnectGateway(args) = direct_connect("DeleteDirectConnectGateway", args)

"""
    DescribeConnectionLoa()

Deprecated. Use DescribeLoa instead. Gets the LOA-CFA for a connection. The Letter of Authorization - Connecting Facility Assignment (LOA-CFA) is a document that your APN partner or service provider uses when establishing your cross connect to AWS at the colocation facility. For more information, see Requesting Cross Connects at AWS Direct Connect Locations in the AWS Direct Connect User Guide.

Required Parameters
{
  "connectionId": "The ID of the connection."
}

Optional Parameters
{
  "providerName": "The name of the APN partner or service provider who establishes connectivity on your behalf. If you specify this parameter, the LOA-CFA lists the provider name alongside your company name as the requester of the cross connect.",
  "loaContentType": "The standard media type for the LOA-CFA document. The only supported value is application/pdf."
}
"""
DescribeConnectionLoa(args) = direct_connect("DescribeConnectionLoa", args)

"""
    UpdateDirectConnectGatewayAssociation()

Updates the specified attributes of the Direct Connect gateway association. Add or remove prefixes from the association.

Optional Parameters
{
  "associationId": "The ID of the Direct Connect gateway association.",
  "removeAllowedPrefixesToDirectConnectGateway": "The Amazon VPC prefixes to no longer advertise to the Direct Connect gateway.",
  "addAllowedPrefixesToDirectConnectGateway": "The Amazon VPC prefixes to advertise to the Direct Connect gateway."
}
"""
UpdateDirectConnectGatewayAssociation() = direct_connect("UpdateDirectConnectGatewayAssociation")
UpdateDirectConnectGatewayAssociation(args) = direct_connect("UpdateDirectConnectGatewayAssociation", args)

"""
    TagResource()

Adds the specified tags to the specified AWS Direct Connect resource. Each resource can have a maximum of 50 tags. Each tag consists of a key and an optional value. If a tag with the same key is already associated with the resource, this action updates its value.

Required Parameters
{
  "resourceArn": "The Amazon Resource Name (ARN) of the resource.",
  "tags": "The tags to add."
}
"""
TagResource(args) = direct_connect("TagResource", args)

"""
    AllocateHostedConnection()

Creates a hosted connection on the specified interconnect or a link aggregation group (LAG) of interconnects. Allocates a VLAN number and a specified amount of capacity (bandwidth) for use by a hosted connection on the specified interconnect or LAG of interconnects. AWS polices the hosted connection for the specified capacity and the AWS Direct Connect Partner must also police the hosted connection for the specified capacity.  Intended for use by AWS Direct Connect Partners only. 

Required Parameters
{
  "connectionId": "The ID of the interconnect or LAG.",
  "connectionName": "The name of the hosted connection.",
  "bandwidth": "The bandwidth of the connection. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, and 10Gbps. Note that only those AWS Direct Connect Partners who have met specific requirements are allowed to create a 1Gbps, 2Gbps, 5Gbps or 10Gbps hosted connection. ",
  "vlan": "The dedicated VLAN provisioned to the hosted connection.",
  "ownerAccount": "The ID of the AWS account ID of the customer for the connection."
}

Optional Parameters
{
  "tags": "The tags associated with the connection."
}
"""
AllocateHostedConnection(args) = direct_connect("AllocateHostedConnection", args)

"""
    DescribeVirtualGateways()

Lists the virtual private gateways owned by the AWS account. You can create one or more AWS Direct Connect private virtual interfaces linked to a virtual private gateway.
"""
DescribeVirtualGateways() = direct_connect("DescribeVirtualGateways")
DescribeVirtualGateways(args) = direct_connect("DescribeVirtualGateways", args)

"""
    DescribeLocations()

Lists the AWS Direct Connect locations in the current AWS Region. These are the locations that can be selected when calling CreateConnection or CreateInterconnect.
"""
DescribeLocations() = direct_connect("DescribeLocations")
DescribeLocations(args) = direct_connect("DescribeLocations", args)

"""
    ConfirmPublicVirtualInterface()

Accepts ownership of a public virtual interface created by another AWS account. After the virtual interface owner makes this call, the specified virtual interface is created and made available to handle traffic.

Required Parameters
{
  "virtualInterfaceId": "The ID of the virtual interface."
}
"""
ConfirmPublicVirtualInterface(args) = direct_connect("ConfirmPublicVirtualInterface", args)

"""
    DescribeDirectConnectGatewayAssociations()

Lists the associations between your Direct Connect gateways and virtual private gateways. You must specify a Direct Connect gateway, a virtual private gateway, or both. If you specify a Direct Connect gateway, the response contains all virtual private gateways associated with the Direct Connect gateway. If you specify a virtual private gateway, the response contains all Direct Connect gateways associated with the virtual private gateway. If you specify both, the response contains the association between the Direct Connect gateway and the virtual private gateway.

Optional Parameters
{
  "directConnectGatewayId": "The ID of the Direct Connect gateway.",
  "associationId": "The ID of the Direct Connect gateway association.",
  "associatedGatewayId": "The ID of the associated gateway.",
  "maxResults": "The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned nextToken value. If MaxResults is given a value larger than 100, only 100 results are returned.",
  "nextToken": "The token provided in the previous call to retrieve the next page.",
  "virtualGatewayId": "The ID of the virtual private gateway."
}
"""
DescribeDirectConnectGatewayAssociations() = direct_connect("DescribeDirectConnectGatewayAssociations")
DescribeDirectConnectGatewayAssociations(args) = direct_connect("DescribeDirectConnectGatewayAssociations", args)

"""
    AllocateTransitVirtualInterface()

Provisions a transit virtual interface to be owned by the specified AWS account. Use this type of interface to connect a transit gateway to your Direct Connect gateway. The owner of a connection provisions a transit virtual interface to be owned by the specified AWS account. After you create a transit virtual interface, it must be confirmed by the owner using ConfirmTransitVirtualInterface. Until this step has been completed, the transit virtual interface is in the requested state and is not available to handle traffic.

Required Parameters
{
  "connectionId": "The ID of the connection on which the transit virtual interface is provisioned.",
  "newTransitVirtualInterfaceAllocation": "Information about the transit virtual interface.",
  "ownerAccount": "The ID of the AWS account that owns the transit virtual interface."
}
"""
AllocateTransitVirtualInterface(args) = direct_connect("AllocateTransitVirtualInterface", args)

"""
    CreatePrivateVirtualInterface()

Creates a private virtual interface. A virtual interface is the VLAN that transports AWS Direct Connect traffic. A private virtual interface can be connected to either a Direct Connect gateway or a Virtual Private Gateway (VGW). Connecting the private virtual interface to a Direct Connect gateway enables the possibility for connecting to multiple VPCs, including VPCs in different AWS Regions. Connecting the private virtual interface to a VGW only provides access to a single VPC within the same Region.

Required Parameters
{
  "connectionId": "The ID of the connection.",
  "newPrivateVirtualInterface": "Information about the private virtual interface."
}
"""
CreatePrivateVirtualInterface(args) = direct_connect("CreatePrivateVirtualInterface", args)

"""
    CreatePublicVirtualInterface()

Creates a public virtual interface. A virtual interface is the VLAN that transports AWS Direct Connect traffic. A public virtual interface supports sending traffic to public services of AWS such as Amazon S3. When creating an IPv6 public virtual interface (addressFamily is ipv6), leave the customer and amazon address fields blank to use auto-assigned IPv6 space. Custom IPv6 addresses are not supported.

Required Parameters
{
  "connectionId": "The ID of the connection.",
  "newPublicVirtualInterface": "Information about the public virtual interface."
}
"""
CreatePublicVirtualInterface(args) = direct_connect("CreatePublicVirtualInterface", args)

"""
    CreateBGPPeer()

Creates a BGP peer on the specified virtual interface. You must create a BGP peer for the corresponding address family (IPv4/IPv6) in order to access AWS resources that also use that address family. If logical redundancy is not supported by the connection, interconnect, or LAG, the BGP peer cannot be in the same address family as an existing BGP peer on the virtual interface. When creating a IPv6 BGP peer, omit the Amazon address and customer address. IPv6 addresses are automatically assigned from the Amazon pool of IPv6 addresses; you cannot specify custom IPv6 addresses. For a public virtual interface, the Autonomous System Number (ASN) must be private or already whitelisted for the virtual interface.

Optional Parameters
{
  "virtualInterfaceId": "The ID of the virtual interface.",
  "newBGPPeer": "Information about the BGP peer."
}
"""
CreateBGPPeer() = direct_connect("CreateBGPPeer")
CreateBGPPeer(args) = direct_connect("CreateBGPPeer", args)

"""
    DeleteBGPPeer()

Deletes the specified BGP peer on the specified virtual interface with the specified customer address and ASN. You cannot delete the last BGP peer from a virtual interface.

Optional Parameters
{
  "virtualInterfaceId": "The ID of the virtual interface.",
  "asn": "The autonomous system (AS) number for Border Gateway Protocol (BGP) configuration.",
  "customerAddress": "The IP address assigned to the customer interface.",
  "bgpPeerId": "The ID of the BGP peer."
}
"""
DeleteBGPPeer() = direct_connect("DeleteBGPPeer")
DeleteBGPPeer(args) = direct_connect("DeleteBGPPeer", args)

"""
    DeleteLag()

Deletes the specified link aggregation group (LAG). You cannot delete a LAG if it has active virtual interfaces or hosted connections.

Required Parameters
{
  "lagId": "The ID of the LAG."
}
"""
DeleteLag(args) = direct_connect("DeleteLag", args)

"""
    UntagResource()

Removes one or more tags from the specified AWS Direct Connect resource.

Required Parameters
{
  "resourceArn": "The Amazon Resource Name (ARN) of the resource.",
  "tagKeys": "The tag keys of the tags to remove."
}
"""
UntagResource(args) = direct_connect("UntagResource", args)

"""
    AllocateConnectionOnInterconnect()

Deprecated. Use AllocateHostedConnection instead. Creates a hosted connection on an interconnect. Allocates a VLAN number and a specified amount of bandwidth for use by a hosted connection on the specified interconnect.  Intended for use by AWS Direct Connect Partners only. 

Required Parameters
{
  "connectionName": "The name of the provisioned connection.",
  "interconnectId": "The ID of the interconnect on which the connection will be provisioned.",
  "bandwidth": "The bandwidth of the connection. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, and 10Gbps. Note that only those AWS Direct Connect Partners who have met specific requirements are allowed to create a 1Gbps, 2Gbps, 5Gbps or 10Gbps hosted connection.",
  "vlan": "The dedicated VLAN provisioned to the connection.",
  "ownerAccount": "The ID of the AWS account of the customer for whom the connection will be provisioned."
}
"""
AllocateConnectionOnInterconnect(args) = direct_connect("AllocateConnectionOnInterconnect", args)

"""
    DescribeLoa()

Gets the LOA-CFA for a connection, interconnect, or link aggregation group (LAG). The Letter of Authorization - Connecting Facility Assignment (LOA-CFA) is a document that is used when establishing your cross connect to AWS at the colocation facility. For more information, see Requesting Cross Connects at AWS Direct Connect Locations in the AWS Direct Connect User Guide.

Required Parameters
{
  "connectionId": "The ID of a connection, LAG, or interconnect."
}

Optional Parameters
{
  "providerName": "The name of the service provider who establishes connectivity on your behalf. If you specify this parameter, the LOA-CFA lists the provider name alongside your company name as the requester of the cross connect.",
  "loaContentType": "The standard media type for the LOA-CFA document. The only supported value is application/pdf."
}
"""
DescribeLoa(args) = direct_connect("DescribeLoa", args)

"""
    DeleteDirectConnectGatewayAssociationProposal()

Deletes the association proposal request between the specified Direct Connect gateway and virtual private gateway or transit gateway.

Required Parameters
{
  "proposalId": "The ID of the proposal."
}
"""
DeleteDirectConnectGatewayAssociationProposal(args) = direct_connect("DeleteDirectConnectGatewayAssociationProposal", args)

"""
    DisassociateConnectionFromLag()

Disassociates a connection from a link aggregation group (LAG). The connection is interrupted and re-established as a standalone connection (the connection is not deleted; to delete the connection, use the DeleteConnection request). If the LAG has associated virtual interfaces or hosted connections, they remain associated with the LAG. A disassociated connection owned by an AWS Direct Connect Partner is automatically converted to an interconnect. If disassociating the connection would cause the LAG to fall below its setting for minimum number of operational connections, the request fails, except when it's the last member of the LAG. If all connections are disassociated, the LAG continues to exist as an empty LAG with no physical connections. 

Required Parameters
{
  "connectionId": "The ID of the connection.",
  "lagId": "The ID of the LAG."
}
"""
DisassociateConnectionFromLag(args) = direct_connect("DisassociateConnectionFromLag", args)

"""
    DescribeInterconnectLoa()

Deprecated. Use DescribeLoa instead. Gets the LOA-CFA for the specified interconnect. The Letter of Authorization - Connecting Facility Assignment (LOA-CFA) is a document that is used when establishing your cross connect to AWS at the colocation facility. For more information, see Requesting Cross Connects at AWS Direct Connect Locations in the AWS Direct Connect User Guide.

Required Parameters
{
  "interconnectId": "The ID of the interconnect."
}

Optional Parameters
{
  "providerName": "The name of the service provider who establishes connectivity on your behalf. If you supply this parameter, the LOA-CFA lists the provider name alongside your company name as the requester of the cross connect.",
  "loaContentType": "The standard media type for the LOA-CFA document. The only supported value is application/pdf."
}
"""
DescribeInterconnectLoa(args) = direct_connect("DescribeInterconnectLoa", args)

"""
    CreateConnection()

Creates a connection between a customer network and a specific AWS Direct Connect location. A connection links your internal network to an AWS Direct Connect location over a standard Ethernet fiber-optic cable. One end of the cable is connected to your router, the other to an AWS Direct Connect router. To find the locations for your Region, use DescribeLocations. You can automatically add the new connection to a link aggregation group (LAG) by specifying a LAG ID in the request. This ensures that the new connection is allocated on the same AWS Direct Connect endpoint that hosts the specified LAG. If there are no available ports on the endpoint, the request fails and no connection is created.

Required Parameters
{
  "location": "The location of the connection.",
  "connectionName": "The name of the connection.",
  "bandwidth": "The bandwidth of the connection."
}

Optional Parameters
{
  "providerName": "The name of the service provider associated with the requested connection.",
  "lagId": "The ID of the LAG.",
  "tags": "The tags to associate with the lag."
}
"""
CreateConnection(args) = direct_connect("CreateConnection", args)

"""
    CreateTransitVirtualInterface()

Creates a transit virtual interface. A transit virtual interface should be used to access one or more transit gateways associated with Direct Connect gateways. A transit virtual interface enables the connection of multiple VPCs attached to a transit gateway to a Direct Connect gateway.  If you associate your transit gateway with one or more Direct Connect gateways, the Autonomous System Number (ASN) used by the transit gateway and the Direct Connect gateway must be different. For example, if you use the default ASN 64512 for both your the transit gateway and Direct Connect gateway, the association request fails. 

Required Parameters
{
  "connectionId": "The ID of the connection.",
  "newTransitVirtualInterface": "Information about the transit virtual interface."
}
"""
CreateTransitVirtualInterface(args) = direct_connect("CreateTransitVirtualInterface", args)

"""
    DescribeInterconnects()

Lists the interconnects owned by the AWS account or only the specified interconnect.

Optional Parameters
{
  "interconnectId": "The ID of the interconnect."
}
"""
DescribeInterconnects() = direct_connect("DescribeInterconnects")
DescribeInterconnects(args) = direct_connect("DescribeInterconnects", args)

"""
    AcceptDirectConnectGatewayAssociationProposal()

Accepts a proposal request to attach a virtual private gateway or transit gateway to a Direct Connect gateway.

Required Parameters
{
  "associatedGatewayOwnerAccount": "The ID of the AWS account that owns the virtual private gateway or transit gateway.",
  "proposalId": "The ID of the request proposal.",
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}

Optional Parameters
{
  "overrideAllowedPrefixesToDirectConnectGateway": "Overrides the Amazon VPC prefixes advertised to the Direct Connect gateway. For information about how to set the prefixes, see Allowed Prefixes in the AWS Direct Connect User Guide."
}
"""
AcceptDirectConnectGatewayAssociationProposal(args) = direct_connect("AcceptDirectConnectGatewayAssociationProposal", args)

"""
    DeleteInterconnect()

Deletes the specified interconnect.  Intended for use by AWS Direct Connect Partners only. 

Required Parameters
{
  "interconnectId": "The ID of the interconnect."
}
"""
DeleteInterconnect(args) = direct_connect("DeleteInterconnect", args)

"""
    ConfirmConnection()

Confirms the creation of the specified hosted connection on an interconnect. Upon creation, the hosted connection is initially in the Ordering state, and remains in this state until the owner confirms creation of the hosted connection.

Required Parameters
{
  "connectionId": "The ID of the hosted connection."
}
"""
ConfirmConnection(args) = direct_connect("ConfirmConnection", args)

"""
    ConfirmPrivateVirtualInterface()

Accepts ownership of a private virtual interface created by another AWS account. After the virtual interface owner makes this call, the virtual interface is created and attached to the specified virtual private gateway or Direct Connect gateway, and is made available to handle traffic.

Required Parameters
{
  "virtualInterfaceId": "The ID of the virtual interface."
}

Optional Parameters
{
  "virtualGatewayId": "The ID of the virtual private gateway.",
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}
"""
ConfirmPrivateVirtualInterface(args) = direct_connect("ConfirmPrivateVirtualInterface", args)

"""
    UpdateVirtualInterfaceAttributes()

Updates the specified attributes of the specified virtual private interface. Setting the MTU of a virtual interface to 9001 (jumbo frames) can cause an update to the underlying physical connection if it wasn't updated to support jumbo frames. Updating the connection disrupts network connectivity for all virtual interfaces associated with the connection for up to 30 seconds. To check whether your connection supports jumbo frames, call DescribeConnections. To check whether your virtual interface supports jumbo frames, call DescribeVirtualInterfaces.

Required Parameters
{
  "virtualInterfaceId": "The ID of the virtual private interface."
}

Optional Parameters
{
  "mtu": "The maximum transmission unit (MTU), in bytes. The supported values are 1500 and 9001. The default value is 1500."
}
"""
UpdateVirtualInterfaceAttributes(args) = direct_connect("UpdateVirtualInterfaceAttributes", args)

"""
    ConfirmTransitVirtualInterface()

Accepts ownership of a transit virtual interface created by another AWS account.  After the owner of the transit virtual interface makes this call, the specified transit virtual interface is created and made available to handle traffic.

Required Parameters
{
  "virtualInterfaceId": "The ID of the virtual interface.",
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}
"""
ConfirmTransitVirtualInterface(args) = direct_connect("ConfirmTransitVirtualInterface", args)

"""
    DescribeConnectionsOnInterconnect()

Deprecated. Use DescribeHostedConnections instead. Lists the connections that have been provisioned on the specified interconnect.  Intended for use by AWS Direct Connect Partners only. 

Required Parameters
{
  "interconnectId": "The ID of the interconnect."
}
"""
DescribeConnectionsOnInterconnect(args) = direct_connect("DescribeConnectionsOnInterconnect", args)

"""
    DeleteDirectConnectGatewayAssociation()

Deletes the association between the specified Direct Connect gateway and virtual private gateway. We recommend that you specify the associationID to delete the association. Alternatively, if you own virtual gateway and a Direct Connect gateway association, you can specify the virtualGatewayId and directConnectGatewayId to delete an association.

Optional Parameters
{
  "directConnectGatewayId": "The ID of the Direct Connect gateway.",
  "associationId": "The ID of the Direct Connect gateway association.",
  "virtualGatewayId": "The ID of the virtual private gateway."
}
"""
DeleteDirectConnectGatewayAssociation() = direct_connect("DeleteDirectConnectGatewayAssociation")
DeleteDirectConnectGatewayAssociation(args) = direct_connect("DeleteDirectConnectGatewayAssociation", args)

"""
    DescribeTags()

Describes the tags associated with the specified AWS Direct Connect resources.

Required Parameters
{
  "resourceArns": "The Amazon Resource Names (ARNs) of the resources."
}
"""
DescribeTags(args) = direct_connect("DescribeTags", args)

"""
    CreateLag()

Creates a link aggregation group (LAG) with the specified number of bundled physical connections between the customer network and a specific AWS Direct Connect location. A LAG is a logical interface that uses the Link Aggregation Control Protocol (LACP) to aggregate multiple interfaces, enabling you to treat them as a single interface. All connections in a LAG must use the same bandwidth and must terminate at the same AWS Direct Connect endpoint. You can have up to 10 connections per LAG. Regardless of this limit, if you request more connections for the LAG than AWS Direct Connect can allocate on a single endpoint, no LAG is created. You can specify an existing physical connection or interconnect to include in the LAG (which counts towards the total number of connections). Doing so interrupts the current physical connection or hosted connections, and re-establishes them as a member of the LAG. The LAG will be created on the same AWS Direct Connect endpoint to which the connection terminates. Any virtual interfaces associated with the connection are automatically disassociated and re-associated with the LAG. The connection ID does not change. If the AWS account used to create a LAG is a registered AWS Direct Connect Partner, the LAG is automatically enabled to host sub-connections. For a LAG owned by a partner, any associated virtual interfaces cannot be directly configured.

Required Parameters
{
  "location": "The location for the LAG.",
  "connectionsBandwidth": "The bandwidth of the individual physical connections bundled by the LAG. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, and 10Gbps. ",
  "lagName": "The name of the LAG.",
  "numberOfConnections": "The number of physical connections initially provisioned and bundled by the LAG."
}

Optional Parameters
{
  "connectionId": "The ID of an existing connection to migrate to the LAG.",
  "providerName": "The name of the service provider associated with the LAG.",
  "childConnectionTags": "The tags to associate with the automtically created LAGs.",
  "tags": "The tags to associate with the LAG."
}
"""
CreateLag(args) = direct_connect("CreateLag", args)

"""
    DescribeHostedConnections()

Lists the hosted connections that have been provisioned on the specified interconnect or link aggregation group (LAG).  Intended for use by AWS Direct Connect Partners only. 

Required Parameters
{
  "connectionId": "The ID of the interconnect or LAG."
}
"""
DescribeHostedConnections(args) = direct_connect("DescribeHostedConnections", args)

"""
    DeleteConnection()

Deletes the specified connection. Deleting a connection only stops the AWS Direct Connect port hour and data transfer charges. If you are partnering with any third parties to connect with the AWS Direct Connect location, you must cancel your service with them separately.

Required Parameters
{
  "connectionId": "The ID of the connection."
}
"""
DeleteConnection(args) = direct_connect("DeleteConnection", args)

"""
    CreateInterconnect()

Creates an interconnect between an AWS Direct Connect Partner's network and a specific AWS Direct Connect location. An interconnect is a connection that is capable of hosting other connections. The AWS Direct Connect partner can use an interconnect to provide AWS Direct Connect hosted connections to customers through their own network services. Like a standard connection, an interconnect links the partner's network to an AWS Direct Connect location over a standard Ethernet fiber-optic cable. One end is connected to the partner's router, the other to an AWS Direct Connect router. You can automatically add the new interconnect to a link aggregation group (LAG) by specifying a LAG ID in the request. This ensures that the new interconnect is allocated on the same AWS Direct Connect endpoint that hosts the specified LAG. If there are no available ports on the endpoint, the request fails and no interconnect is created. For each end customer, the AWS Direct Connect Partner provisions a connection on their interconnect by calling AllocateHostedConnection. The end customer can then connect to AWS resources by creating a virtual interface on their connection, using the VLAN assigned to them by the AWS Direct Connect Partner.  Intended for use by AWS Direct Connect Partners only. 

Required Parameters
{
  "location": "The location of the interconnect.",
  "interconnectName": "The name of the interconnect.",
  "bandwidth": "The port bandwidth, in Gbps. The possible values are 1 and 10."
}

Optional Parameters
{
  "providerName": "The name of the service provider associated with the interconnect.",
  "lagId": "The ID of the LAG.",
  "tags": "The tags to associate with the interconnect."
}
"""
CreateInterconnect(args) = direct_connect("CreateInterconnect", args)

"""
    AllocatePublicVirtualInterface()

Provisions a public virtual interface to be owned by the specified AWS account. The owner of a connection calls this function to provision a public virtual interface to be owned by the specified AWS account. Virtual interfaces created using this function must be confirmed by the owner using ConfirmPublicVirtualInterface. Until this step has been completed, the virtual interface is in the confirming state and is not available to handle traffic. When creating an IPv6 public virtual interface, omit the Amazon address and customer address. IPv6 addresses are automatically assigned from the Amazon pool of IPv6 addresses; you cannot specify custom IPv6 addresses.

Required Parameters
{
  "connectionId": "The ID of the connection on which the public virtual interface is provisioned.",
  "newPublicVirtualInterfaceAllocation": "Information about the public virtual interface.",
  "ownerAccount": "The ID of the AWS account that owns the public virtual interface."
}
"""
AllocatePublicVirtualInterface(args) = direct_connect("AllocatePublicVirtualInterface", args)

"""
    UpdateLag()

Updates the attributes of the specified link aggregation group (LAG). You can update the following attributes:   The name of the LAG.   The value for the minimum number of connections that must be operational for the LAG itself to be operational.    When you create a LAG, the default value for the minimum number of operational connections is zero (0). If you update this value and the number of operational connections falls below the specified value, the LAG automatically goes down to avoid over-utilization of the remaining connections. Adjust this value with care, as it could force the LAG down if it is set higher than the current number of operational connections.

Required Parameters
{
  "lagId": "The ID of the LAG."
}

Optional Parameters
{
  "lagName": "The name of the LAG.",
  "minimumLinks": "The minimum number of physical connections that must be operational for the LAG itself to be operational."
}
"""
UpdateLag(args) = direct_connect("UpdateLag", args)

"""
    AssociateVirtualInterface()

Associates a virtual interface with a specified link aggregation group (LAG) or connection. Connectivity to AWS is temporarily interrupted as the virtual interface is being migrated. If the target connection or LAG has an associated virtual interface with a conflicting VLAN number or a conflicting IP address, the operation fails. Virtual interfaces associated with a hosted connection cannot be associated with a LAG; hosted connections must be migrated along with their virtual interfaces using AssociateHostedConnection. To reassociate a virtual interface to a new connection or LAG, the requester must own either the virtual interface itself or the connection to which the virtual interface is currently associated. Additionally, the requester must own the connection or LAG for the association.

Required Parameters
{
  "connectionId": "The ID of the LAG or connection.",
  "virtualInterfaceId": "The ID of the virtual interface."
}
"""
AssociateVirtualInterface(args) = direct_connect("AssociateVirtualInterface", args)

"""
    DescribeConnections()

Displays the specified connection or all connections in this Region.

Optional Parameters
{
  "connectionId": "The ID of the connection."
}
"""
DescribeConnections() = direct_connect("DescribeConnections")
DescribeConnections(args) = direct_connect("DescribeConnections", args)

"""
    DescribeDirectConnectGateways()

Lists all your Direct Connect gateways or only the specified Direct Connect gateway. Deleted Direct Connect gateways are not returned.

Optional Parameters
{
  "maxResults": "The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned nextToken value. If MaxResults is given a value larger than 100, only 100 results are returned.",
  "nextToken": "The token provided in the previous call to retrieve the next page.",
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}
"""
DescribeDirectConnectGateways() = direct_connect("DescribeDirectConnectGateways")
DescribeDirectConnectGateways(args) = direct_connect("DescribeDirectConnectGateways", args)

"""
    DescribeLags()

Describes all your link aggregation groups (LAG) or the specified LAG.

Optional Parameters
{
  "lagId": "The ID of the LAG."
}
"""
DescribeLags() = direct_connect("DescribeLags")
DescribeLags(args) = direct_connect("DescribeLags", args)

"""
    CreateDirectConnectGatewayAssociation()

Creates an association between a Direct Connect gateway and a virtual private gateway. The virtual private gateway must be attached to a VPC and must not be associated with another Direct Connect gateway.

Required Parameters
{
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}

Optional Parameters
{
  "gatewayId": "The ID of the virtual private gateway or transit gateway.",
  "addAllowedPrefixesToDirectConnectGateway": "The Amazon VPC prefixes to advertise to the Direct Connect gateway This parameter is required when you create an association to a transit gateway. For information about how to set the prefixes, see Allowed Prefixes in the AWS Direct Connect User Guide.",
  "virtualGatewayId": "The ID of the virtual private gateway."
}
"""
CreateDirectConnectGatewayAssociation(args) = direct_connect("CreateDirectConnectGatewayAssociation", args)

"""
    DescribeVirtualInterfaces()

Displays all virtual interfaces for an AWS account. Virtual interfaces deleted fewer than 15 minutes before you make the request are also returned. If you specify a connection ID, only the virtual interfaces associated with the connection are returned. If you specify a virtual interface ID, then only a single virtual interface is returned. A virtual interface (VLAN) transmits the traffic between the AWS Direct Connect location and the customer network.

Optional Parameters
{
  "connectionId": "The ID of the connection.",
  "virtualInterfaceId": "The ID of the virtual interface."
}
"""
DescribeVirtualInterfaces() = direct_connect("DescribeVirtualInterfaces")
DescribeVirtualInterfaces(args) = direct_connect("DescribeVirtualInterfaces", args)

"""
    CreateDirectConnectGatewayAssociationProposal()

Creates a proposal to associate the specified virtual private gateway or transit gateway with the specified Direct Connect gateway. You can only associate a Direct Connect gateway and virtual private gateway or transit gateway when the account that owns the Direct Connect gateway and the account that owns the virtual private gateway or transit gateway have the same AWS Payer ID.

Required Parameters
{
  "directConnectGatewayOwnerAccount": "The ID of the AWS account that owns the Direct Connect gateway.",
  "gatewayId": "The ID of the virtual private gateway or transit gateway.",
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}

Optional Parameters
{
  "removeAllowedPrefixesToDirectConnectGateway": "The Amazon VPC prefixes to no longer advertise to the Direct Connect gateway.",
  "addAllowedPrefixesToDirectConnectGateway": "The Amazon VPC prefixes to advertise to the Direct Connect gateway."
}
"""
CreateDirectConnectGatewayAssociationProposal(args) = direct_connect("CreateDirectConnectGatewayAssociationProposal", args)

"""
    DescribeDirectConnectGatewayAssociationProposals()

Describes one or more association proposals for connection between a virtual private gateway or transit gateway and a Direct Connect gateway. 

Optional Parameters
{
  "proposalId": "The ID of the proposal.",
  "associatedGatewayId": "The ID of the associated gateway.",
  "maxResults": "The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned nextToken value. If MaxResults is given a value larger than 100, only 100 results are returned.",
  "nextToken": "The token for the next page of results.",
  "directConnectGatewayId": "The ID of the Direct Connect gateway."
}
"""
DescribeDirectConnectGatewayAssociationProposals() = direct_connect("DescribeDirectConnectGatewayAssociationProposals")
DescribeDirectConnectGatewayAssociationProposals(args) = direct_connect("DescribeDirectConnectGatewayAssociationProposals", args)

"""
    CreateDirectConnectGateway()

Creates a Direct Connect gateway, which is an intermediate object that enables you to connect a set of virtual interfaces and virtual private gateways. A Direct Connect gateway is global and visible in any AWS Region after it is created. The virtual interfaces and virtual private gateways that are connected through a Direct Connect gateway can be in different AWS Regions. This enables you to connect to a VPC in any Region, regardless of the Region in which the virtual interfaces are located, and pass traffic between them.

Required Parameters
{
  "directConnectGatewayName": "The name of the Direct Connect gateway."
}

Optional Parameters
{
  "amazonSideAsn": "The autonomous system number (ASN) for Border Gateway Protocol (BGP) to be configured on the Amazon side of the connection. The ASN must be in the private range of 64,512 to 65,534 or 4,200,000,000 to 4,294,967,294. The default is 64512."
}
"""
CreateDirectConnectGateway(args) = direct_connect("CreateDirectConnectGateway", args)