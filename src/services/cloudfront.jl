include("../AWSServices.jl")
using .AWSServices: cloudfront

"""
    ListDistributions2019_03_26()

List CloudFront distributions.

Optional Parameters
{
  "Marker": "Use this when paginating results to indicate where to begin in your list of distributions. The results include distributions in the list that occur after the marker. To get the next page of results, set the Marker to the value of the NextMarker from the current page's response (which is also the ID of the last distribution on that page).",
  "MaxItems": "The maximum number of distributions you want in the response body."
}
"""
ListDistributions2019_03_26() = cloudfront("GET", "/2019-03-26/distribution")
ListDistributions2019_03_26(args) = cloudfront("GET", "/2019-03-26/distribution", args)
ListDistributions2019_03_26(a...; b...) = ListDistributions2019_03_26(a..., b)

"""
    TagResource2019_03_26()

Add tags to a CloudFront resource.

Required Parameters
{
  "Tags": " A complex type that contains zero or more Tag elements.",
  "Resource": " An ARN of a CloudFront resource."
}
"""
TagResource2019_03_26(Tags, Resource) = cloudfront("POST", "/2019-03-26/tagging?Operation=Tag")
TagResource2019_03_26(Tags, Resource, args) = cloudfront("POST", "/2019-03-26/tagging?Operation=Tag", args)
TagResource2019_03_26(a...; b...) = TagResource2019_03_26(a..., b)

"""
    GetFieldLevelEncryptionProfileConfig2019_03_26()

Get the field-level encryption profile configuration information.

Required Parameters
{
  "Id": "Get the ID for the field-level encryption profile configuration information."
}
"""
GetFieldLevelEncryptionProfileConfig2019_03_26(Id) = cloudfront("GET", "/2019-03-26/field-level-encryption-profile/{Id}/config")
GetFieldLevelEncryptionProfileConfig2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/field-level-encryption-profile/{Id}/config", args)
GetFieldLevelEncryptionProfileConfig2019_03_26(a...; b...) = GetFieldLevelEncryptionProfileConfig2019_03_26(a..., b)

"""
    GetCloudFrontOriginAccessIdentity2019_03_26()

Get the information about an origin access identity. 

Required Parameters
{
  "Id": "The identity's ID."
}
"""
GetCloudFrontOriginAccessIdentity2019_03_26(Id) = cloudfront("GET", "/2019-03-26/origin-access-identity/cloudfront/{Id}")
GetCloudFrontOriginAccessIdentity2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/origin-access-identity/cloudfront/{Id}", args)
GetCloudFrontOriginAccessIdentity2019_03_26(a...; b...) = GetCloudFrontOriginAccessIdentity2019_03_26(a..., b)

"""
    GetDistributionConfig2019_03_26()

Get the configuration information about a distribution. 

Required Parameters
{
  "Id": "The distribution's ID. If the ID is empty, an empty distribution configuration is returned."
}
"""
GetDistributionConfig2019_03_26(Id) = cloudfront("GET", "/2019-03-26/distribution/{Id}/config")
GetDistributionConfig2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/distribution/{Id}/config", args)
GetDistributionConfig2019_03_26(a...; b...) = GetDistributionConfig2019_03_26(a..., b)

"""
    GetDistribution2019_03_26()

Get the information about a distribution.

Required Parameters
{
  "Id": "The distribution's ID. If the ID is empty, an empty distribution configuration is returned."
}
"""
GetDistribution2019_03_26(Id) = cloudfront("GET", "/2019-03-26/distribution/{Id}")
GetDistribution2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/distribution/{Id}", args)
GetDistribution2019_03_26(a...; b...) = GetDistribution2019_03_26(a..., b)

"""
    GetPublicKeyConfig2019_03_26()

Return public key configuration informaation

Required Parameters
{
  "Id": "Request the ID for the public key configuration."
}
"""
GetPublicKeyConfig2019_03_26(Id) = cloudfront("GET", "/2019-03-26/public-key/{Id}/config")
GetPublicKeyConfig2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/public-key/{Id}/config", args)
GetPublicKeyConfig2019_03_26(a...; b...) = GetPublicKeyConfig2019_03_26(a..., b)

"""
    UpdateCloudFrontOriginAccessIdentity2019_03_26()

Update an origin access identity. 

Required Parameters
{
  "Id": "The identity's id.",
  "CloudFrontOriginAccessIdentityConfig": "The identity's configuration information."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the identity's configuration. For example: E2QWRUHAPOMQZL."
}
"""
UpdateCloudFrontOriginAccessIdentity2019_03_26(Id, CloudFrontOriginAccessIdentityConfig) = cloudfront("PUT", "/2019-03-26/origin-access-identity/cloudfront/{Id}/config")
UpdateCloudFrontOriginAccessIdentity2019_03_26(Id, CloudFrontOriginAccessIdentityConfig, args) = cloudfront("PUT", "/2019-03-26/origin-access-identity/cloudfront/{Id}/config", args)
UpdateCloudFrontOriginAccessIdentity2019_03_26(a...; b...) = UpdateCloudFrontOriginAccessIdentity2019_03_26(a..., b)

"""
    CreateDistributionWithTags2019_03_26()

Create a new distribution with tags.

Required Parameters
{
  "DistributionConfigWithTags": "The distribution's configuration information. "
}
"""
CreateDistributionWithTags2019_03_26(DistributionConfigWithTags) = cloudfront("POST", "/2019-03-26/distribution?WithTags")
CreateDistributionWithTags2019_03_26(DistributionConfigWithTags, args) = cloudfront("POST", "/2019-03-26/distribution?WithTags", args)
CreateDistributionWithTags2019_03_26(a...; b...) = CreateDistributionWithTags2019_03_26(a..., b)

"""
    CreateDistribution2019_03_26()

Creates a new web distribution. You create a CloudFront distribution to tell CloudFront where you want content to be delivered from, and the details about how to track and manage content delivery. Send a POST request to the /CloudFront API version/distribution/distribution ID resource.  When you update a distribution, there are more required fields than when you create a distribution. When you update your distribution by using UpdateDistribution, follow the steps included in the documentation to get the current configuration and then make your updates. This helps to make sure that you include all of the required fields. To view a summary, see Required Fields for Create Distribution and Update Distribution in the Amazon CloudFront Developer Guide. 

Required Parameters
{
  "DistributionConfig": "The distribution's configuration information."
}
"""
CreateDistribution2019_03_26(DistributionConfig) = cloudfront("POST", "/2019-03-26/distribution")
CreateDistribution2019_03_26(DistributionConfig, args) = cloudfront("POST", "/2019-03-26/distribution", args)
CreateDistribution2019_03_26(a...; b...) = CreateDistribution2019_03_26(a..., b)

"""
    GetPublicKey2019_03_26()

Get the public key information.

Required Parameters
{
  "Id": "Request the ID for the public key."
}
"""
GetPublicKey2019_03_26(Id) = cloudfront("GET", "/2019-03-26/public-key/{Id}")
GetPublicKey2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/public-key/{Id}", args)
GetPublicKey2019_03_26(a...; b...) = GetPublicKey2019_03_26(a..., b)

"""
    CreateFieldLevelEncryptionConfig2019_03_26()

Create a new field-level encryption configuration.

Required Parameters
{
  "FieldLevelEncryptionConfig": "The request to create a new field-level encryption configuration."
}
"""
CreateFieldLevelEncryptionConfig2019_03_26(FieldLevelEncryptionConfig) = cloudfront("POST", "/2019-03-26/field-level-encryption")
CreateFieldLevelEncryptionConfig2019_03_26(FieldLevelEncryptionConfig, args) = cloudfront("POST", "/2019-03-26/field-level-encryption", args)
CreateFieldLevelEncryptionConfig2019_03_26(a...; b...) = CreateFieldLevelEncryptionConfig2019_03_26(a..., b)

"""
    ListStreamingDistributions2019_03_26()

List streaming distributions. 

Optional Parameters
{
  "Marker": "The value that you provided for the Marker request parameter.",
  "MaxItems": "The value that you provided for the MaxItems request parameter."
}
"""
ListStreamingDistributions2019_03_26() = cloudfront("GET", "/2019-03-26/streaming-distribution")
ListStreamingDistributions2019_03_26(args) = cloudfront("GET", "/2019-03-26/streaming-distribution", args)
ListStreamingDistributions2019_03_26(a...; b...) = ListStreamingDistributions2019_03_26(a..., b)

"""
    GetStreamingDistributionConfig2019_03_26()

Get the configuration information about a streaming distribution. 

Required Parameters
{
  "Id": "The streaming distribution's ID."
}
"""
GetStreamingDistributionConfig2019_03_26(Id) = cloudfront("GET", "/2019-03-26/streaming-distribution/{Id}/config")
GetStreamingDistributionConfig2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/streaming-distribution/{Id}/config", args)
GetStreamingDistributionConfig2019_03_26(a...; b...) = GetStreamingDistributionConfig2019_03_26(a..., b)

"""
    UpdateFieldLevelEncryptionConfig2019_03_26()

Update a field-level encryption configuration. 

Required Parameters
{
  "Id": "The ID of the configuration you want to update.",
  "FieldLevelEncryptionConfig": "Request to update a field-level encryption configuration. "
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the configuration identity to update. For example: E2QWRUHAPOMQZL."
}
"""
UpdateFieldLevelEncryptionConfig2019_03_26(Id, FieldLevelEncryptionConfig) = cloudfront("PUT", "/2019-03-26/field-level-encryption/{Id}/config")
UpdateFieldLevelEncryptionConfig2019_03_26(Id, FieldLevelEncryptionConfig, args) = cloudfront("PUT", "/2019-03-26/field-level-encryption/{Id}/config", args)
UpdateFieldLevelEncryptionConfig2019_03_26(a...; b...) = UpdateFieldLevelEncryptionConfig2019_03_26(a..., b)

"""
    GetStreamingDistribution2019_03_26()

Gets information about a specified RTMP distribution, including the distribution configuration.

Required Parameters
{
  "Id": "The streaming distribution's ID."
}
"""
GetStreamingDistribution2019_03_26(Id) = cloudfront("GET", "/2019-03-26/streaming-distribution/{Id}")
GetStreamingDistribution2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/streaming-distribution/{Id}", args)
GetStreamingDistribution2019_03_26(a...; b...) = GetStreamingDistribution2019_03_26(a..., b)

"""
    DeleteFieldLevelEncryptionProfile2019_03_26()

Remove a field-level encryption profile.

Required Parameters
{
  "Id": "Request the ID of the profile you want to delete from CloudFront."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the profile to delete. For example: E2QWRUHAPOMQZL."
}
"""
DeleteFieldLevelEncryptionProfile2019_03_26(Id) = cloudfront("DELETE", "/2019-03-26/field-level-encryption-profile/{Id}")
DeleteFieldLevelEncryptionProfile2019_03_26(Id, args) = cloudfront("DELETE", "/2019-03-26/field-level-encryption-profile/{Id}", args)
DeleteFieldLevelEncryptionProfile2019_03_26(a...; b...) = DeleteFieldLevelEncryptionProfile2019_03_26(a..., b)

"""
    GetCloudFrontOriginAccessIdentityConfig2019_03_26()

Get the configuration information about an origin access identity. 

Required Parameters
{
  "Id": "The identity's ID. "
}
"""
GetCloudFrontOriginAccessIdentityConfig2019_03_26(Id) = cloudfront("GET", "/2019-03-26/origin-access-identity/cloudfront/{Id}/config")
GetCloudFrontOriginAccessIdentityConfig2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/origin-access-identity/cloudfront/{Id}/config", args)
GetCloudFrontOriginAccessIdentityConfig2019_03_26(a...; b...) = GetCloudFrontOriginAccessIdentityConfig2019_03_26(a..., b)

"""
    GetFieldLevelEncryptionConfig2019_03_26()

Get the field-level encryption configuration information.

Required Parameters
{
  "Id": "Request the ID for the field-level encryption configuration information."
}
"""
GetFieldLevelEncryptionConfig2019_03_26(Id) = cloudfront("GET", "/2019-03-26/field-level-encryption/{Id}/config")
GetFieldLevelEncryptionConfig2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/field-level-encryption/{Id}/config", args)
GetFieldLevelEncryptionConfig2019_03_26(a...; b...) = GetFieldLevelEncryptionConfig2019_03_26(a..., b)

"""
    UntagResource2019_03_26()

Remove tags from a CloudFront resource.

Required Parameters
{
  "Resource": " An ARN of a CloudFront resource.",
  "TagKeys": " A complex type that contains zero or more Tag key elements."
}
"""
UntagResource2019_03_26(Resource, TagKeys) = cloudfront("POST", "/2019-03-26/tagging?Operation=Untag")
UntagResource2019_03_26(Resource, TagKeys, args) = cloudfront("POST", "/2019-03-26/tagging?Operation=Untag", args)
UntagResource2019_03_26(a...; b...) = UntagResource2019_03_26(a..., b)

"""
    CreateStreamingDistribution2019_03_26()

Creates a new RTMP distribution. An RTMP distribution is similar to a web distribution, but an RTMP distribution streams media files using the Adobe Real-Time Messaging Protocol (RTMP) instead of serving files using HTTP.  To create a new distribution, submit a POST request to the CloudFront API version/distribution resource. The request body must include a document with a StreamingDistributionConfig element. The response echoes the StreamingDistributionConfig element and returns other information about the RTMP distribution. To get the status of your request, use the GET StreamingDistribution API action. When the value of Enabled is true and the value of Status is Deployed, your distribution is ready. A distribution usually deploys in less than 15 minutes. For more information about web distributions, see Working with RTMP Distributions in the Amazon CloudFront Developer Guide.  Beginning with the 2012-05-05 version of the CloudFront API, we made substantial changes to the format of the XML document that you include in the request body when you create or update a web distribution or an RTMP distribution, and when you invalidate objects. With previous versions of the API, we discovered that it was too easy to accidentally delete one or more values for an element that accepts multiple values, for example, CNAMEs and trusted signers. Our changes for the 2012-05-05 release are intended to prevent these accidental deletions and to notify you when there's a mismatch between the number of values you say you're specifying in the Quantity element and the number of values specified. 

Required Parameters
{
  "StreamingDistributionConfig": "The streaming distribution's configuration information."
}
"""
CreateStreamingDistribution2019_03_26(StreamingDistributionConfig) = cloudfront("POST", "/2019-03-26/streaming-distribution")
CreateStreamingDistribution2019_03_26(StreamingDistributionConfig, args) = cloudfront("POST", "/2019-03-26/streaming-distribution", args)
CreateStreamingDistribution2019_03_26(a...; b...) = CreateStreamingDistribution2019_03_26(a..., b)

"""
    DeleteFieldLevelEncryptionConfig2019_03_26()

Remove a field-level encryption configuration.

Required Parameters
{
  "Id": "The ID of the configuration you want to delete from CloudFront."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the configuration identity to delete. For example: E2QWRUHAPOMQZL."
}
"""
DeleteFieldLevelEncryptionConfig2019_03_26(Id) = cloudfront("DELETE", "/2019-03-26/field-level-encryption/{Id}")
DeleteFieldLevelEncryptionConfig2019_03_26(Id, args) = cloudfront("DELETE", "/2019-03-26/field-level-encryption/{Id}", args)
DeleteFieldLevelEncryptionConfig2019_03_26(a...; b...) = DeleteFieldLevelEncryptionConfig2019_03_26(a..., b)

"""
    CreateCloudFrontOriginAccessIdentity2019_03_26()

Creates a new origin access identity. If you're using Amazon S3 for your origin, you can use an origin access identity to require users to access your content using a CloudFront URL instead of the Amazon S3 URL. For more information about how to use origin access identities, see Serving Private Content through CloudFront in the Amazon CloudFront Developer Guide.

Required Parameters
{
  "CloudFrontOriginAccessIdentityConfig": "The current configuration information for the identity."
}
"""
CreateCloudFrontOriginAccessIdentity2019_03_26(CloudFrontOriginAccessIdentityConfig) = cloudfront("POST", "/2019-03-26/origin-access-identity/cloudfront")
CreateCloudFrontOriginAccessIdentity2019_03_26(CloudFrontOriginAccessIdentityConfig, args) = cloudfront("POST", "/2019-03-26/origin-access-identity/cloudfront", args)
CreateCloudFrontOriginAccessIdentity2019_03_26(a...; b...) = CreateCloudFrontOriginAccessIdentity2019_03_26(a..., b)

"""
    GetFieldLevelEncryption2019_03_26()

Get the field-level encryption configuration information.

Required Parameters
{
  "Id": "Request the ID for the field-level encryption configuration information."
}
"""
GetFieldLevelEncryption2019_03_26(Id) = cloudfront("GET", "/2019-03-26/field-level-encryption/{Id}")
GetFieldLevelEncryption2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/field-level-encryption/{Id}", args)
GetFieldLevelEncryption2019_03_26(a...; b...) = GetFieldLevelEncryption2019_03_26(a..., b)

"""
    ListCloudFrontOriginAccessIdentities2019_03_26()

Lists origin access identities.

Optional Parameters
{
  "Marker": "Use this when paginating results to indicate where to begin in your list of origin access identities. The results include identities in the list that occur after the marker. To get the next page of results, set the Marker to the value of the NextMarker from the current page's response (which is also the ID of the last identity on that page).",
  "MaxItems": "The maximum number of origin access identities you want in the response body. "
}
"""
ListCloudFrontOriginAccessIdentities2019_03_26() = cloudfront("GET", "/2019-03-26/origin-access-identity/cloudfront")
ListCloudFrontOriginAccessIdentities2019_03_26(args) = cloudfront("GET", "/2019-03-26/origin-access-identity/cloudfront", args)
ListCloudFrontOriginAccessIdentities2019_03_26(a...; b...) = ListCloudFrontOriginAccessIdentities2019_03_26(a..., b)

"""
    DeleteCloudFrontOriginAccessIdentity2019_03_26()

Delete an origin access identity. 

Required Parameters
{
  "Id": "The origin access identity's ID."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header you received from a previous GET or PUT request. For example: E2QWRUHAPOMQZL."
}
"""
DeleteCloudFrontOriginAccessIdentity2019_03_26(Id) = cloudfront("DELETE", "/2019-03-26/origin-access-identity/cloudfront/{Id}")
DeleteCloudFrontOriginAccessIdentity2019_03_26(Id, args) = cloudfront("DELETE", "/2019-03-26/origin-access-identity/cloudfront/{Id}", args)
DeleteCloudFrontOriginAccessIdentity2019_03_26(a...; b...) = DeleteCloudFrontOriginAccessIdentity2019_03_26(a..., b)

"""
    ListFieldLevelEncryptionConfigs2019_03_26()

List all field-level encryption configurations that have been created in CloudFront for this account.

Optional Parameters
{
  "Marker": "Use this when paginating results to indicate where to begin in your list of configurations. The results include configurations in the list that occur after the marker. To get the next page of results, set the Marker to the value of the NextMarker from the current page's response (which is also the ID of the last configuration on that page). ",
  "MaxItems": "The maximum number of field-level encryption configurations you want in the response body. "
}
"""
ListFieldLevelEncryptionConfigs2019_03_26() = cloudfront("GET", "/2019-03-26/field-level-encryption")
ListFieldLevelEncryptionConfigs2019_03_26(args) = cloudfront("GET", "/2019-03-26/field-level-encryption", args)
ListFieldLevelEncryptionConfigs2019_03_26(a...; b...) = ListFieldLevelEncryptionConfigs2019_03_26(a..., b)

"""
    CreateStreamingDistributionWithTags2019_03_26()

Create a new streaming distribution with tags.

Required Parameters
{
  "StreamingDistributionConfigWithTags": " The streaming distribution's configuration information. "
}
"""
CreateStreamingDistributionWithTags2019_03_26(StreamingDistributionConfigWithTags) = cloudfront("POST", "/2019-03-26/streaming-distribution?WithTags")
CreateStreamingDistributionWithTags2019_03_26(StreamingDistributionConfigWithTags, args) = cloudfront("POST", "/2019-03-26/streaming-distribution?WithTags", args)
CreateStreamingDistributionWithTags2019_03_26(a...; b...) = CreateStreamingDistributionWithTags2019_03_26(a..., b)

"""
    ListTagsForResource2019_03_26()

List tags for a CloudFront resource.

Required Parameters
{
  "Resource": " An ARN of a CloudFront resource."
}
"""
ListTagsForResource2019_03_26(Resource) = cloudfront("GET", "/2019-03-26/tagging")
ListTagsForResource2019_03_26(Resource, args) = cloudfront("GET", "/2019-03-26/tagging", args)
ListTagsForResource2019_03_26(a...; b...) = ListTagsForResource2019_03_26(a..., b)

"""
    ListPublicKeys2019_03_26()

List all public keys that have been added to CloudFront for this account.

Optional Parameters
{
  "Marker": "Use this when paginating results to indicate where to begin in your list of public keys. The results include public keys in the list that occur after the marker. To get the next page of results, set the Marker to the value of the NextMarker from the current page's response (which is also the ID of the last public key on that page). ",
  "MaxItems": "The maximum number of public keys you want in the response body. "
}
"""
ListPublicKeys2019_03_26() = cloudfront("GET", "/2019-03-26/public-key")
ListPublicKeys2019_03_26(args) = cloudfront("GET", "/2019-03-26/public-key", args)
ListPublicKeys2019_03_26(a...; b...) = ListPublicKeys2019_03_26(a..., b)

"""
    GetInvalidation2019_03_26()

Get the information about an invalidation. 

Required Parameters
{
  "Id": "The identifier for the invalidation request, for example, IDFDVBD632BHDS5.",
  "DistributionId": "The distribution's ID."
}
"""
GetInvalidation2019_03_26(Id, DistributionId) = cloudfront("GET", "/2019-03-26/distribution/{DistributionId}/invalidation/{Id}")
GetInvalidation2019_03_26(Id, DistributionId, args) = cloudfront("GET", "/2019-03-26/distribution/{DistributionId}/invalidation/{Id}", args)
GetInvalidation2019_03_26(a...; b...) = GetInvalidation2019_03_26(a..., b)

"""
    ListInvalidations2019_03_26()

Lists invalidation batches. 

Required Parameters
{
  "DistributionId": "The distribution's ID."
}

Optional Parameters
{
  "Marker": "Use this parameter when paginating results to indicate where to begin in your list of invalidation batches. Because the results are returned in decreasing order from most recent to oldest, the most recent results are on the first page, the second page will contain earlier results, and so on. To get the next page of results, set Marker to the value of the NextMarker from the current page's response. This value is the same as the ID of the last invalidation batch on that page. ",
  "MaxItems": "The maximum number of invalidation batches that you want in the response body."
}
"""
ListInvalidations2019_03_26(DistributionId) = cloudfront("GET", "/2019-03-26/distribution/{DistributionId}/invalidation")
ListInvalidations2019_03_26(DistributionId, args) = cloudfront("GET", "/2019-03-26/distribution/{DistributionId}/invalidation", args)
ListInvalidations2019_03_26(a...; b...) = ListInvalidations2019_03_26(a..., b)

"""
    CreatePublicKey2019_03_26()

Add a new public key to CloudFront to use, for example, for field-level encryption. You can add a maximum of 10 public keys with one AWS account.

Required Parameters
{
  "PublicKeyConfig": "The request to add a public key to CloudFront."
}
"""
CreatePublicKey2019_03_26(PublicKeyConfig) = cloudfront("POST", "/2019-03-26/public-key")
CreatePublicKey2019_03_26(PublicKeyConfig, args) = cloudfront("POST", "/2019-03-26/public-key", args)
CreatePublicKey2019_03_26(a...; b...) = CreatePublicKey2019_03_26(a..., b)

"""
    DeleteDistribution2019_03_26()

Delete a distribution. 

Required Parameters
{
  "Id": "The distribution ID. "
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when you disabled the distribution. For example: E2QWRUHAPOMQZL. "
}
"""
DeleteDistribution2019_03_26(Id) = cloudfront("DELETE", "/2019-03-26/distribution/{Id}")
DeleteDistribution2019_03_26(Id, args) = cloudfront("DELETE", "/2019-03-26/distribution/{Id}", args)
DeleteDistribution2019_03_26(a...; b...) = DeleteDistribution2019_03_26(a..., b)

"""
    ListDistributionsByWebACLId2019_03_26()

List the distributions that are associated with a specified AWS WAF web ACL. 

Required Parameters
{
  "WebACLId": "The ID of the AWS WAF web ACL that you want to list the associated distributions. If you specify \"null\" for the ID, the request returns a list of the distributions that aren't associated with a web ACL. "
}

Optional Parameters
{
  "Marker": "Use Marker and MaxItems to control pagination of results. If you have more than MaxItems distributions that satisfy the request, the response includes a NextMarker element. To get the next page of results, submit another request. For the value of Marker, specify the value of NextMarker from the last response. (For the first request, omit Marker.) ",
  "MaxItems": "The maximum number of distributions that you want CloudFront to return in the response body. The maximum and default values are both 100."
}
"""
ListDistributionsByWebACLId2019_03_26(WebACLId) = cloudfront("GET", "/2019-03-26/distributionsByWebACLId/{WebACLId}")
ListDistributionsByWebACLId2019_03_26(WebACLId, args) = cloudfront("GET", "/2019-03-26/distributionsByWebACLId/{WebACLId}", args)
ListDistributionsByWebACLId2019_03_26(a...; b...) = ListDistributionsByWebACLId2019_03_26(a..., b)

"""
    UpdateStreamingDistribution2019_03_26()

Update a streaming distribution. 

Required Parameters
{
  "Id": "The streaming distribution's id.",
  "StreamingDistributionConfig": "The streaming distribution's configuration information."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the streaming distribution's configuration. For example: E2QWRUHAPOMQZL."
}
"""
UpdateStreamingDistribution2019_03_26(Id, StreamingDistributionConfig) = cloudfront("PUT", "/2019-03-26/streaming-distribution/{Id}/config")
UpdateStreamingDistribution2019_03_26(Id, StreamingDistributionConfig, args) = cloudfront("PUT", "/2019-03-26/streaming-distribution/{Id}/config", args)
UpdateStreamingDistribution2019_03_26(a...; b...) = UpdateStreamingDistribution2019_03_26(a..., b)

"""
    DeletePublicKey2019_03_26()

Remove a public key you previously added to CloudFront.

Required Parameters
{
  "Id": "The ID of the public key you want to remove from CloudFront."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the public key identity to delete. For example: E2QWRUHAPOMQZL."
}
"""
DeletePublicKey2019_03_26(Id) = cloudfront("DELETE", "/2019-03-26/public-key/{Id}")
DeletePublicKey2019_03_26(Id, args) = cloudfront("DELETE", "/2019-03-26/public-key/{Id}", args)
DeletePublicKey2019_03_26(a...; b...) = DeletePublicKey2019_03_26(a..., b)

"""
    CreateInvalidation2019_03_26()

Create a new invalidation. 

Required Parameters
{
  "DistributionId": "The distribution's id.",
  "InvalidationBatch": "The batch information for the invalidation."
}
"""
CreateInvalidation2019_03_26(DistributionId, InvalidationBatch) = cloudfront("POST", "/2019-03-26/distribution/{DistributionId}/invalidation")
CreateInvalidation2019_03_26(DistributionId, InvalidationBatch, args) = cloudfront("POST", "/2019-03-26/distribution/{DistributionId}/invalidation", args)
CreateInvalidation2019_03_26(a...; b...) = CreateInvalidation2019_03_26(a..., b)

"""
    UpdateFieldLevelEncryptionProfile2019_03_26()

Update a field-level encryption profile. 

Required Parameters
{
  "Id": "The ID of the field-level encryption profile request. ",
  "FieldLevelEncryptionProfileConfig": "Request to update a field-level encryption profile. "
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the profile identity to update. For example: E2QWRUHAPOMQZL."
}
"""
UpdateFieldLevelEncryptionProfile2019_03_26(Id, FieldLevelEncryptionProfileConfig) = cloudfront("PUT", "/2019-03-26/field-level-encryption-profile/{Id}/config")
UpdateFieldLevelEncryptionProfile2019_03_26(Id, FieldLevelEncryptionProfileConfig, args) = cloudfront("PUT", "/2019-03-26/field-level-encryption-profile/{Id}/config", args)
UpdateFieldLevelEncryptionProfile2019_03_26(a...; b...) = UpdateFieldLevelEncryptionProfile2019_03_26(a..., b)

"""
    GetFieldLevelEncryptionProfile2019_03_26()

Get the field-level encryption profile information.

Required Parameters
{
  "Id": "Get the ID for the field-level encryption profile information."
}
"""
GetFieldLevelEncryptionProfile2019_03_26(Id) = cloudfront("GET", "/2019-03-26/field-level-encryption-profile/{Id}")
GetFieldLevelEncryptionProfile2019_03_26(Id, args) = cloudfront("GET", "/2019-03-26/field-level-encryption-profile/{Id}", args)
GetFieldLevelEncryptionProfile2019_03_26(a...; b...) = GetFieldLevelEncryptionProfile2019_03_26(a..., b)

"""
    ListFieldLevelEncryptionProfiles2019_03_26()

Request a list of field-level encryption profiles that have been created in CloudFront for this account.

Optional Parameters
{
  "Marker": "Use this when paginating results to indicate where to begin in your list of profiles. The results include profiles in the list that occur after the marker. To get the next page of results, set the Marker to the value of the NextMarker from the current page's response (which is also the ID of the last profile on that page). ",
  "MaxItems": "The maximum number of field-level encryption profiles you want in the response body. "
}
"""
ListFieldLevelEncryptionProfiles2019_03_26() = cloudfront("GET", "/2019-03-26/field-level-encryption-profile")
ListFieldLevelEncryptionProfiles2019_03_26(args) = cloudfront("GET", "/2019-03-26/field-level-encryption-profile", args)
ListFieldLevelEncryptionProfiles2019_03_26(a...; b...) = ListFieldLevelEncryptionProfiles2019_03_26(a..., b)

"""
    UpdatePublicKey2019_03_26()

Update public key information. Note that the only value you can change is the comment.

Required Parameters
{
  "Id": "ID of the public key to be updated.",
  "PublicKeyConfig": "Request to update public key information."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the public key to update. For example: E2QWRUHAPOMQZL."
}
"""
UpdatePublicKey2019_03_26(Id, PublicKeyConfig) = cloudfront("PUT", "/2019-03-26/public-key/{Id}/config")
UpdatePublicKey2019_03_26(Id, PublicKeyConfig, args) = cloudfront("PUT", "/2019-03-26/public-key/{Id}/config", args)
UpdatePublicKey2019_03_26(a...; b...) = UpdatePublicKey2019_03_26(a..., b)

"""
    UpdateDistribution2019_03_26()

Updates the configuration for a web distribution.   When you update a distribution, there are more required fields than when you create a distribution. When you update your distribution by using this API action, follow the steps here to get the current configuration and then make your updates, to make sure that you include all of the required fields. To view a summary, see Required Fields for Create Distribution and Update Distribution in the Amazon CloudFront Developer Guide.  The update process includes getting the current distribution configuration, updating the XML document that is returned to make your changes, and then submitting an UpdateDistribution request to make the updates. For information about updating a distribution using the CloudFront console instead, see Creating a Distribution in the Amazon CloudFront Developer Guide.  To update a web distribution using the CloudFront API    Submit a GetDistributionConfig request to get the current configuration and an Etag header for the distribution.  If you update the distribution again, you must get a new Etag header.    Update the XML document that was returned in the response to your GetDistributionConfig request to include your changes.   When you edit the XML file, be aware of the following:   You must strip out the ETag parameter that is returned.   Additional fields are required when you update a distribution. There may be fields included in the XML file for features that you haven't configured for your distribution. This is expected and required to successfully update the distribution.   You can't change the value of CallerReference. If you try to change this value, CloudFront returns an IllegalUpdate error.    The new configuration replaces the existing configuration; the values that you specify in an UpdateDistribution request are not merged into your existing configuration. When you add, delete, or replace values in an element that allows multiple values (for example, CNAME), you must specify all of the values that you want to appear in the updated distribution. In addition, you must update the corresponding Quantity element.      Submit an UpdateDistribution request to update the configuration for your distribution:   In the request body, include the XML document that you updated in Step 2. The request body must include an XML document with a DistributionConfig element.   Set the value of the HTTP If-Match header to the value of the ETag header that CloudFront returned when you submitted the GetDistributionConfig request in Step 1.     Review the response to the UpdateDistribution request to confirm that the configuration was successfully updated.   Optional: Submit a GetDistribution request to confirm that your changes have propagated. When propagation is complete, the value of Status is Deployed.  

Required Parameters
{
  "DistributionConfig": "The distribution's configuration information.",
  "Id": "The distribution's id."
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when retrieving the distribution's configuration. For example: E2QWRUHAPOMQZL."
}
"""
UpdateDistribution2019_03_26(DistributionConfig, Id) = cloudfront("PUT", "/2019-03-26/distribution/{Id}/config")
UpdateDistribution2019_03_26(DistributionConfig, Id, args) = cloudfront("PUT", "/2019-03-26/distribution/{Id}/config", args)
UpdateDistribution2019_03_26(a...; b...) = UpdateDistribution2019_03_26(a..., b)

"""
    DeleteStreamingDistribution2019_03_26()

Delete a streaming distribution. To delete an RTMP distribution using the CloudFront API, perform the following steps.  To delete an RTMP distribution using the CloudFront API:   Disable the RTMP distribution.   Submit a GET Streaming Distribution Config request to get the current configuration and the Etag header for the distribution.    Update the XML document that was returned in the response to your GET Streaming Distribution Config request to change the value of Enabled to false.   Submit a PUT Streaming Distribution Config request to update the configuration for your distribution. In the request body, include the XML document that you updated in Step 3. Then set the value of the HTTP If-Match header to the value of the ETag header that CloudFront returned when you submitted the GET Streaming Distribution Config request in Step 2.   Review the response to the PUT Streaming Distribution Config request to confirm that the distribution was successfully disabled.   Submit a GET Streaming Distribution Config request to confirm that your changes have propagated. When propagation is complete, the value of Status is Deployed.   Submit a DELETE Streaming Distribution request. Set the value of the HTTP If-Match header to the value of the ETag header that CloudFront returned when you submitted the GET Streaming Distribution Config request in Step 2.   Review the response to your DELETE Streaming Distribution request to confirm that the distribution was successfully deleted.   For information about deleting a distribution using the CloudFront console, see Deleting a Distribution in the Amazon CloudFront Developer Guide.

Required Parameters
{
  "Id": "The distribution ID. "
}

Optional Parameters
{
  "IfMatch": "The value of the ETag header that you received when you disabled the streaming distribution. For example: E2QWRUHAPOMQZL."
}
"""
DeleteStreamingDistribution2019_03_26(Id) = cloudfront("DELETE", "/2019-03-26/streaming-distribution/{Id}")
DeleteStreamingDistribution2019_03_26(Id, args) = cloudfront("DELETE", "/2019-03-26/streaming-distribution/{Id}", args)
DeleteStreamingDistribution2019_03_26(a...; b...) = DeleteStreamingDistribution2019_03_26(a..., b)

"""
    CreateFieldLevelEncryptionProfile2019_03_26()

Create a field-level encryption profile.

Required Parameters
{
  "FieldLevelEncryptionProfileConfig": "The request to create a field-level encryption profile."
}
"""
CreateFieldLevelEncryptionProfile2019_03_26(FieldLevelEncryptionProfileConfig) = cloudfront("POST", "/2019-03-26/field-level-encryption-profile")
CreateFieldLevelEncryptionProfile2019_03_26(FieldLevelEncryptionProfileConfig, args) = cloudfront("POST", "/2019-03-26/field-level-encryption-profile", args)
CreateFieldLevelEncryptionProfile2019_03_26(a...; b...) = CreateFieldLevelEncryptionProfile2019_03_26(a..., b)