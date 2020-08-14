# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: ecr

using Compat
using UUIDs
"""
    BatchCheckLayerAvailability()

Checks the availability of one or more image layers in a repository. When an image is pushed to a repository, each image layer is checked to verify if it has been uploaded before. If it has been uploaded, then the image layer is skipped.  This operation is used by the Amazon ECR proxy and is not generally used by customers for pulling and pushing images. In most cases, you should use the docker CLI to pull, tag, and push images. 

# Required Parameters
- `layerDigests`: The digests of the image layers to check.
- `repositoryName`: The name of the repository that is associated with the image layers to check.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the image layers to check. If you do not specify a registry, the default registry is assumed.
"""
BatchCheckLayerAvailability(layerDigests, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("BatchCheckLayerAvailability", Dict{String, Any}("layerDigests"=>layerDigests, "repositoryName"=>repositoryName); aws=aws)
BatchCheckLayerAvailability(layerDigests, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("BatchCheckLayerAvailability", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("layerDigests"=>layerDigests, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    BatchDeleteImage()

Deletes a list of specified images within a repository. Images are specified with either an imageTag or imageDigest. You can remove a tag from an image by specifying the image's tag in your request. When you remove the last tag from an image, the image is deleted from your repository. You can completely delete an image (and all of its tags) by specifying the image's digest in your request.

# Required Parameters
- `imageIds`: A list of image ID references that correspond to images to delete. The format of the imageIds reference is imageTag=tag or imageDigest=digest.
- `repositoryName`: The repository that contains the image to delete.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the image to delete. If you do not specify a registry, the default registry is assumed.
"""
BatchDeleteImage(imageIds, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("BatchDeleteImage", Dict{String, Any}("imageIds"=>imageIds, "repositoryName"=>repositoryName); aws=aws)
BatchDeleteImage(imageIds, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("BatchDeleteImage", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("imageIds"=>imageIds, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    BatchGetImage()

Gets detailed information for an image. Images are specified with either an imageTag or imageDigest. When an image is pulled, the BatchGetImage API is called once to retrieve the image manifest.

# Required Parameters
- `imageIds`: A list of image ID references that correspond to images to describe. The format of the imageIds reference is imageTag=tag or imageDigest=digest.
- `repositoryName`: The repository that contains the images to describe.

# Optional Parameters
- `acceptedMediaTypes`: The accepted media types for the request. Valid values: application/vnd.docker.distribution.manifest.v1+json | application/vnd.docker.distribution.manifest.v2+json | application/vnd.oci.image.manifest.v1+json 
- `registryId`: The AWS account ID associated with the registry that contains the images to describe. If you do not specify a registry, the default registry is assumed.
"""
BatchGetImage(imageIds, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("BatchGetImage", Dict{String, Any}("imageIds"=>imageIds, "repositoryName"=>repositoryName); aws=aws)
BatchGetImage(imageIds, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("BatchGetImage", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("imageIds"=>imageIds, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    CompleteLayerUpload()

Informs Amazon ECR that the image layer upload has completed for a specified registry, repository name, and upload ID. You can optionally provide a sha256 digest of the image layer for data validation purposes. When an image is pushed, the CompleteLayerUpload API is called once per each new image layer to verify that the upload has completed.  This operation is used by the Amazon ECR proxy and is not generally used by customers for pulling and pushing images. In most cases, you should use the docker CLI to pull, tag, and push images. 

# Required Parameters
- `layerDigests`: The sha256 digest of the image layer.
- `repositoryName`: The name of the repository to associate with the image layer.
- `uploadId`: The upload ID from a previous InitiateLayerUpload operation to associate with the image layer.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry to which to upload layers. If you do not specify a registry, the default registry is assumed.
"""
CompleteLayerUpload(layerDigests, repositoryName, uploadId; aws::AWSConfig=AWS.aws_config) = ecr("CompleteLayerUpload", Dict{String, Any}("layerDigests"=>layerDigests, "repositoryName"=>repositoryName, "uploadId"=>uploadId); aws=aws)
CompleteLayerUpload(layerDigests, repositoryName, uploadId, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("CompleteLayerUpload", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("layerDigests"=>layerDigests, "repositoryName"=>repositoryName, "uploadId"=>uploadId), args)); aws=aws)

"""
    CreateRepository()

Creates a repository. For more information, see Amazon ECR Repositories in the Amazon Elastic Container Registry User Guide.

# Required Parameters
- `repositoryName`: The name to use for the repository. The repository name may be specified on its own (such as nginx-web-app) or it can be prepended with a namespace to group the repository into a category (such as project-a/nginx-web-app).

# Optional Parameters
- `encryptionConfiguration`: The encryption configuration for the repository. This determines how the contents of your repository are encrypted at rest.
- `imageScanningConfiguration`: The image scanning configuration for the repository. This determines whether images are scanned for known vulnerabilities after being pushed to the repository.
- `imageTagMutability`: The tag mutability setting for the repository. If this parameter is omitted, the default setting of MUTABLE will be used which will allow image tags to be overwritten. If IMMUTABLE is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.
- `tags`: The metadata that you apply to the repository to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.
"""
CreateRepository(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("CreateRepository", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
CreateRepository(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("CreateRepository", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    DeleteLifecyclePolicy()

Deletes the lifecycle policy associated with the specified repository.

# Required Parameters
- `repositoryName`: The name of the repository.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository. If you do not specify a registry, the default registry is assumed.
"""
DeleteLifecyclePolicy(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("DeleteLifecyclePolicy", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
DeleteLifecyclePolicy(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("DeleteLifecyclePolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    DeleteRepository()

Deletes a repository. If the repository contains images, you must either delete all images in the repository or use the force option to delete the repository.

# Required Parameters
- `repositoryName`: The name of the repository to delete.

# Optional Parameters
- `force`:  If a repository contains images, forces the deletion.
- `registryId`: The AWS account ID associated with the registry that contains the repository to delete. If you do not specify a registry, the default registry is assumed.
"""
DeleteRepository(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("DeleteRepository", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
DeleteRepository(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("DeleteRepository", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    DeleteRepositoryPolicy()

Deletes the repository policy associated with the specified repository.

# Required Parameters
- `repositoryName`: The name of the repository that is associated with the repository policy to delete.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository policy to delete. If you do not specify a registry, the default registry is assumed.
"""
DeleteRepositoryPolicy(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("DeleteRepositoryPolicy", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
DeleteRepositoryPolicy(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("DeleteRepositoryPolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    DescribeImageScanFindings()

Returns the scan findings for the specified image.

# Required Parameters
- `imageId`: 
- `repositoryName`: The repository for the image for which to describe the scan findings.

# Optional Parameters
- `maxResults`: The maximum number of image scan results returned by DescribeImageScanFindings in paginated output. When this parameter is used, DescribeImageScanFindings only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another DescribeImageScanFindings request with the returned nextToken value. This value can be between 1 and 1000. If this parameter is not used, then DescribeImageScanFindings returns up to 100 results and a nextToken value, if applicable.
- `nextToken`: The nextToken value returned from a previous paginated DescribeImageScanFindings request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. This value is null when there are no more results to return.
- `registryId`: The AWS account ID associated with the registry that contains the repository in which to describe the image scan findings for. If you do not specify a registry, the default registry is assumed.
"""
DescribeImageScanFindings(imageId, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("DescribeImageScanFindings", Dict{String, Any}("imageId"=>imageId, "repositoryName"=>repositoryName); aws=aws)
DescribeImageScanFindings(imageId, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("DescribeImageScanFindings", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("imageId"=>imageId, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    DescribeImages()

Returns metadata about the images in a repository.  Beginning with Docker version 1.9, the Docker client compresses image layers before pushing them to a V2 Docker registry. The output of the docker images command shows the uncompressed image size, so it may return a larger image size than the image sizes returned by DescribeImages. 

# Required Parameters
- `repositoryName`: The repository that contains the images to describe.

# Optional Parameters
- `filter`: The filter key and value with which to filter your DescribeImages results.
- `imageIds`: The list of image IDs for the requested repository.
- `maxResults`: The maximum number of repository results returned by DescribeImages in paginated output. When this parameter is used, DescribeImages only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another DescribeImages request with the returned nextToken value. This value can be between 1 and 1000. If this parameter is not used, then DescribeImages returns up to 100 results and a nextToken value, if applicable. This option cannot be used when you specify images with imageIds.
- `nextToken`: The nextToken value returned from a previous paginated DescribeImages request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. This value is null when there are no more results to return. This option cannot be used when you specify images with imageIds.
- `registryId`: The AWS account ID associated with the registry that contains the repository in which to describe images. If you do not specify a registry, the default registry is assumed.
"""
DescribeImages(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("DescribeImages", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
DescribeImages(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("DescribeImages", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    DescribeRepositories()

Describes image repositories in a registry.

# Optional Parameters
- `maxResults`: The maximum number of repository results returned by DescribeRepositories in paginated output. When this parameter is used, DescribeRepositories only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another DescribeRepositories request with the returned nextToken value. This value can be between 1 and 1000. If this parameter is not used, then DescribeRepositories returns up to 100 results and a nextToken value, if applicable. This option cannot be used when you specify repositories with repositoryNames.
- `nextToken`: The nextToken value returned from a previous paginated DescribeRepositories request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. This value is null when there are no more results to return. This option cannot be used when you specify repositories with repositoryNames.  This token should be treated as an opaque identifier that is only used to retrieve the next items in a list and not for other programmatic purposes. 
- `registryId`: The AWS account ID associated with the registry that contains the repositories to be described. If you do not specify a registry, the default registry is assumed.
- `repositoryNames`: A list of repositories to describe. If this parameter is omitted, then all repositories in a registry are described.
"""
DescribeRepositories(; aws::AWSConfig=AWS.aws_config) = ecr("DescribeRepositories"; aws=aws)
DescribeRepositories(args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("DescribeRepositories", args; aws=aws)

"""
    GetAuthorizationToken()

Retrieves an authorization token. An authorization token represents your IAM authentication credentials and can be used to access any Amazon ECR registry that your IAM principal has access to. The authorization token is valid for 12 hours. The authorizationToken returned is a base64 encoded string that can be decoded and used in a docker login command to authenticate to a registry. The AWS CLI offers an get-login-password command that simplifies the login process. For more information, see Registry Authentication in the Amazon Elastic Container Registry User Guide.

# Optional Parameters
- `registryIds`: A list of AWS account IDs that are associated with the registries for which to get AuthorizationData objects. If you do not specify a registry, the default registry is assumed.
"""
GetAuthorizationToken(; aws::AWSConfig=AWS.aws_config) = ecr("GetAuthorizationToken"; aws=aws)
GetAuthorizationToken(args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("GetAuthorizationToken", args; aws=aws)

"""
    GetDownloadUrlForLayer()

Retrieves the pre-signed Amazon S3 download URL corresponding to an image layer. You can only get URLs for image layers that are referenced in an image. When an image is pulled, the GetDownloadUrlForLayer API is called once per image layer that is not already cached.  This operation is used by the Amazon ECR proxy and is not generally used by customers for pulling and pushing images. In most cases, you should use the docker CLI to pull, tag, and push images. 

# Required Parameters
- `layerDigest`: The digest of the image layer to download.
- `repositoryName`: The name of the repository that is associated with the image layer to download.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the image layer to download. If you do not specify a registry, the default registry is assumed.
"""
GetDownloadUrlForLayer(layerDigest, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("GetDownloadUrlForLayer", Dict{String, Any}("layerDigest"=>layerDigest, "repositoryName"=>repositoryName); aws=aws)
GetDownloadUrlForLayer(layerDigest, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("GetDownloadUrlForLayer", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("layerDigest"=>layerDigest, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    GetLifecyclePolicy()

Retrieves the lifecycle policy for the specified repository.

# Required Parameters
- `repositoryName`: The name of the repository.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository. If you do not specify a registry, the default registry is assumed.
"""
GetLifecyclePolicy(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("GetLifecyclePolicy", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
GetLifecyclePolicy(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("GetLifecyclePolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    GetLifecyclePolicyPreview()

Retrieves the results of the lifecycle policy preview request for the specified repository.

# Required Parameters
- `repositoryName`: The name of the repository.

# Optional Parameters
- `filter`: An optional parameter that filters results based on image tag status and all tags, if tagged.
- `imageIds`: The list of imageIDs to be included.
- `maxResults`: The maximum number of repository results returned by GetLifecyclePolicyPreviewRequest in&#x2028; paginated output. When this parameter is used, GetLifecyclePolicyPreviewRequest only returns&#x2028; maxResults results in a single page along with a nextToken&#x2028; response element. The remaining results of the initial request can be seen by sending&#x2028; another GetLifecyclePolicyPreviewRequest request with the returned nextToken&#x2028; value. This value can be between 1 and 1000. If this&#x2028; parameter is not used, then GetLifecyclePolicyPreviewRequest returns up to&#x2028; 100 results and a nextToken value, if&#x2028; applicable. This option cannot be used when you specify images with imageIds.
- `nextToken`: The nextToken value returned from a previous paginated&#x2028; GetLifecyclePolicyPreviewRequest request where maxResults was used and the&#x2028; results exceeded the value of that parameter. Pagination continues from the end of the&#x2028; previous results that returned the nextToken value. This value is&#x2028; null when there are no more results to return. This option cannot be used when you specify images with imageIds.
- `registryId`: The AWS account ID associated with the registry that contains the repository. If you do not specify a registry, the default registry is assumed.
"""
GetLifecyclePolicyPreview(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("GetLifecyclePolicyPreview", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
GetLifecyclePolicyPreview(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("GetLifecyclePolicyPreview", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    GetRepositoryPolicy()

Retrieves the repository policy for the specified repository.

# Required Parameters
- `repositoryName`: The name of the repository with the policy to retrieve.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository. If you do not specify a registry, the default registry is assumed.
"""
GetRepositoryPolicy(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("GetRepositoryPolicy", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
GetRepositoryPolicy(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("GetRepositoryPolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    InitiateLayerUpload()

Notifies Amazon ECR that you intend to upload an image layer. When an image is pushed, the InitiateLayerUpload API is called once per image layer that has not already been uploaded. Whether or not an image layer has been uploaded is determined by the BatchCheckLayerAvailability API action.  This operation is used by the Amazon ECR proxy and is not generally used by customers for pulling and pushing images. In most cases, you should use the docker CLI to pull, tag, and push images. 

# Required Parameters
- `repositoryName`: The name of the repository to which you intend to upload layers.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry to which you intend to upload layers. If you do not specify a registry, the default registry is assumed.
"""
InitiateLayerUpload(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("InitiateLayerUpload", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
InitiateLayerUpload(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("InitiateLayerUpload", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    ListImages()

Lists all the image IDs for the specified repository. You can filter images based on whether or not they are tagged by using the tagStatus filter and specifying either TAGGED, UNTAGGED or ANY. For example, you can filter your results to return only UNTAGGED images and then pipe that result to a BatchDeleteImage operation to delete them. Or, you can filter your results to return only TAGGED images to list all of the tags in your repository.

# Required Parameters
- `repositoryName`: The repository with image IDs to be listed.

# Optional Parameters
- `filter`: The filter key and value with which to filter your ListImages results.
- `maxResults`: The maximum number of image results returned by ListImages in paginated output. When this parameter is used, ListImages only returns maxResults results in a single page along with a nextToken response element. The remaining results of the initial request can be seen by sending another ListImages request with the returned nextToken value. This value can be between 1 and 1000. If this parameter is not used, then ListImages returns up to 100 results and a nextToken value, if applicable.
- `nextToken`: The nextToken value returned from a previous paginated ListImages request where maxResults was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the nextToken value. This value is null when there are no more results to return.  This token should be treated as an opaque identifier that is only used to retrieve the next items in a list and not for other programmatic purposes. 
- `registryId`: The AWS account ID associated with the registry that contains the repository in which to list images. If you do not specify a registry, the default registry is assumed.
"""
ListImages(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("ListImages", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
ListImages(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("ListImages", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    ListTagsForResource()

List the tags for an Amazon ECR resource.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) that identifies the resource for which to list the tags. Currently, the only supported resource is an Amazon ECR repository.

"""
ListTagsForResource(resourceArn; aws::AWSConfig=AWS.aws_config) = ecr("ListTagsForResource", Dict{String, Any}("resourceArn"=>resourceArn); aws=aws)
ListTagsForResource(resourceArn, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("ListTagsForResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("resourceArn"=>resourceArn), args)); aws=aws)

"""
    PutImage()

Creates or updates the image manifest and tags associated with an image. When an image is pushed and all new image layers have been uploaded, the PutImage API is called once to create or update the image manifest and the tags associated with the image.  This operation is used by the Amazon ECR proxy and is not generally used by customers for pulling and pushing images. In most cases, you should use the docker CLI to pull, tag, and push images. 

# Required Parameters
- `imageManifest`: The image manifest corresponding to the image to be uploaded.
- `repositoryName`: The name of the repository in which to put the image.

# Optional Parameters
- `imageDigest`: The image digest of the image manifest corresponding to the image.
- `imageManifestMediaType`: The media type of the image manifest. If you push an image manifest that does not contain the mediaType field, you must specify the imageManifestMediaType in the request.
- `imageTag`: The tag to associate with the image. This parameter is required for images that use the Docker Image Manifest V2 Schema 2 or Open Container Initiative (OCI) formats.
- `registryId`: The AWS account ID associated with the registry that contains the repository in which to put the image. If you do not specify a registry, the default registry is assumed.
"""
PutImage(imageManifest, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("PutImage", Dict{String, Any}("imageManifest"=>imageManifest, "repositoryName"=>repositoryName); aws=aws)
PutImage(imageManifest, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("PutImage", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("imageManifest"=>imageManifest, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    PutImageScanningConfiguration()

Updates the image scanning configuration for the specified repository.

# Required Parameters
- `imageScanningConfiguration`: The image scanning configuration for the repository. This setting determines whether images are scanned for known vulnerabilities after being pushed to the repository.
- `repositoryName`: The name of the repository in which to update the image scanning configuration setting.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository in which to update the image scanning configuration setting. If you do not specify a registry, the default registry is assumed.
"""
PutImageScanningConfiguration(imageScanningConfiguration, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("PutImageScanningConfiguration", Dict{String, Any}("imageScanningConfiguration"=>imageScanningConfiguration, "repositoryName"=>repositoryName); aws=aws)
PutImageScanningConfiguration(imageScanningConfiguration, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("PutImageScanningConfiguration", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("imageScanningConfiguration"=>imageScanningConfiguration, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    PutImageTagMutability()

Updates the image tag mutability settings for the specified repository. For more information, see Image Tag Mutability in the Amazon Elastic Container Registry User Guide.

# Required Parameters
- `imageTagMutability`: The tag mutability setting for the repository. If MUTABLE is specified, image tags can be overwritten. If IMMUTABLE is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.
- `repositoryName`: The name of the repository in which to update the image tag mutability settings.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository in which to update the image tag mutability settings. If you do not specify a registry, the default registry is assumed.
"""
PutImageTagMutability(imageTagMutability, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("PutImageTagMutability", Dict{String, Any}("imageTagMutability"=>imageTagMutability, "repositoryName"=>repositoryName); aws=aws)
PutImageTagMutability(imageTagMutability, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("PutImageTagMutability", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("imageTagMutability"=>imageTagMutability, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    PutLifecyclePolicy()

Creates or updates the lifecycle policy for the specified repository. For more information, see Lifecycle Policy Template.

# Required Parameters
- `lifecyclePolicyText`: The JSON repository policy text to apply to the repository.
- `repositoryName`: The name of the repository to receive the policy.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository. If you do&#x2028; not specify a registry, the default registry is assumed.
"""
PutLifecyclePolicy(lifecyclePolicyText, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("PutLifecyclePolicy", Dict{String, Any}("lifecyclePolicyText"=>lifecyclePolicyText, "repositoryName"=>repositoryName); aws=aws)
PutLifecyclePolicy(lifecyclePolicyText, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("PutLifecyclePolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("lifecyclePolicyText"=>lifecyclePolicyText, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    SetRepositoryPolicy()

Applies a repository policy to the specified repository to control access permissions. For more information, see Amazon ECR Repository Policies in the Amazon Elastic Container Registry User Guide.

# Required Parameters
- `policyText`: The JSON repository policy text to apply to the repository. For more information, see Amazon ECR Repository Policies in the Amazon Elastic Container Registry User Guide.
- `repositoryName`: The name of the repository to receive the policy.

# Optional Parameters
- `force`: If the policy you are attempting to set on a repository policy would prevent you from setting another policy in the future, you must force the SetRepositoryPolicy operation. This is intended to prevent accidental repository lock outs.
- `registryId`: The AWS account ID associated with the registry that contains the repository. If you do not specify a registry, the default registry is assumed.
"""
SetRepositoryPolicy(policyText, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("SetRepositoryPolicy", Dict{String, Any}("policyText"=>policyText, "repositoryName"=>repositoryName); aws=aws)
SetRepositoryPolicy(policyText, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("SetRepositoryPolicy", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("policyText"=>policyText, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    StartImageScan()

Starts an image vulnerability scan. An image scan can only be started once per day on an individual image. This limit includes if an image was scanned on initial push. For more information, see Image Scanning in the Amazon Elastic Container Registry User Guide.

# Required Parameters
- `imageId`: 
- `repositoryName`: The name of the repository that contains the images to scan.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry that contains the repository in which to start an image scan request. If you do not specify a registry, the default registry is assumed.
"""
StartImageScan(imageId, repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("StartImageScan", Dict{String, Any}("imageId"=>imageId, "repositoryName"=>repositoryName); aws=aws)
StartImageScan(imageId, repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("StartImageScan", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("imageId"=>imageId, "repositoryName"=>repositoryName), args)); aws=aws)

"""
    StartLifecyclePolicyPreview()

Starts a preview of a lifecycle policy for the specified repository. This allows you to see the results before associating the lifecycle policy with the repository.

# Required Parameters
- `repositoryName`: The name of the repository to be evaluated.

# Optional Parameters
- `lifecyclePolicyText`: The policy to be evaluated against. If you do not specify a policy, the current policy for the repository is used.
- `registryId`: The AWS account ID associated with the registry that contains the repository. If you do not specify a registry, the default registry is assumed.
"""
StartLifecyclePolicyPreview(repositoryName; aws::AWSConfig=AWS.aws_config) = ecr("StartLifecyclePolicyPreview", Dict{String, Any}("repositoryName"=>repositoryName); aws=aws)
StartLifecyclePolicyPreview(repositoryName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("StartLifecyclePolicyPreview", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("repositoryName"=>repositoryName), args)); aws=aws)

"""
    TagResource()

Adds specified tags to a resource with the specified ARN. Existing tags on a resource are not changed if they are not specified in the request parameters.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the the resource to which to add tags. Currently, the only supported resource is an Amazon ECR repository.
- `tags`: The tags to add to the resource. A tag is an array of key-value pairs. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

"""
TagResource(resourceArn, tags; aws::AWSConfig=AWS.aws_config) = ecr("TagResource", Dict{String, Any}("resourceArn"=>resourceArn, "tags"=>tags); aws=aws)
TagResource(resourceArn, tags, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("TagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("resourceArn"=>resourceArn, "tags"=>tags), args)); aws=aws)

"""
    UntagResource()

Deletes specified tags from a resource.

# Required Parameters
- `resourceArn`: The Amazon Resource Name (ARN) of the resource from which to remove tags. Currently, the only supported resource is an Amazon ECR repository.
- `tagKeys`: The keys of the tags to be removed.

"""
UntagResource(resourceArn, tagKeys; aws::AWSConfig=AWS.aws_config) = ecr("UntagResource", Dict{String, Any}("resourceArn"=>resourceArn, "tagKeys"=>tagKeys); aws=aws)
UntagResource(resourceArn, tagKeys, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("UntagResource", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("resourceArn"=>resourceArn, "tagKeys"=>tagKeys), args)); aws=aws)

"""
    UploadLayerPart()

Uploads an image layer part to Amazon ECR. When an image is pushed, each new image layer is uploaded in parts. The maximum size of each image layer part can be 20971520 bytes (or about 20MB). The UploadLayerPart API is called once per each new image layer part.  This operation is used by the Amazon ECR proxy and is not generally used by customers for pulling and pushing images. In most cases, you should use the docker CLI to pull, tag, and push images. 

# Required Parameters
- `layerPartBlob`: The base64-encoded layer part payload.
- `partFirstByte`: The position of the first byte of the layer part witin the overall image layer.
- `partLastByte`: The position of the last byte of the layer part within the overall image layer.
- `repositoryName`: The name of the repository to which you are uploading layer parts.
- `uploadId`: The upload ID from a previous InitiateLayerUpload operation to associate with the layer part upload.

# Optional Parameters
- `registryId`: The AWS account ID associated with the registry to which you are uploading layer parts. If you do not specify a registry, the default registry is assumed.
"""
UploadLayerPart(layerPartBlob, partFirstByte, partLastByte, repositoryName, uploadId; aws::AWSConfig=AWS.aws_config) = ecr("UploadLayerPart", Dict{String, Any}("layerPartBlob"=>layerPartBlob, "partFirstByte"=>partFirstByte, "partLastByte"=>partLastByte, "repositoryName"=>repositoryName, "uploadId"=>uploadId); aws=aws)
UploadLayerPart(layerPartBlob, partFirstByte, partLastByte, repositoryName, uploadId, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = ecr("UploadLayerPart", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("layerPartBlob"=>layerPartBlob, "partFirstByte"=>partFirstByte, "partLastByte"=>partLastByte, "repositoryName"=>repositoryName, "uploadId"=>uploadId), args)); aws=aws)
