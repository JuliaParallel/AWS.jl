# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: sagemaker_runtime

using Compat
using UUIDs
"""
    InvokeEndpoint()

After you deploy a model into production using Amazon SageMaker hosting services, your client applications use this API to get inferences from the model hosted at the specified endpoint.  For an overview of Amazon SageMaker, see How It Works.  Amazon SageMaker strips all POST headers except those supported by the API. Amazon SageMaker might add additional headers. You should not rely on the behavior of headers outside those enumerated in the request syntax.  Calls to InvokeEndpoint are authenticated by using AWS Signature Version 4. For information, see Authenticating Requests (AWS Signature Version 4) in the Amazon S3 API Reference. A customer's model containers must respond to requests within 60 seconds. The model itself can have a maximum processing time of 60 seconds before responding to the /invocations. If your model is going to take 50-60 seconds of processing time, the SDK socket timeout should be set to be 70 seconds.  Endpoints are scoped to an individual account, and are not public. The URL does not contain the account ID, but Amazon SageMaker determines the account ID from the authentication token that is supplied by the caller. 

# Required Parameters
- `Body`: Provides input data, in the format specified in the ContentType request header. Amazon SageMaker passes all of the data in the body to the model.  For information about the format of the request body, see Common Data Formats-Inference.
- `EndpointName`: The name of the endpoint that you specified when you created the endpoint using the CreateEndpoint API. 

# Optional Parameters
- `Accept`: The desired MIME type of the inference in the response.
- `Content-Type`: The MIME type of the input data in the request body.
- `X-Amzn-SageMaker-Custom-Attributes`: Provides additional information about a request for an inference submitted to a model hosted at an Amazon SageMaker endpoint. The information is an opaque value that is forwarded verbatim. You could use this value, for example, to provide an ID that you can use to track a request or to provide other metadata that a service endpoint was programmed to process. The value must consist of no more than 1024 visible US-ASCII characters as specified in Section 3.3.6. Field Value Components of the Hypertext Transfer Protocol (HTTP/1.1). This feature is currently supported in the AWS SDKs but not in the Amazon SageMaker Python SDK.
- `X-Amzn-SageMaker-Target-Model`: The model to request for inference when invoking a multi-model endpoint. 
- `X-Amzn-SageMaker-Target-Variant`: Specify the production variant to send the inference request to when invoking an endpoint that is running two or more variants. Note that this parameter overrides the default behavior for the endpoint, which is to distribute the invocation traffic based on the variant weights.
"""
InvokeEndpoint(Body, EndpointName; aws::AWSConfig=AWS.aws_config) = sagemaker_runtime("POST", "/endpoints/$(EndpointName)/invocations", Dict{String, Any}("Body"=>Body); aws=aws)
InvokeEndpoint(Body, EndpointName, args::AbstractDict{String, <:Any}; aws::AWSConfig=AWS.aws_config) = sagemaker_runtime("POST", "/endpoints/$(EndpointName)/invocations", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Body"=>Body), args)); aws=aws)
