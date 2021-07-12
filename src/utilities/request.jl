abstract type AbstractBackend end
struct HTTPBackend <: AbstractBackend end
struct DownloadsBackend <: AbstractBackend end

default_backend() = DEFAULT_BACKEND[]

Base.@kwdef mutable struct Request
    service::String
    api_version::String
    request_method::String

    headers::AbstractDict{String, String}=LittleDict{String, String}()
    content::Union{String, Vector{UInt8}}=""
    resource::String=""
    url::String=""

    return_stream::Bool=false
    response_stream::Union{<:IO, Nothing}=nothing
    http_options::AbstractDict{Symbol,<:Any}=LittleDict{Symbol,String}()
    return_raw::Bool=false
    response_dict_type::Type{<:AbstractDict}=LittleDict
    downloader::Union{Nothing, Downloads.Downloader}=nothing
    backend::AbstractBackend=default_backend()
end

submit_request(aws::AbstractAWSConfig, request::Request; return_headers::Bool=false) = submit_request(request.backend, aws, request; return_headers)

const AWS_DOWNLOADER = Ref{Union{Nothing, Downloader}}(nothing)
const AWS_DOWNLOAD_LOCK = ReentrantLock()
const DEFAULT_BACKEND = Ref{AbstractBackend}(DownloadsBackend())

# https://github.com/JuliaLang/Downloads.jl/blob/84e948c02b8a0625552a764bf90f7d2ee97c949c/src/Downloads.jl#L293-L301
function get_downloader(downloader=nothing)
    lock(AWS_DOWNLOAD_LOCK) do
        yield() # let other downloads finish
        downloader isa Downloader && return
        while true
            downloader = AWS_DOWNLOADER[]
            downloader isa Downloader && return
            AWS_DOWNLOADER[] = Downloader()
        end
    end
    return downloader
end

function _http_request(::DownloadsBackend, request)
    # If we pass `output`, Downloads.jl will expect a message
    # body in the response. Specifically, it sets
    # <https://curl.se/libcurl/c/CURLOPT_NOBODY.html>
    # only when we do not pass the `output` argument.
    #
    # When the method is `HEAD`, the response may have a Content-Length
    # but not send any content back (which appears to be correct,
    # <https://stackoverflow.com/a/18925736/12486544>).
    # 
    # Thus, if we did not set `CURLOPT_NOBODY`, and it gets a Content-Length
    # back, it will hang waiting for that body.
    # 
    # Therefore, we do not pass an `output` when the `request_method` is `HEAD`.
    if request.request_method != "HEAD"
        output = IOBuffer()
        output_arg = (; output=output)

        # We set a callback so later on we know how to get the `body` back.
        body_arg = () -> (; body = take!(output))
    else
        output_arg = NamedTuple()
        body_arg = () -> NamedTuple()
    end

    # We pass an `input` only when we have content we wish to send.
    if !isempty(request.content)
        input = IOBuffer()
        write(input, request.content)
        input_arg = (; input=input)
    else
        input_arg = NamedTuple()
    end

    downloader = @something(request.downloader, get_downloader())
    # set the hook so that we don't follow redirects
    downloader.easy_hook = (easy, info) -> Curl.setopt(easy, Curl.CURLOPT_FOLLOWLOCATION, false)


    response = Downloads.request(request.url; input_arg..., output_arg...,
                                 method = request.request_method,
                                 request.headers, verbose=false, throw=true,
                                 downloader)
    http_response = HTTP.Response(response.status, response.headers; body_arg()..., request=nothing) 

    if HTTP.iserror(http_response)
        target = HTTP.resource(HTTP.URI(request.url))
        throw(HTTP.StatusError(http_response.status, request.request_method, target, http_response))
    end

    return http_response
end


"""
    submit_request(aws::AbstractAWSConfig, request::Request; return_headers::Bool=false)

Submit the request to AWS.

# Arguments
- `aws::AbstractAWSConfig`: AWSConfig containing credentials and other information for fulfilling the request, default value is the global configuration
- `request::Request`: All the information about making a request to AWS

# Keywords
- `return_headers::Bool=false`: True if you want the headers from the response returned back

# Returns
- `Tuple or Dict`: Tuple if returning_headers, otherwise just return a Dict of the response body
"""
function submit_request(backend::AbstractBackend, aws::AbstractAWSConfig, request::Request; return_headers::Bool=false)
    response = nothing
    TOO_MANY_REQUESTS = 429
    EXPIRED_ERROR_CODES = ["ExpiredToken", "ExpiredTokenException", "RequestExpired"]
    REDIRECT_ERROR_CODES = [301, 302, 303, 304, 305, 307, 308]
    THROTTLING_ERROR_CODES = [
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestThrottledException",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "LimitExceededException",
        "RequestThrottled",
        "PriorRequestNotComplete"
    ]

    request.headers["User-Agent"] = user_agent[]
    request.headers["Host"] = HTTP.URI(request.url).host

    @repeat 3 try
        credentials(aws) === nothing || sign!(aws, request)

        response = @mock _http_request(backend, request)

        if response.status in REDIRECT_ERROR_CODES
            if HTTP.header(response, "Location") != ""
                request.url = HTTP.header(response, "Location")
            else
                e = HTTP.StatusError(response.status, response)
                throw(AWSException(e))
            end
        end
    catch e
        if e isa HTTP.StatusError
            e = AWSException(e)
        end

        @retry if :message in fieldnames(typeof(e)) && occursin("Signature expired", e.message) end

        # Handle ExpiredToken...
        # https://github.com/aws/aws-sdk-go/blob/v1.31.5/aws/request/retryer.go#L98
        @retry if ecode(e) in EXPIRED_ERROR_CODES
            check_credentials(credentials(aws), force_refresh=true)
        end

        # Throttle handling
        # https://github.com/boto/botocore/blob/1.16.17/botocore/data/_retry.json
        # https://docs.aws.amazon.com/general/latest/gr/api-retries.html
        @delay_retry if e isa AWSException &&
            (_http_status(e.cause) == TOO_MANY_REQUESTS || ecode(e) in THROTTLING_ERROR_CODES)
        end

        # Handle BadDigest error and CRC32 check sum failure
        @retry if e isa AWSException && (
            _header(e.cause, "crc32body") == "x-amz-crc32" ||
            ecode(e) in ("BadDigest", "RequestTimeout", "RequestTimeoutException")
        )
        end

        if e isa AWSException && occursin("Missing Authentication Token", e.message) && aws.credentials === nothing
            return throw(NoCredentials("You're attempting to perform a request without credentials set."))
        end
    end

    response_dict_type = request.response_dict_type

    # For HEAD request, return headers...
    if request.request_method == "HEAD"
        return response_dict_type(response.headers)
    end

    # Return response stream if requested...
    if request.return_stream
        return request.response_stream
    end

    # Return raw data if requested...
    if request.return_raw
        return (return_headers ? (response.body, response.headers) : response.body)
    end

    # Parse response data according to mimetype...
    mime = HTTP.header(response, "Content-Type", "")

    if isempty(mime)
        if length(response.body) > 5 && response.body[1:5] == b"<?xml"
            mime = "text/xml"
        end
    end

    body = String(copy(response.body))

    if occursin(r"/xml", mime)
        xml_dict_type = response_dict_type{Union{Symbol, String}, Any}
        body = parse_xml(body)
        root = XMLDict.root(body.x)

        return (return_headers ? (xml_dict(root, xml_dict_type), response_dict_type(response.headers)) : xml_dict(root, xml_dict_type))
    elseif occursin(r"/x-amz-json-1.[01]$", mime) || endswith(mime, "json")
        info = isempty(response.body) ? nothing : JSON.parse(body, dicttype=response_dict_type)
        return (return_headers ? (info, response_dict_type(response.headers)) : info)
    elseif startswith(mime, "text/")
        return (return_headers ? (body, response_dict_type(response.headers)) : body)
    else
        return (return_headers ? (response.body, response.headers) : response.body)
    end
end


function _http_request(::HTTPBackend, request::Request)
    @repeat 4 try
        http_stack = HTTP.stack(redirect=false, retry=false, aws_authorization=false)

        if request.return_stream && request.response_stream === nothing
            request.response_stream = Base.BufferStream()
        end

        return HTTP.request(
            http_stack,
            request.request_method,
            HTTP.URI(request.url),
            HTTP.mkheaders(request.headers),
            request.content;
            require_ssl_verification=false,
            response_stream=request.response_stream,
            request.http_options...
        )
    catch e
        # Base.IOError is needed because HTTP.jl can often have errors that aren't
        # caught and wrapped in an HTTP.IOError
        # https://github.com/JuliaWeb/HTTP.jl/issues/382
        @delay_retry if isa(e, Sockets.DNSError) ||
                        isa(e, HTTP.ParseError) ||
                        isa(e, HTTP.IOError) ||
                        isa(e, Base.IOError) ||
                        (isa(e, HTTP.StatusError) && _http_status(e) >= 500)
        end
    end
end


_http_status(e::HTTP.StatusError) = e.status
_header(e::HTTP.StatusError, k, d="") = HTTP.header(e.response, k, d)
