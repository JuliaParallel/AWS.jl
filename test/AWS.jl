@testset "service module" begin
    @service S3
    @test :S3 in names(Main)
end

@testset "User Agent" begin
    new_user_agent = "new user agent"

    @test AWS.user_agent == "AWS.jl/1.0.0"
    set_user_agent(new_user_agent)
    @test AWS.user_agent == new_user_agent
end

@testset "sign" begin
    aws = AWS.AWSConfig()

    access_key = "access-key"
    secret_key = "ssh... it is a secret"

    aws.credentials.access_key_id = access_key
    aws.credentials.secret_key = secret_key

    time = DateTime(2020)
    date = Dates.format(time, "yyyymmdd")

    request = Request(
        service="s3",
        api_version="api_verison",
        request_method="GET",
        headers=LittleDict(
            "Host" => "s3.us-east-1.amazonaws.com",
            "User-Agent" => "AWS.jl/1.0.0"
        ),
        resource="/test-resource",
        url="https://s3.us-east-1.amazonaws.com/test-resource"
    )

    @testset "sign v2" begin
        result = AWS._sign_aws2!(aws, request, time)
        content = result.content
        content_type = result.headers["Content-Type"]

        expected_access_key = "AWSAccessKeyId=$access_key"
        expected_expires = "Expires=2020-01-01T00%3A02%3A00Z"
        expected_signature_method = "SignatureMethod=HmacSHA256"
        expected_signature_version = "SignatureVersion=2"
        expected_signature = "Signature=O0MLzMKpEcfVZeHy0tyxVAuZF%2BvrvbgIGgqbWtJLTQ0%3D"

        expected_content = join([
            expected_access_key,
            expected_expires,
            expected_signature_method,
            expected_signature_version,
            expected_signature
        ], '&')

        @test expected_content == content
    end

    @testset "sign v4" begin
        expected_x_amz_content_sha256 = bytes2hex(digest(MD_SHA256, request.content))
        expected_content_md5 = base64encode(digest(MD_MD5, request.content))
        expected_x_amz_date = Dates.format(time, dateformat"yyyymmdd\THHMMSS\Z")

        result = AWS._sign_aws4!(aws, request, time)
        headers = result.headers

        @test headers["x-amz-content-sha256"] == expected_x_amz_content_sha256
        @test headers["Content-MD5"] == expected_content_md5
        @test headers["x-amz-date"] == expected_x_amz_date

        authorization_header = split(headers["Authorization"], ' ')
        @test authorization_header[1] == "AWS4-HMAC-SHA256"
        @test authorization_header[2] == "Credential=$access_key/$date/us-east-1/$(request.service)/aws4_request,"
        @test authorization_header[3] == "SignedHeaders=content-md5;content-type;host;user-agent;x-amz-content-sha256;x-amz-date,"
        @test authorization_header[4] == "Signature=0f292eaf0b66cf353bafcb1b9b6d90ee27064236a60f17f6fc5bd7d40173a0be"
    end
end

@testset "do_request" begin
    aws = AWS.AWSConfig()

    @testset "HEAD request method" begin
        expected_result_type = LittleDict

        request = Request(
            service="s3",
            api_version="api_verison",
            request_method="HEAD",
            url="https://s3.us-east-1.amazonaws.com/sample-bucket"
        )

        apply(Patches._http_request_patch) do
            Patches._response!()
            result = AWS.do_request(aws, request)

            @test result == expected_result_type(Patches.headers)
            @test typeof(result) <: expected_result_type
        end
    end

    @testset "return stream" begin
        request = Request(
            service="s3",
            api_version="api_verison",
            request_method="GET",
            return_stream=true,
            response_stream=Base.BufferStream(),
            url="https://s3.us-east-1.amazonaws.com/sample-bucket"
        )

        apply(Patches._http_request_patch) do
            Patches._response!()
            result = AWS.do_request(aws, request)

            @test result == request.response_stream
        end
    end

    @testset "return raw" begin
        request = Request(
            service="s3",
            api_version="api_verison",
            request_method="GET",
            url="https://s3.us-east-1.amazonaws.com/sample-bucket",
            return_raw=true
        )

        @testset "body" begin
            apply(Patches._http_request_patch) do
                Patches._response!()
                result = AWS.do_request(aws, request)

                @test String(result) == Patches.body
            end
        end

        @testset "body and headers" begin
            apply(Patches._http_request_patch) do
                Patches._response!()
                body, headers = AWS.do_request(aws, request; return_headers=true)

                @test String(body) == Patches.body
                @test headers == Patches.headers
            end
        end
    end

    @testset "MIME" begin
        request = Request(
            service="s3",
            api_version="api_verison",
            request_method="GET",
            url="https://s3.us-east-1.amazonaws.com/sample-bucket"
        )

        @testset "empty" begin
            apply(Patches._http_request_patch) do
                @testset "default" begin
                    expected_body = ""
                    expected_headers = Pair["Content-Type"=>"",]

                    Patches._response!(headers=expected_headers, body=expected_body)

                    @testset "body" begin
                       result = AWS.do_request(aws, request)

                       @test String(result) == expected_body
                    end

                    @testset "body and headers" begin
                        body, headers = AWS.do_request(aws, request; return_headers=true)

                        @test String(body) == expected_body
                        @test headers == expected_headers
                    end
                end

                @testset "text/xml" begin
                    expected_headers = Pair["Content-Type"=>"",]
                    expected_body_type = LittleDict{Union{Symbol, String}, Any}
                    expected_body = xml_dict((Patches.body), expected_body_type)

                    expected_header_type = LittleDict{SubString{String}, SubString{String}}

                    Patches._response!(headers=expected_headers)

                    @testset "body" begin
                        result = AWS.do_request(aws, request)

                        @test typeof(result) <: expected_body_type
                        @test result == expected_body
                    end

                    @testset "body and headers" begin
                        body, headers = AWS.do_request(aws, request; return_headers=true)

                        @test body == expected_body
                        @test typeof(body) <: expected_body_type

                        @test headers == LittleDict(expected_headers)
                        @test typeof(headers) <: expected_header_type
                    end
                end
            end
        end

        @testset "xml" begin
            request = Request(
                service="s3",
                api_version="api_verison",
                request_method="GET",
                url="https://s3.us-east-1.amazonaws.com/sample-bucket",
            )

            expected_body_type = LittleDict{Union{Symbol, String}, Any}
            expected_body = xml_dict((Patches.body), expected_body_type)
            expected_headers = Pair["Content-Type"=>"application/xml",]

            apply(Patches._http_request_patch) do
                Patches._response!(headers=expected_headers,)

                @testset "body" begin
                    result = AWS.do_request(aws, request)

                    @test result == expected_body
                    @test typeof(result) <: expected_body_type
                end

                @testset "body and headers" begin
                    body, headers = AWS.do_request(aws, request; return_headers=true)

                    @test body == expected_body
                    @test typeof(body) <: expected_body_type

                    @test headers == LittleDict(expected_headers)
                    @test typeof(headers) <: LittleDict{SubString{String}, SubString{String}}
               end
            end
        end

        @testset "JSON" begin
            json_headers = ["Content-Type"=>"application/json"]
            json_body = """{"Marker":null,"VaultList":[{"CreationDate":"2020-06-22T03:14:41.754Z","LastInventoryDate":null,"NumberOfArchives":0,"SizeInBytes":0,"VaultARN":"arn:aws:glacier:us-east-1:000:vaults/test","VaultName":"test"}]}"""

            expected_body_type = LittleDict{String, Any}
            expected_body = JSON.parse(json_body, dicttype=LittleDict)

            apply(Patches._http_request_patch) do
                Patches._response!(body=json_body, headers=json_headers,)

                @testset "body" begin
                    result = AWS.do_request(aws, request)

                    @test typeof(result) <: expected_body_type
                    @test result == expected_body
                end

                @testset "body and headers" begin
                    body, headers = AWS.do_request(aws, request; return_headers=true)

                    @test body == expected_body
                    @test typeof(body) <: expected_body_type

                    @test headers == LittleDict(json_headers)
                    @test typeof(headers) <: LittleDict{SubString{String}, SubString{String}}
                end
            end
        end
    end
end

@testset "_generate_rest_resource" begin
    request_uri = "/{Bucket}/{Key+}"
    args = Dict{String, Any}(
        "Bucket"=>"aws.jl-test",
        "Key"=>"Test-Key"
    )

    expected = "/$(args["Bucket"])/$(args["Key"])"
    result = AWS._generate_rest_resource(request_uri, args)
    @test expected == result
end

@testset "_generate_service_url" begin
    region = "us-east-2"
    resource = "/aws.jl-test---timestamp"

    request = Request(
        service="service",
        api_version="api_version",
        request_method="GET",
        resource=resource,
    )

    @testset "regionless endpoints" for regionless_endpoint in ("iam", "route53")
        endpoint = "sdb"
        request.service = regionless_endpoint
        expected_result = "https://$regionless_endpoint.amazonaws.com$resource"
        result = AWS._generate_service_url(region, request.service, request.resource)

        @test result == expected_result
    end

    @testset "region service" begin
        endpoint = "sdb"
        request.service = endpoint
        expected_result = "https://$endpoint.$region.amazonaws.com$resource"
        result = AWS._generate_service_url(region, request.service, request.resource)

        @test result == expected_result
    end


    @testset "sdb -- us-east-1 region exception" begin
        endpoint = "sdb"
        request.service = endpoint
        expected_result = "https://$endpoint.amazonaws.com$resource"
        region = "us-east-1"
        result = AWS._generate_service_url(region, request.service, request.resource)

        @test result == expected_result
    end
end

@testset "_return_headers" begin
    @testset "key exists" begin
        expected = true
        dict = Dict{String, Any}("return_headers"=>true)
        result = AWS._return_headers(dict)

        @test result == expected
        @test isempty(dict)
    end

    @testset "key dne" begin
        expected = false
        result = AWS._return_headers(Dict{String, Any}())

        @test result == expected
    end
end

@testset "_flatten_query" begin
    high_level_value = "high_level_value"
    entry_1 = LittleDict("low_level_key_1"=>"low_level_value_1", "low_level_key_2"=>"low_level_value_2")
    entry_2 = LittleDict("low_level_key_3"=>"low_level_value_3", "low_level_key_4"=>"low_level_value_4")

    args = LittleDict("high_level_key"=>high_level_value, "high_level_array"=>[entry_1, entry_2])

    @testset "non-special case suffix" begin
        service = "sts"
        result = AWS._flatten_query(service, args)

        expected = Pair{String,String}[
            "high_level_key" => "high_level_value",
            "high_level_array.member.1.low_level_key_1" => "low_level_value_1",
            "high_level_array.member.1.low_level_key_2" => "low_level_value_2",
            "high_level_array.member.2.low_level_key_3" => "low_level_value_3",
            "high_level_array.member.2.low_level_key_4" => "low_level_value_4"
        ]

        @test result == expected
    end

    @testset "sqs - special casing suffix" begin
        service = "sqs"
        result = AWS._flatten_query(service, args)

        expected = Pair{String,String}[
            "high_level_key" => "high_level_value",
            "high_level_array.1.low_level_key_1" => "low_level_value_1",
            "high_level_array.1.low_level_key_2" => "low_level_value_2",
            "high_level_array.2.low_level_key_3" => "low_level_value_3",
            "high_level_array.2.low_level_key_4" => "low_level_value_4"
        ]

        @test result == expected
    end
end

@testset "json" begin
    @testset "secrets_manager" begin
        secret_name = "AWS.jl-Test-Secret" * lowercase(Dates.format(now(Dates.UTC), "yyyymmddTHHMMSSZ"))
        secret_string = "sshhh it is a secret!"

        function _get_secret_string(secret_name)
            response = AWSServices.secrets_manager("GetSecretValue", LittleDict("SecretId"=>secret_name))

            return response["SecretString"]
        end

        resp = AWSServices.secrets_manager("CreateSecret", LittleDict(
                "Name"=>secret_name,
                "SecretString"=>secret_string,
                "ClientRequestToken"=>string(uuid4())
            )
        )

        try
            @test _get_secret_string(secret_name) == secret_string
        finally
            AWSServices.secrets_manager("DeleteSecret", LittleDict(
                    "SecretId"=>secret_name,
                    "ForceDeleteWithoutRecovery"=>"true",
                )
            )

            @test_throws AWSException _get_secret_string(secret_name)
        end
    end
end

@testset "query" begin
    @testset "iam" begin
        policy_arn = ""
        expected_policy_name = "AWS.jl-Test-Policy" * lowercase(Dates.format(now(Dates.UTC), "yyyymmddTHHMMSSZ"))
        expected_policy_document = LittleDict(
            "Version"=> "2012-10-17",
            "Statement"=> [
                LittleDict(
                    "Effect"=>"Allow",
                    "Action"=>["s3:Get*", "s3:List*"],
                    "Resource"=> ["arn:aws:s3:::my-bucket/shared/*"]
                )
            ],
        )
        expected_policy_document = JSON.json(expected_policy_document)

        # Create Policy
        response = AWSServices.iam("CreatePolicy", LittleDict("PolicyName"=>expected_policy_name, "PolicyDocument"=>expected_policy_document))
        policy_arn = response["CreatePolicyResponse"]["CreatePolicyResult"]["Policy"]["Arn"]

        # Get Policy
        try
            response_policy_version = AWSServices.iam("GetPolicyVersion", LittleDict("PolicyArn"=>policy_arn, "VersionId"=>"v1"))
            response_document = response_policy_version["GetPolicyVersionResponse"]["GetPolicyVersionResult"]["PolicyVersion"]["Document"]
            @test HTTP.unescapeuri(response_document) == expected_policy_document
        finally
            # Delete Policy
            AWSServices.iam("DeletePolicy", LittleDict("PolicyArn"=>policy_arn))
            @test_throws AWSException AWSServices.iam("GetPolicy", LittleDict("PolicyArn"=>policy_arn))
        end
    end

    @testset "sqs" begin
        queue_name = "aws-jl-test---" * lowercase(Dates.format(now(Dates.UTC), "yyyymmddTHHMMSSZ"))
        expected_message = "Hello for AWS.jl"

        function _get_queue_url(queue_name)
            result = AWSServices.sqs("GetQueueUrl", LittleDict("QueueName"=>queue_name))

            return result["GetQueueUrlResponse"]["GetQueueUrlResult"]["QueueUrl"]
        end

        # Create Queue
        AWSServices.sqs("CreateQueue", LittleDict("QueueName"=>queue_name))

        # Get Queues
        queue_url = _get_queue_url(queue_name)
        @test !isempty(queue_url)

        # Change Message Visibility Batch Request
        expected_message_id = "aws-jl-test"

        AWSServices.sqs("SendMessage", LittleDict(
                "QueueUrl"=>queue_url,
                "MessageBody"=>expected_message
            )
        )

        response = AWSServices.sqs("ReceiveMessage", LittleDict("QueueUrl"=>queue_url,))
        receipt_handle = response["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]["ReceiptHandle"]

        response = AWSServices.sqs("DeleteMessageBatch", LittleDict(
                "QueueUrl"=>queue_url,
                "DeleteMessageBatchRequestEntry"=>[
                    LittleDict(
                        "Id"=>expected_message_id,
                        "ReceiptHandle"=>receipt_handle,
                    )
                ]
            )
        )

        message_id = response["DeleteMessageBatchResponse"]["DeleteMessageBatchResult"]["DeleteMessageBatchResultEntry"]["Id"]
        @test message_id == expected_message_id

        # Send message
        AWSServices.sqs("SendMessage", LittleDict(
                "QueueUrl"=>queue_url,
                "MessageBody"=>expected_message
            )
        )

        # Receive Message
        result = AWSServices.sqs("ReceiveMessage", LittleDict("QueueUrl"=>queue_url))
        message = result["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]["Body"]
        @test message == expected_message

        # Delete Queue
        AWSServices.sqs("DeleteQueue", LittleDict("QueueUrl"=>queue_url))
        @test_throws AWSException _get_queue_url(queue_name)
    end
end

@testset "rest-xml" begin
    bucket_name = "aws.jl-test---" * lowercase(Dates.format(now(Dates.UTC), "yyyymmddTHHMMSSZ"))
    file_name = string(uuid4())

    function _bucket_exists(bucket_name)
        try
            AWSServices.s3("HEAD", "/$bucket_name")
            return true
        catch e
            if e isa AWSException && e.cause.status == 404
                return false
            else
                rethrow(e)
            end
        end
    end

    @testset "HEAD" begin
        @test _bucket_exists(bucket_name) == false
    end

    @testset "PUT" begin
        AWSServices.s3("PUT", "/$bucket_name")

        @test _bucket_exists(bucket_name)
    end

    @testset "PUT - w/ Params" begin
        body = "sample-file-body"
        AWSServices.s3("PUT", "/$bucket_name/$file_name", Dict("body" => body))

        @test !isempty(AWSServices.s3("GET", "/$bucket_name/$file_name"))
    end

    @testset "GET" begin
        result = AWSServices.s3("GET", "/$bucket_name")
        @test result["ListBucketResult"]["Contents"]["Key"] == file_name
    end

    @testset "GET - w/ Params" begin
        max_keys = 1
        result = AWSServices.s3("GET", "/$bucket_name", Dict("max_keys" => max_keys))

        @test length([result["ListBucketResult"]["Contents"]]) == max_keys
    end

    @testset "POST - w/ Params" begin
        body = """
            <Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Object>
                    <Key>$file_name</Key>
                </Object>
            </Delete>
            """

        AWSServices.s3("POST", "/$bucket_name?delete", Dict("body" => body))

        try
            AWSServices.s3("GET", "/$bucket_name/$file_name")
            @test false
        catch e
            if e isa AWSException && e.code == "NoSuchKey"
                @test true
            else
                rethrow(e)
            end
        end
    end

    @testset "DELETE" begin
        AWSServices.s3("DELETE", "/$bucket_name")

        sleep(2)
        @test _bucket_exists(bucket_name) == false
    end
end

@testset "rest-json" begin
    timestamp = lowercase(Dates.format(now(Dates.UTC), "yyyymmddTHHMMSSZ"))
    vault_names = ["aws.jl.test-01---$timestamp", "aws.jl.test-02---$timestamp", ]

    @testset "PUT" begin
        for vault in vault_names
            AWSServices.glacier("PUT", "/-/vaults/$vault")
        end
    end

    @testset "POST" begin
        tags = Dict("Tags"=> LittleDict("Tag-01" => "Tag-01", "Tag-02" => "Tag-02"))

        for vault in vault_names
            AWSServices.glacier("POST", "/-/vaults/$vault/tags?operation=add", tags)
        end

        for vault in vault_names
            result_tags = AWSServices.glacier("GET", "/-/vaults/$vault/tags")

            @test result_tags == tags
        end
    end

    @testset "GET - w/ args" begin
        # If this is an Integer AWS Coral cannot convert it to a String
        # "class com.amazon.coral.value.json.numbers.TruncatingBigNumber can not be converted to an String"
        limit = "1"
        params = LittleDict("limit" => limit)
        result = AWSServices.glacier("GET", "/-/vaults/", params)

        @test length(result["VaultList"]) == parse(Int, limit)
    end

    @testset "DELETE" begin
        for vault in vault_names
            AWSServices.glacier("DELETE", "/-/vaults/$vault")
        end

        result = AWSServices.glacier("GET", "/-/vaults")
        res_vault_names = [v["VaultName"] for v in result["VaultList"]]

        for vault in vault_names
            @test !(vault in res_vault_names)
        end
    end
end
