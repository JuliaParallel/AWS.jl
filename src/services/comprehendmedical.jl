# This file is auto-generated by AWSMetadata.jl
include("../AWSServices.jl")
using Compat
using .AWSServices: comprehendmedical

"""
    DescribeEntitiesDetectionV2Job()

Gets the properties associated with a medical entities detection job. Use this operation to get the status of a detection job.

Required Parameters
JobId => The identifier that Amazon Comprehend Medical generated for the job. The StartEntitiesDetectionV2Job operation returns this identifier in its response.

"""
DescribeEntitiesDetectionV2Job(JobId) = comprehendmedical("DescribeEntitiesDetectionV2Job", Dict{String, Any}("JobId"=>JobId))
DescribeEntitiesDetectionV2Job(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("DescribeEntitiesDetectionV2Job", Dict{String, Any}("JobId"=>JobId, args...))

"""
    DescribeICD10CMInferenceJob()

Gets the properties associated with an InferICD10CM job. Use this operation to get the status of an inference job.

Required Parameters
JobId => The identifier that Amazon Comprehend Medical generated for the job. The StartICD10CMInferenceJob operation returns this identifier in its response.

"""
DescribeICD10CMInferenceJob(JobId) = comprehendmedical("DescribeICD10CMInferenceJob", Dict{String, Any}("JobId"=>JobId))
DescribeICD10CMInferenceJob(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("DescribeICD10CMInferenceJob", Dict{String, Any}("JobId"=>JobId, args...))

"""
    DescribePHIDetectionJob()

Gets the properties associated with a protected health information (PHI) detection job. Use this operation to get the status of a detection job.

Required Parameters
JobId => The identifier that Amazon Comprehend Medical generated for the job. The StartPHIDetectionJob operation returns this identifier in its response.

"""
DescribePHIDetectionJob(JobId) = comprehendmedical("DescribePHIDetectionJob", Dict{String, Any}("JobId"=>JobId))
DescribePHIDetectionJob(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("DescribePHIDetectionJob", Dict{String, Any}("JobId"=>JobId, args...))

"""
    DescribeRxNormInferenceJob()

Gets the properties associated with an InferRxNorm job. Use this operation to get the status of an inference job.

Required Parameters
JobId => The identifier that Amazon Comprehend Medical generated for the job. The StartRxNormInferenceJob operation returns this identifier in its response.

"""
DescribeRxNormInferenceJob(JobId) = comprehendmedical("DescribeRxNormInferenceJob", Dict{String, Any}("JobId"=>JobId))
DescribeRxNormInferenceJob(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("DescribeRxNormInferenceJob", Dict{String, Any}("JobId"=>JobId, args...))

"""
    DetectEntities()

The DetectEntities operation is deprecated. You should use the DetectEntitiesV2 operation instead.  Inspects the clinical text for a variety of medical entities and returns specific information about them such as entity category, location, and confidence score on that information .

Required Parameters
Text =>  A UTF-8 text string containing the clinical content being examined for entities. Each string must contain fewer than 20,000 bytes of characters.

"""
DetectEntities(Text) = comprehendmedical("DetectEntities", Dict{String, Any}("Text"=>Text))
DetectEntities(Text, args::AbstractDict{String, <: Any}) = comprehendmedical("DetectEntities", Dict{String, Any}("Text"=>Text, args...))

"""
    DetectEntitiesV2()

Inspects the clinical text for a variety of medical entities and returns specific information about them such as entity category, location, and confidence score on that information. Amazon Comprehend Medical only detects medical entities in English language texts. The DetectEntitiesV2 operation replaces the DetectEntities operation. This new action uses a different model for determining the entities in your medical text and changes the way that some entities are returned in the output. You should use the DetectEntitiesV2 operation in all new applications. The DetectEntitiesV2 operation returns the Acuity and Direction entities as attributes instead of types. 

Required Parameters
Text => A UTF-8 string containing the clinical content being examined for entities. Each string must contain fewer than 20,000 bytes of characters.

"""
DetectEntitiesV2(Text) = comprehendmedical("DetectEntitiesV2", Dict{String, Any}("Text"=>Text))
DetectEntitiesV2(Text, args::AbstractDict{String, <: Any}) = comprehendmedical("DetectEntitiesV2", Dict{String, Any}("Text"=>Text, args...))

"""
    DetectPHI()

 Inspects the clinical text for protected health information (PHI) entities and returns the entity category, location, and confidence score for each entity. Amazon Comprehend Medical only detects entities in English language texts.

Required Parameters
Text =>  A UTF-8 text string containing the clinical content being examined for PHI entities. Each string must contain fewer than 20,000 bytes of characters.

"""
DetectPHI(Text) = comprehendmedical("DetectPHI", Dict{String, Any}("Text"=>Text))
DetectPHI(Text, args::AbstractDict{String, <: Any}) = comprehendmedical("DetectPHI", Dict{String, Any}("Text"=>Text, args...))

"""
    InferICD10CM()

InferICD10CM detects medical conditions as entities listed in a patient record and links those entities to normalized concept identifiers in the ICD-10-CM knowledge base from the Centers for Disease Control. Amazon Comprehend Medical only detects medical entities in English language texts.

Required Parameters
Text => The input text used for analysis. The input for InferICD10CM is a string from 1 to 10000 characters.

"""
InferICD10CM(Text) = comprehendmedical("InferICD10CM", Dict{String, Any}("Text"=>Text))
InferICD10CM(Text, args::AbstractDict{String, <: Any}) = comprehendmedical("InferICD10CM", Dict{String, Any}("Text"=>Text, args...))

"""
    InferRxNorm()

InferRxNorm detects medications as entities listed in a patient record and links to the normalized concept identifiers in the RxNorm database from the National Library of Medicine. Amazon Comprehend Medical only detects medical entities in English language texts.

Required Parameters
Text => The input text used for analysis. The input for InferRxNorm is a string from 1 to 10000 characters.

"""
InferRxNorm(Text) = comprehendmedical("InferRxNorm", Dict{String, Any}("Text"=>Text))
InferRxNorm(Text, args::AbstractDict{String, <: Any}) = comprehendmedical("InferRxNorm", Dict{String, Any}("Text"=>Text, args...))

"""
    ListEntitiesDetectionV2Jobs()

Gets a list of medical entity detection jobs that you have submitted.

Optional Parameters
Filter => Filters the jobs that are returned. You can filter jobs based on their names, status, or the date and time that they were submitted. You can only set one filter at a time.
MaxResults => The maximum number of results to return in each page. The default is 100.
NextToken => Identifies the next page of results to return.
"""
ListEntitiesDetectionV2Jobs() = comprehendmedical("ListEntitiesDetectionV2Jobs")
ListEntitiesDetectionV2Jobs(args::AbstractDict{String, <: Any}) = comprehendmedical("ListEntitiesDetectionV2Jobs", args)

"""
    ListICD10CMInferenceJobs()

Gets a list of InferICD10CM jobs that you have submitted.

Optional Parameters
Filter => Filters the jobs that are returned. You can filter jobs based on their names, status, or the date and time that they were submitted. You can only set one filter at a time.
MaxResults => The maximum number of results to return in each page. The default is 100.
NextToken => Identifies the next page of results to return.
"""
ListICD10CMInferenceJobs() = comprehendmedical("ListICD10CMInferenceJobs")
ListICD10CMInferenceJobs(args::AbstractDict{String, <: Any}) = comprehendmedical("ListICD10CMInferenceJobs", args)

"""
    ListPHIDetectionJobs()

Gets a list of protected health information (PHI) detection jobs that you have submitted.

Optional Parameters
Filter => Filters the jobs that are returned. You can filter jobs based on their names, status, or the date and time that they were submitted. You can only set one filter at a time.
MaxResults => The maximum number of results to return in each page. The default is 100.
NextToken => Identifies the next page of results to return.
"""
ListPHIDetectionJobs() = comprehendmedical("ListPHIDetectionJobs")
ListPHIDetectionJobs(args::AbstractDict{String, <: Any}) = comprehendmedical("ListPHIDetectionJobs", args)

"""
    ListRxNormInferenceJobs()

Gets a list of InferRxNorm jobs that you have submitted.

Optional Parameters
Filter => Filters the jobs that are returned. You can filter jobs based on their names, status, or the date and time that they were submitted. You can only set one filter at a time.
MaxResults => Identifies the next page of results to return.
NextToken => Identifies the next page of results to return.
"""
ListRxNormInferenceJobs() = comprehendmedical("ListRxNormInferenceJobs")
ListRxNormInferenceJobs(args::AbstractDict{String, <: Any}) = comprehendmedical("ListRxNormInferenceJobs", args)

"""
    StartEntitiesDetectionV2Job()

Starts an asynchronous medical entity detection job for a collection of documents. Use the DescribeEntitiesDetectionV2Job operation to track the status of a job.

Required Parameters
DataAccessRoleArn => The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that grants Amazon Comprehend Medical read access to your input data. For more information, see  Role-Based Permissions Required for Asynchronous Operations.
InputDataConfig => Specifies the format and location of the input data for the job.
LanguageCode => The language of the input documents. All documents must be in the same language.
OutputDataConfig => Specifies where to send the output files.

Optional Parameters
ClientRequestToken => A unique identifier for the request. If you don't set the client request token, Amazon Comprehend Medical generates one.
JobName => The identifier of the job.
KMSKey => An AWS Key Management Service key to encrypt your output files. If you do not specify a key, the files are written in plain text.
"""
StartEntitiesDetectionV2Job(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig) = comprehendmedical("StartEntitiesDetectionV2Job", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig))
StartEntitiesDetectionV2Job(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig, args::AbstractDict{String, <: Any}) = comprehendmedical("StartEntitiesDetectionV2Job", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig, args...))

"""
    StartICD10CMInferenceJob()

Starts an asynchronous job to detect medical conditions and link them to the ICD-10-CM ontology. Use the DescribeICD10CMInferenceJob operation to track the status of a job.

Required Parameters
DataAccessRoleArn => The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that grants Amazon Comprehend Medical read access to your input data. For more information, see  Role-Based Permissions Required for Asynchronous Operations.
InputDataConfig => Specifies the format and location of the input data for the job.
LanguageCode => The language of the input documents. All documents must be in the same language.
OutputDataConfig => Specifies where to send the output files.

Optional Parameters
ClientRequestToken => A unique identifier for the request. If you don't set the client request token, Amazon Comprehend Medical generates one.
JobName => The identifier of the job.
KMSKey => An AWS Key Management Service key to encrypt your output files. If you do not specify a key, the files are written in plain text.
"""
StartICD10CMInferenceJob(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig) = comprehendmedical("StartICD10CMInferenceJob", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig))
StartICD10CMInferenceJob(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig, args::AbstractDict{String, <: Any}) = comprehendmedical("StartICD10CMInferenceJob", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig, args...))

"""
    StartPHIDetectionJob()

Starts an asynchronous job to detect protected health information (PHI). Use the DescribePHIDetectionJob operation to track the status of a job.

Required Parameters
DataAccessRoleArn => The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that grants Amazon Comprehend Medical read access to your input data. For more information, see  Role-Based Permissions Required for Asynchronous Operations.
InputDataConfig => Specifies the format and location of the input data for the job.
LanguageCode => The language of the input documents. All documents must be in the same language.
OutputDataConfig => Specifies where to send the output files.

Optional Parameters
ClientRequestToken => A unique identifier for the request. If you don't set the client request token, Amazon Comprehend Medical generates one.
JobName => The identifier of the job.
KMSKey => An AWS Key Management Service key to encrypt your output files. If you do not specify a key, the files are written in plain text.
"""
StartPHIDetectionJob(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig) = comprehendmedical("StartPHIDetectionJob", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig))
StartPHIDetectionJob(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig, args::AbstractDict{String, <: Any}) = comprehendmedical("StartPHIDetectionJob", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig, args...))

"""
    StartRxNormInferenceJob()

Starts an asynchronous job to detect medication entities and link them to the RxNorm ontology. Use the DescribeRxNormInferenceJob operation to track the status of a job.

Required Parameters
DataAccessRoleArn => The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that grants Amazon Comprehend Medical read access to your input data. For more information, see  Role-Based Permissions Required for Asynchronous Operations.
InputDataConfig => Specifies the format and location of the input data for the job.
LanguageCode => The language of the input documents. All documents must be in the same language.
OutputDataConfig => Specifies where to send the output files.

Optional Parameters
ClientRequestToken => A unique identifier for the request. If you don't set the client request token, Amazon Comprehend Medical generates one.
JobName => The identifier of the job.
KMSKey => An AWS Key Management Service key to encrypt your output files. If you do not specify a key, the files are written in plain text.
"""
StartRxNormInferenceJob(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig) = comprehendmedical("StartRxNormInferenceJob", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig))
StartRxNormInferenceJob(DataAccessRoleArn, InputDataConfig, LanguageCode, OutputDataConfig, args::AbstractDict{String, <: Any}) = comprehendmedical("StartRxNormInferenceJob", Dict{String, Any}("DataAccessRoleArn"=>DataAccessRoleArn, "InputDataConfig"=>InputDataConfig, "LanguageCode"=>LanguageCode, "OutputDataConfig"=>OutputDataConfig, args...))

"""
    StopEntitiesDetectionV2Job()

Stops a medical entities detection job in progress.

Required Parameters
JobId => The identifier of the medical entities job to stop.

"""
StopEntitiesDetectionV2Job(JobId) = comprehendmedical("StopEntitiesDetectionV2Job", Dict{String, Any}("JobId"=>JobId))
StopEntitiesDetectionV2Job(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("StopEntitiesDetectionV2Job", Dict{String, Any}("JobId"=>JobId, args...))

"""
    StopICD10CMInferenceJob()

Stops an InferICD10CM inference job in progress.

Required Parameters
JobId => The identifier of the job.

"""
StopICD10CMInferenceJob(JobId) = comprehendmedical("StopICD10CMInferenceJob", Dict{String, Any}("JobId"=>JobId))
StopICD10CMInferenceJob(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("StopICD10CMInferenceJob", Dict{String, Any}("JobId"=>JobId, args...))

"""
    StopPHIDetectionJob()

Stops a protected health information (PHI) detection job in progress.

Required Parameters
JobId => The identifier of the PHI detection job to stop.

"""
StopPHIDetectionJob(JobId) = comprehendmedical("StopPHIDetectionJob", Dict{String, Any}("JobId"=>JobId))
StopPHIDetectionJob(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("StopPHIDetectionJob", Dict{String, Any}("JobId"=>JobId, args...))

"""
    StopRxNormInferenceJob()

Stops an InferRxNorm inference job in progress.

Required Parameters
JobId => The identifier of the job.

"""
StopRxNormInferenceJob(JobId) = comprehendmedical("StopRxNormInferenceJob", Dict{String, Any}("JobId"=>JobId))
StopRxNormInferenceJob(JobId, args::AbstractDict{String, <: Any}) = comprehendmedical("StopRxNormInferenceJob", Dict{String, Any}("JobId"=>JobId, args...))
