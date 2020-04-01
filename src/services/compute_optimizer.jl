include("../AWSServices.jl")
using .AWSServices: compute_optimizer

"""
    GetAutoScalingGroupRecommendations()

Returns Auto Scaling group recommendations. AWS Compute Optimizer currently generates recommendations for Auto Scaling groups that are configured to run instances of the M, C, R, T, and X instance families. The service does not generate recommendations for Auto Scaling groups that have a scaling policy attached to them, or that do not have the same values for desired, minimum, and maximum capacity. In order for Compute Optimizer to analyze your Auto Scaling groups, they must be of a fixed size. For more information, see the AWS Compute Optimizer User Guide.

Optional Parameters
{
  "filters": "An array of objects that describe a filter that returns a more specific list of Auto Scaling group recommendations.",
  "autoScalingGroupArns": "The Amazon Resource Name (ARN) of the Auto Scaling groups for which to return recommendations.",
  "maxResults": "The maximum number of Auto Scaling group recommendations to return with a single call. To retrieve the remaining results, make another call with the returned NextToken value.",
  "nextToken": "The token to advance to the next page of Auto Scaling group recommendations.",
  "accountIds": "The AWS account IDs for which to return Auto Scaling group recommendations. Only one account ID can be specified per request."
}
"""
GetAutoScalingGroupRecommendations() = compute_optimizer("GetAutoScalingGroupRecommendations")
GetAutoScalingGroupRecommendations(args) = compute_optimizer("GetAutoScalingGroupRecommendations", args)

"""
    GetEC2InstanceRecommendations()

Returns Amazon EC2 instance recommendations. AWS Compute Optimizer currently generates recommendations for Amazon Elastic Compute Cloud (Amazon EC2) and Amazon EC2 Auto Scaling. It generates recommendations for M, C, R, T, and X instance families. For more information, see the AWS Compute Optimizer User Guide.

Optional Parameters
{
  "filters": "An array of objects that describe a filter that returns a more specific list of instance recommendations.",
  "maxResults": "The maximum number of instance recommendations to return with a single call. To retrieve the remaining results, make another call with the returned NextToken value.",
  "instanceArns": "The Amazon Resource Name (ARN) of the instances for which to return recommendations.",
  "nextToken": "The token to advance to the next page of instance recommendations.",
  "accountIds": "The AWS account IDs for which to return instance recommendations. Only one account ID can be specified per request."
}
"""
GetEC2InstanceRecommendations() = compute_optimizer("GetEC2InstanceRecommendations")
GetEC2InstanceRecommendations(args) = compute_optimizer("GetEC2InstanceRecommendations", args)

"""
    GetEC2RecommendationProjectedMetrics()

Returns the projected utilization metrics of Amazon EC2 instance recommendations.

Required Parameters
{
  "stat": "The statistic of the projected metrics.",
  "startTime": "The time stamp of the first projected metrics data point to return.",
  "period": "The granularity, in seconds, of the projected metrics data points.",
  "instanceArn": "The Amazon Resource Name (ARN) of the instances for which to return recommendation projected metrics.",
  "endTime": "The time stamp of the last projected metrics data point to return."
}
"""
GetEC2RecommendationProjectedMetrics(args) = compute_optimizer("GetEC2RecommendationProjectedMetrics", args)

"""
    GetRecommendationSummaries()

Returns the optimization findings for an account. For example, it returns the number of Amazon EC2 instances in an account that are under-provisioned, over-provisioned, or optimized. It also returns the number of Auto Scaling groups in an account that are not optimized, or optimized.

Optional Parameters
{
  "maxResults": "The maximum number of recommendation summaries to return with a single call. To retrieve the remaining results, make another call with the returned NextToken value.",
  "nextToken": "The token to advance to the next page of recommendation summaries.",
  "accountIds": "The AWS account IDs for which to return recommendation summaries. Only one account ID can be specified per request."
}
"""
GetRecommendationSummaries() = compute_optimizer("GetRecommendationSummaries")
GetRecommendationSummaries(args) = compute_optimizer("GetRecommendationSummaries", args)

"""
    GetEnrollmentStatus()

Returns the enrollment (opt in) status of an account to the AWS Compute Optimizer service. If the account is a master account of an organization, this operation also confirms the enrollment status of member accounts within the organization.
"""
GetEnrollmentStatus() = compute_optimizer("GetEnrollmentStatus")
GetEnrollmentStatus(args) = compute_optimizer("GetEnrollmentStatus", args)

"""
    UpdateEnrollmentStatus()

Updates the enrollment (opt in) status of an account to the AWS Compute Optimizer service. If the account is a master account of an organization, this operation can also enroll member accounts within the organization.

Required Parameters
{
  "status": "The new enrollment status of the account. Accepted options are Active or Inactive. You will get an error if Pending or Failed are specified."
}

Optional Parameters
{
  "includeMemberAccounts": "Indicates whether to enroll member accounts within the organization, if the account is a master account of an organization."
}
"""
UpdateEnrollmentStatus(args) = compute_optimizer("UpdateEnrollmentStatus", args)