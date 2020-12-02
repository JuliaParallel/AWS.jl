# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: customer_profiles
using AWS.Compat
using AWS.UUIDs

"""
    AddProfileKey()

Associates a new key value with a specific profile, such as a Contact Trace Record (CTR) ContactId. A profile object can have a single unique key and any number of additional keys that can be used to identify the profile that it belongs to.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `KeyName`: A searchable identifier of a customer profile.
- `ProfileId`: The unique identifier of a customer profile.
- `Values`: A list of key values.

"""
add_profile_key(DomainName, KeyName, ProfileId, Values; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/keys", Dict{String, Any}("KeyName"=>KeyName, "ProfileId"=>ProfileId, "Values"=>Values); aws_config=aws_config)
add_profile_key(DomainName, KeyName, ProfileId, Values, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/keys", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("KeyName"=>KeyName, "ProfileId"=>ProfileId, "Values"=>Values), args)); aws_config=aws_config)

"""
    CreateDomain()

Creates a domain, which is a container for all customer data, such as customer profile attributes, object types, profile keys, and encryption keys. You can create multiple domains, and each domain can have multiple third-party integrations. Each Amazon Connect instance can be associated with only one domain. Multiple Amazon Connect instances can be associated with one domain.

# Required Parameters
- `DefaultExpirationDays`: The default number of days until the data within the domain expires.
- `DomainName`: The unique name of the domain.

# Optional Parameters
- `DeadLetterQueueUrl`: The URL of the SQS dead letter queue, which is used for reporting errors associated with ingesting data from third party applications. You must set up a policy on the DeadLetterQueue for the SendMessage operation to enable Amazon Connect Customer Profiles to send messages to the DeadLetterQueue.
- `DefaultEncryptionKey`: The default encryption key, which is an AWS managed key, is used when no specific type of encryption key is specified. It is used to encrypt all data before it is placed in permanent or semi-permanent storage.
- `Tags`: The tags used to organize, track, or control access for this resource.
"""
create_domain(DefaultExpirationDays, DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)", Dict{String, Any}("DefaultExpirationDays"=>DefaultExpirationDays); aws_config=aws_config)
create_domain(DefaultExpirationDays, DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("DefaultExpirationDays"=>DefaultExpirationDays), args)); aws_config=aws_config)

"""
    CreateProfile()

Creates a standard profile. A standard profile represents the following attributes for a customer profile in a domain.

# Required Parameters
- `DomainName`: The unique name of the domain.

# Optional Parameters
- `AccountNumber`: A unique account number that you have given to the customer.
- `AdditionalInformation`: Any additional information relevant to the customer's profile.
- `Address`: A generic address associated with the customer that is not mailing, shipping, or billing.
- `Attributes`: A key value pair of attributes of a customer profile.
- `BillingAddress`: The customer’s billing address.
- `BirthDate`: The customer’s birth date.
- `BusinessEmailAddress`: The customer’s business email address.
- `BusinessName`: The name of the customer’s business.
- `BusinessPhoneNumber`: The customer’s business phone number.
- `EmailAddress`: The customer's email address, which has not been specified as a personal or business address.
- `FirstName`: The customer’s first name.
- `Gender`: The gender with which the customer identifies.
- `HomePhoneNumber`: The customer’s home phone number.
- `LastName`: The customer’s last name.
- `MailingAddress`: The customer’s mailing address.
- `MiddleName`: The customer’s middle name.
- `MobilePhoneNumber`: The customer’s mobile phone number.
- `PartyType`: The type of profile used to describe the customer.
- `PersonalEmailAddress`: The customer’s personal email address.
- `PhoneNumber`: The customer's phone number, which has not been specified as a mobile, home, or business number.
- `ShippingAddress`: The customer’s shipping address.
"""
create_profile(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles"; aws_config=aws_config)
create_profile(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles", args; aws_config=aws_config)

"""
    DeleteDomain()

Deletes a specific domain and all of its customer data, such as customer profile attributes and their related objects.

# Required Parameters
- `DomainName`: The unique name of the domain.

"""
delete_domain(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("DELETE", "/domains/$(DomainName)"; aws_config=aws_config)
delete_domain(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("DELETE", "/domains/$(DomainName)", args; aws_config=aws_config)

"""
    DeleteIntegration()

Removes an integration from a specific domain.

# Required Parameters
- `DomainName`: The unique name of the domain.

# Optional Parameters
- `Uri`: The URI of the S3 bucket or any other type of data source.
"""
delete_integration(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/integrations/delete"; aws_config=aws_config)
delete_integration(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/integrations/delete", args; aws_config=aws_config)

"""
    DeleteProfile()

Deletes the standard customer profile and all data pertaining to the profile.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `ProfileId`: The unique identifier of a customer profile.

"""
delete_profile(DomainName, ProfileId; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/delete", Dict{String, Any}("ProfileId"=>ProfileId); aws_config=aws_config)
delete_profile(DomainName, ProfileId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/delete", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ProfileId"=>ProfileId), args)); aws_config=aws_config)

"""
    DeleteProfileKey()

Removes a searchable key from a customer profile.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `KeyName`: A searchable identifier of a customer profile.
- `ProfileId`: The unique identifier of a customer profile.
- `Values`: A list of key values.

"""
delete_profile_key(DomainName, KeyName, ProfileId, Values; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/keys/delete", Dict{String, Any}("KeyName"=>KeyName, "ProfileId"=>ProfileId, "Values"=>Values); aws_config=aws_config)
delete_profile_key(DomainName, KeyName, ProfileId, Values, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/keys/delete", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("KeyName"=>KeyName, "ProfileId"=>ProfileId, "Values"=>Values), args)); aws_config=aws_config)

"""
    DeleteProfileObject()

Removes an object associated with a profile of a given ProfileObjectType.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `ObjectTypeName`: The name of the profile object type.
- `ProfileId`: The unique identifier of a customer profile.
- `ProfileObjectUniqueKey`: The unique identifier of the profile object generated by the service.

"""
delete_profile_object(DomainName, ObjectTypeName, ProfileId, ProfileObjectUniqueKey; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/objects/delete", Dict{String, Any}("ObjectTypeName"=>ObjectTypeName, "ProfileId"=>ProfileId, "ProfileObjectUniqueKey"=>ProfileObjectUniqueKey); aws_config=aws_config)
delete_profile_object(DomainName, ObjectTypeName, ProfileId, ProfileObjectUniqueKey, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/objects/delete", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ObjectTypeName"=>ObjectTypeName, "ProfileId"=>ProfileId, "ProfileObjectUniqueKey"=>ProfileObjectUniqueKey), args)); aws_config=aws_config)

"""
    DeleteProfileObjectType()

Removes a ProfileObjectType from a specific domain as well as removes all the ProfileObjects of that type. It also disables integrations from this specific ProfileObjectType. In addition, it scrubs all of the fields of the standard profile that were populated from this ProfileObjectType.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `ObjectTypeName`: The name of the profile object type.

"""
delete_profile_object_type(DomainName, ObjectTypeName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("DELETE", "/domains/$(DomainName)/object-types/$(ObjectTypeName)"; aws_config=aws_config)
delete_profile_object_type(DomainName, ObjectTypeName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("DELETE", "/domains/$(DomainName)/object-types/$(ObjectTypeName)", args; aws_config=aws_config)

"""
    GetDomain()

Returns information about a specific domain.

# Required Parameters
- `DomainName`: A unique name for the domain.

"""
get_domain(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)"; aws_config=aws_config)
get_domain(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)", args; aws_config=aws_config)

"""
    GetIntegration()

Returns an integration for a domain.

# Required Parameters
- `DomainName`: The unique name of the domain.

# Optional Parameters
- `Uri`: The URI of the S3 bucket or any other type of data source.
"""
get_integration(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/integrations"; aws_config=aws_config)
get_integration(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/integrations", args; aws_config=aws_config)

"""
    GetProfileObjectType()

Returns the object types for a specific domain.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `ObjectTypeName`: The name of the profile object type.

"""
get_profile_object_type(DomainName, ObjectTypeName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)/object-types/$(ObjectTypeName)"; aws_config=aws_config)
get_profile_object_type(DomainName, ObjectTypeName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)/object-types/$(ObjectTypeName)", args; aws_config=aws_config)

"""
    GetProfileObjectTypeTemplate()

Returns the template information for a specific object type. A template is a predefined ProfileObjectType, such as “Salesforce-Account” or “Salesforce-Contact.” When a user sends a ProfileObject, using the PutProfileObject API, with an ObjectTypeName that matches one of the TemplateIds, it uses the mappings from the template.

# Required Parameters
- `TemplateId`: A unique identifier for the object template.

"""
get_profile_object_type_template(TemplateId; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/templates/$(TemplateId)"; aws_config=aws_config)
get_profile_object_type_template(TemplateId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/templates/$(TemplateId)", args; aws_config=aws_config)

"""
    ListAccountIntegrations()

Lists all of the integrations associated to a specific URI in the AWS account.

# Required Parameters
- `Uri`: The URI of the S3 bucket or any other type of data source.

# Optional Parameters
- `max-results`: The maximum number of objects returned per page.
- `next-token`: The pagination token from the previous ListAccountIntegrations API call.
"""
list_account_integrations(Uri; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/integrations", Dict{String, Any}("Uri"=>Uri); aws_config=aws_config)
list_account_integrations(Uri, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/integrations", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Uri"=>Uri), args)); aws_config=aws_config)

"""
    ListDomains()

Returns a list of all the domains for an AWS account that have been created.

# Optional Parameters
- `max-results`: The maximum number of objects returned per page.
- `next-token`: The pagination token from the previous ListDomain API call.
"""
list_domains(; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains"; aws_config=aws_config)
list_domains(args::AbstractDict{String, Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains", args; aws_config=aws_config)

"""
    ListIntegrations()

Lists all of the integrations in your domain.

# Required Parameters
- `DomainName`: The unique name of the domain.

# Optional Parameters
- `max-results`: The maximum number of objects returned per page.
- `next-token`: The pagination token from the previous ListIntegrations API call.
"""
list_integrations(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)/integrations"; aws_config=aws_config)
list_integrations(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)/integrations", args; aws_config=aws_config)

"""
    ListProfileObjectTypeTemplates()

Lists all of the template information for object types.

# Optional Parameters
- `max-results`: The maximum number of objects returned per page.
- `next-token`: The pagination token from the previous ListObjectTypeTemplates API call.
"""
list_profile_object_type_templates(; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/templates"; aws_config=aws_config)
list_profile_object_type_templates(args::AbstractDict{String, Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/templates", args; aws_config=aws_config)

"""
    ListProfileObjectTypes()

Lists all of the templates available within the service.

# Required Parameters
- `DomainName`: The unique name of the domain.

# Optional Parameters
- `max-results`: The maximum number of objects returned per page.
- `next-token`: Identifies the next page of results to return.
"""
list_profile_object_types(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)/object-types"; aws_config=aws_config)
list_profile_object_types(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/domains/$(DomainName)/object-types", args; aws_config=aws_config)

"""
    ListProfileObjects()

Returns a list of objects associated with a profile of a given ProfileObjectType.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `ObjectTypeName`: The name of the profile object type.
- `ProfileId`: The unique identifier of a customer profile.

# Optional Parameters
- `max-results`: The maximum number of objects returned per page.
- `next-token`: The pagination token from the previous call to ListProfileObjects.
"""
list_profile_objects(DomainName, ObjectTypeName, ProfileId; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/objects", Dict{String, Any}("ObjectTypeName"=>ObjectTypeName, "ProfileId"=>ProfileId); aws_config=aws_config)
list_profile_objects(DomainName, ObjectTypeName, ProfileId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/objects", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ObjectTypeName"=>ObjectTypeName, "ProfileId"=>ProfileId), args)); aws_config=aws_config)

"""
    ListTagsForResource()

Displays the tags associated with an Amazon Connect Customer Profiles resource. In Connect Customer Profiles, domains, profile object types, and integrations can be tagged.

# Required Parameters
- `resourceArn`: The ARN of the resource for which you want to view tags.

"""
list_tags_for_resource(resourceArn; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/tags/$(resourceArn)"; aws_config=aws_config)
list_tags_for_resource(resourceArn, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("GET", "/tags/$(resourceArn)", args; aws_config=aws_config)

"""
    PutIntegration()

Adds an integration between the service and a third-party service, which includes Amazon AppFlow and Amazon Connect. An integration can belong to only one domain.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `ObjectTypeName`: The name of the profile object type.
- `Uri`: The URI of the S3 bucket or any other type of data source.

# Optional Parameters
- `Tags`: The tags used to organize, track, or control access for this resource.
"""
put_integration(DomainName, ObjectTypeName, Uri; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/integrations", Dict{String, Any}("ObjectTypeName"=>ObjectTypeName, "Uri"=>Uri); aws_config=aws_config)
put_integration(DomainName, ObjectTypeName, Uri, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/integrations", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ObjectTypeName"=>ObjectTypeName, "Uri"=>Uri), args)); aws_config=aws_config)

"""
    PutProfileObject()

Adds additional objects to customer profiles of a given ObjectType. When adding a specific profile object, like a Contact Trace Record (CTR), an inferred profile can get created if it is not mapped to an existing profile. The resulting profile will only have a phone number populated in the standard ProfileObject. Any additional CTRs with the same phone number will be mapped to the same inferred profile. When a ProfileObject is created and if a ProfileObjectType already exists for the ProfileObject, it will provide data to a standard profile depending on the ProfileObjectType definition. PutProfileObject needs an ObjectType, which can be created using PutProfileObjectType.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `Object`: A string that is serialized from a JSON object.
- `ObjectTypeName`: The name of the profile object type.

"""
put_profile_object(DomainName, Object, ObjectTypeName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/profiles/objects", Dict{String, Any}("Object"=>Object, "ObjectTypeName"=>ObjectTypeName); aws_config=aws_config)
put_profile_object(DomainName, Object, ObjectTypeName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/profiles/objects", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Object"=>Object, "ObjectTypeName"=>ObjectTypeName), args)); aws_config=aws_config)

"""
    PutProfileObjectType()

Defines a ProfileObjectType.

# Required Parameters
- `Description`: Description of the profile object type.
- `DomainName`: The unique name of the domain.
- `ObjectTypeName`: The name of the profile object type.

# Optional Parameters
- `AllowProfileCreation`: Indicates whether a profile should be created when data is received if one doesn’t exist for an object of this type. The default is FALSE. If the AllowProfileCreation flag is set to FALSE, then the service tries to fetch a standard profile and associate this object with the profile. If it is set to TRUE, and if no match is found, then the service creates a new standard profile.
- `EncryptionKey`: The customer-provided key to encrypt the profile object that will be created in this profile object type.
- `ExpirationDays`: The number of days until the data in the object expires.
- `Fields`: A map of the name and ObjectType field.
- `Keys`: A list of unique keys that can be used to map data to the profile.
- `Tags`: The tags used to organize, track, or control access for this resource.
- `TemplateId`: A unique identifier for the object template.
"""
put_profile_object_type(Description, DomainName, ObjectTypeName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/object-types/$(ObjectTypeName)", Dict{String, Any}("Description"=>Description); aws_config=aws_config)
put_profile_object_type(Description, DomainName, ObjectTypeName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/object-types/$(ObjectTypeName)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("Description"=>Description), args)); aws_config=aws_config)

"""
    SearchProfiles()

Searches for profiles within a specific domain name using name, phone number, email address, account number, or a custom defined index.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `KeyName`: A searchable identifier of a customer profile. The predefined keys you can use to search include: _account, _profileId, _fullName, _phone, _email, _ctrContactId, _marketoLeadId, _salesforceAccountId, _salesforceContactId, _zendeskUserId, _zendeskExternalId, _serviceNowSystemId.
- `Values`: A list of key values.

# Optional Parameters
- `max-results`: The maximum number of objects returned per page.
- `next-token`: The pagination token from the previous SearchProfiles API call.
"""
search_profiles(DomainName, KeyName, Values; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/search", Dict{String, Any}("KeyName"=>KeyName, "Values"=>Values); aws_config=aws_config)
search_profiles(DomainName, KeyName, Values, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/domains/$(DomainName)/profiles/search", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("KeyName"=>KeyName, "Values"=>Values), args)); aws_config=aws_config)

"""
    TagResource()

Assigns one or more tags (key-value pairs) to the specified Amazon Connect Customer Profiles resource. Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values. In Connect Customer Profiles, domains, profile object types, and integrations can be tagged. Tags don't have any semantic meaning to AWS and are interpreted strictly as strings of characters. You can use the TagResource action with a resource that already has tags. If you specify a new tag key, this tag is appended to the list of tags associated with the resource. If you specify a tag key that is already associated with the resource, the new tag value that you specify replaces the previous value for that tag. You can associate as many as 50 tags with a resource.

# Required Parameters
- `resourceArn`: The ARN of the resource that you're adding tags to.
- `tags`: The tags used to organize, track, or control access for this resource.

"""
tag_resource(resourceArn, tags; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/tags/$(resourceArn)", Dict{String, Any}("tags"=>tags); aws_config=aws_config)
tag_resource(resourceArn, tags, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("POST", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tags"=>tags), args)); aws_config=aws_config)

"""
    UntagResource()

Removes one or more tags from the specified Amazon Connect Customer Profiles resource. In Connect Customer Profiles, domains, profile object types, and integrations can be tagged.

# Required Parameters
- `resourceArn`: The ARN of the resource from which you are removing tags.
- `tagKeys`: The list of tag keys to remove from the resource.

"""
untag_resource(resourceArn, tagKeys; aws_config::AWSConfig=global_aws_config()) = customer_profiles("DELETE", "/tags/$(resourceArn)", Dict{String, Any}("tagKeys"=>tagKeys); aws_config=aws_config)
untag_resource(resourceArn, tagKeys, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("DELETE", "/tags/$(resourceArn)", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("tagKeys"=>tagKeys), args)); aws_config=aws_config)

"""
    UpdateDomain()

Updates the properties of a domain, including creating or selecting a dead letter queue or an encryption key. Once a domain is created, the name can’t be changed.

# Required Parameters
- `DomainName`: The unique name for the domain.

# Optional Parameters
- `DeadLetterQueueUrl`: The URL of the SQS dead letter queue, which is used for reporting errors associated with ingesting data from third party applications. If specified as an empty string, it will clear any existing value. You must set up a policy on the DeadLetterQueue for the SendMessage operation to enable Amazon Connect Customer Profiles to send messages to the DeadLetterQueue.
- `DefaultEncryptionKey`: The default encryption key, which is an AWS managed key, is used when no specific type of encryption key is specified. It is used to encrypt all data before it is placed in permanent or semi-permanent storage. If specified as an empty string, it will clear any existing value.
- `DefaultExpirationDays`: The default number of days until the data within the domain expires.
- `Tags`: The tags used to organize, track, or control access for this resource.
"""
update_domain(DomainName; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)"; aws_config=aws_config)
update_domain(DomainName, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)", args; aws_config=aws_config)

"""
    UpdateProfile()

Updates the properties of a profile. The ProfileId is required for updating a customer profile. When calling the UpdateProfile API, specifying an empty string value means that any existing value will be removed. Not specifying a string value means that any value already there will be kept.

# Required Parameters
- `DomainName`: The unique name of the domain.
- `ProfileId`: The unique identifier of a customer profile.

# Optional Parameters
- `AccountNumber`: A unique account number that you have given to the customer.
- `AdditionalInformation`: Any additional information relevant to the customer's profile.
- `Address`: A generic address associated with the customer that is not mailing, shipping, or billing.
- `Attributes`: A key value pair of attributes of a customer profile.
- `BillingAddress`: The customer’s billing address.
- `BirthDate`: The customer’s birth date.
- `BusinessEmailAddress`: The customer’s business email address.
- `BusinessName`: The name of the customer’s business.
- `BusinessPhoneNumber`: The customer’s business phone number.
- `EmailAddress`: The customer's email address, which has not been specified as a personal or business address.
- `FirstName`: The customer’s first name.
- `Gender`: The gender with which the customer identifies.
- `HomePhoneNumber`: The customer’s home phone number.
- `LastName`: The customer’s last name.
- `MailingAddress`: The customer’s mailing address.
- `MiddleName`: The customer’s middle name.
- `MobilePhoneNumber`: The customer’s mobile phone number.
- `PartyType`: The type of profile used to describe the customer.
- `PersonalEmailAddress`: The customer’s personal email address.
- `PhoneNumber`: The customer's phone number, which has not been specified as a mobile, home, or business number.
- `ShippingAddress`: The customer’s shipping address.
"""
update_profile(DomainName, ProfileId; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/profiles", Dict{String, Any}("ProfileId"=>ProfileId); aws_config=aws_config)
update_profile(DomainName, ProfileId, args::AbstractDict{String, <:Any}; aws_config::AWSConfig=global_aws_config()) = customer_profiles("PUT", "/domains/$(DomainName)/profiles", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("ProfileId"=>ProfileId), args)); aws_config=aws_config)
