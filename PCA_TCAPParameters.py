tcap_begin_tag = chr(0x62)
tcap_end_tag = chr(0x64)
otid = chr(0x48)
dtid = chr(0x49)
abort = chr(0x4a)
dialog_portion = chr(0x6b)
external_tag = chr(0x28)
Object_Identifier_Tag = chr(0x06)
Single_ASN1_Type = chr(0xa0)
dialog_request_Tag = chr(0x60)
dialog_response_Tag = chr(0x61)
dialog_abort_Tag = chr(0x61)
protocol_version_Tag = chr(0x80)
Application_Context = chr(0xa1)
Application_Context_result = chr(0xa2)
result_diag = chr(0xa3)
component_portion = chr(0x6c)
#component_type_invoke = chr(0xa1)
component_type_reject = chr(0xa4)
Tag_Desc= {}
Tag_Desc[tcap_begin_tag] = 'tcap_begin'
Tag_Desc[tcap_end_tag] = 'tcap_end'
Tag_Desc[otid] = 'Originating TID'
Tag_Desc[dtid] = 'Destination TID'
Tag_Desc[abort] = 'abort'
Tag_Desc[dialog_portion] = 'dialog_portion'
Tag_Desc[external_tag] = 'external_tag'
Tag_Desc[Object_Identifier_Tag] = 'oid'
Tag_Desc[Single_ASN1_Type] = 'Single_ASN1_Type'
Tag_Desc[dialog_request_Tag] = 'dialog_request'
Tag_Desc[dialog_response_Tag] = 'dialog_response'
Tag_Desc[dialog_abort_Tag] = 'dialog_abort'
Tag_Desc[protocol_version_Tag] = 'protocol_version'
Tag_Desc[component_portion] = 'component_portion'
Tag_Desc[Application_Context] = 'Application_Context'
Tag_Desc[Application_Context_result] = 'Application_Context_result'
Tag_Desc[result_diag] = 'result_diag'



Unidirectional =  1
Begin = 2
End  =  4
Continue  =  5
Abort  =  7
message_type = {}
message_type[Unidirectional] = 'Unidirectional'
message_type[Begin] = 'Begin'
message_type[End] = 'End'
message_type[Continue] = 'Continue'
message_type[Abort] = 'Abort'


app_context = {}
app_context['40010213'] = 'shortMsgMO_Relay_v3'
app_context['40010212'] = 'shortMsgMO_Relay_v2'
app_context['40010203'] = 'shortMsgGateway_SRI_v3'
app_context['40010202'] = 'shortMsgGateway_SRI_v2'
app_context['40010253'] = 'shortMsgMT_Relay_v3'
app_context['40010252'] = 'shortMsgMT_Relay_v2'
app_context['40010233'] = 'shortMsgAlert_v3'
app_context['40010232'] = 'shortMsgAlert_v2'


tag_class = {}
tag_class[0] = 'Universal'
tag_class[1] = 'Application-wide'
tag_class[2] = 'Context-specific'
tag_class[3] = 'Private use'

TAG_DESC = {}
TAG_TYPE = {}
Routing_Context_Tag = chr(0x00)+chr(0x06)
TAG_DESC[Routing_Context_Tag] = 'Routing Context'
TAG_TYPE[Routing_Context_Tag] = 'unsigned integer'

INFO_String_Tag = chr(0x00)+chr(0x04)
TAG_DESC[INFO_String_Tag] = 'INFO String'
TAG_TYPE[INFO_String_Tag] = 'string'

Protocol_Data_Tag = chr(0x02)+chr(0x10)
TAG_DESC[Protocol_Data_Tag] = 'Protocol_Data'
TAG_TYPE[Protocol_Data_Tag] = 'hex'

Reserved_Tag = chr(0x00)+chr(0x00)
TAG_DESC[Reserved_Tag] = 'Resreved Tag'
TAG_TYPE[Reserved_Tag] = 'hex'

