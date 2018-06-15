
component_portion = chr(0x6c)
component_type_invoke = chr(0xa1)
component_type_reject = chr(0xa4)
component_type_return_error = chr(0xa3)
invoke_id = chr(0x02)
SM_RP_UI = chr(0x04)
Originator_address = chr(0x82)
SC_Address = chr(0x84)
SM_RP_DA = chr(0x30)
msisdn = chr(0x80)
SM_RP_PRI = chr(0x81)
Tag_Desc= {}
Tag_Desc[invoke_id] = 'invoke_id'
Tag_Desc[component_portion] = 'component_portion'
Tag_Desc[component_type_invoke] = 'component_type_invoke'
Tag_Desc[component_type_reject] = 'component_type_reject'
Tag_Desc[component_type_return_error] = 'component_type_return_error'
Tag_Desc[SM_RP_UI] = 'SM_RP_UI'
Tag_Desc[Originator_address] = 'Originator_address'
Tag_Desc[SC_Address] = 'SC_Address'
Tag_Desc[SM_RP_DA] = 'SM_RP_DA'
Tag_Desc[msisdn] = 'msisdn'
Tag_Desc[SM_RP_PRI] = 'SM_RP_PRI'
 

mo_ForwardSM = 46
mt_ForwardSM = 44
reportSM_DeliveryStatus = 47
alertServiceCentre = 64
informServiceCentre = 63
sendRoutingInfoForSM = 45
op_code = {}
op_code[mo_ForwardSM] = 'mo-ForwardSM'
op_code[mt_ForwardSM] = 'mt-ForwardSM'
op_code[reportSM_DeliveryStatus] = 'reportSM-DeliveryStatus'
op_code[alertServiceCentre] = 'alertServiceCentre'
op_code[informServiceCentre] = 'informServiceCentre'
op_code[sendRoutingInfoForSM] = 'sendRoutingInfoForSM'


  
Unidirectional =  1
Begin = 2
End  =  3
Continue  =  4
Abort  =  5
message_type = {}
message_type[Unidirectional] = 'Unidirectional'
message_type[Begin] = 'Begin'
message_type[End] = 'End'
message_type[Continue] = 'Continue'
message_type[Abort] = 'Abort'



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

