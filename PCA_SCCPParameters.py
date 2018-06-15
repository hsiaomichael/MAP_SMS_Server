
  
CR_Connection_request =  chr(0x01)
UDTS_unitdata =  chr(0x09)
XUDTS_Extended_unitdata = chr(0x11)
SCCP_message_type = {}
SCCP_message_type[CR_Connection_request] = 'CR_Connection_request'
SCCP_message_type[UDTS_unitdata] = 'UDTS_unitdata'
SCCP_message_type[XUDTS_Extended_unitdata] = 'XUDTS_Extended_unitdata'
 

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

