version = chr(0x01)
reserve = chr(0x00)
  
  
Management_Messages = chr(0x00)
Transfer_Messages = chr(0x01)
SSNM = chr(0x02)
ASPSM = chr(0x03)
ASPTM = chr(0x04)
RKM = chr(0x09)
message_class = {}
message_class[Management_Messages] = 'Management (MGMT) Messages'
message_class[Transfer_Messages] = 'Transfer Messages'
message_class[SSNM] = 'SS7 Signalling Network Management (SSNM) Messages'
message_class[ASPSM] = 'ASP State Maintenance (ASPSM) Messages'
message_class[ASPTM] = 'ASP Traffic Maintenance (ASPTM) Messages'
message_class[RKM] = 'Management (MGMT) Messages'
  
ERR =  chr(0x00) 
NTFY = chr(0x01)
message_type_MGMT = {}
message_type_MGMT[ERR] = 'Error (ERR)'
message_type_MGMT[NTFY] = 'Notify (NTFY)'
 
DATA = chr(0x01)
message_type_Transfer_Messages = {}
message_type_Transfer_Messages[DATA] = 'Payload Data (DATA)'
  
DUNA = chr(0x01)
DAVA = chr(0x02)
DAUD = chr(0x03)
SCON = chr(0x04)
DUPU = chr(0x05)
DRST = chr(0x06)
message_type_SSNM = {}
message_type_SSNM[DUNA] = 'Destination Unavailable (DUNA)'
message_type_SSNM[DAVA] = 'Destination Available (DAVA)'
message_type_SSNM[DAUD] = 'Destination State Audit (DAUD)'
message_type_SSNM[SCON] = 'Signalling Congestion (SCON)'
message_type_SSNM[DUPU] = 'Destination User Part Unavailable (DUPU)'
message_type_SSNM[DRST] = 'Destination Restricted (DRST)'
  
  
ASPSM_ASPUP =  chr(0x01) 
ASPSM_ASPDN =  chr(0x02) 
ASPSM_BEAT =  chr(0x03) 
ASPSM_ASPUP_ACK =  chr(0x04) 
ASPSM_ASPDN_ACK =  chr(0x05) 
ASPSM_BEAT_ACK =  chr(0x06) 
message_type_ASPSM = {}
message_type_ASPSM[ASPSM_ASPUP] = 'ASP Up (ASPUP)'
message_type_ASPSM[ASPSM_ASPDN] = 'ASP Down (ASPDN)'
message_type_ASPSM[ASPSM_BEAT] = 'Heartbeat (BEAT)'
message_type_ASPSM[ASPSM_ASPUP_ACK] = 'ASP Up (ASPUP) ACK'
message_type_ASPSM[ASPSM_ASPDN_ACK] = 'ASP Up Acknowledgement (ASPUP ACK)'
message_type_ASPSM[ASPSM_BEAT_ACK] = 'Heartbeat Acknowledgement (BEAT ACK)'
   
  
ASPAC =  chr(0x01) 
ASPIA =  chr(0x02)
ASPAC_ACK =  chr(0x03)
ASPIA_ACK =  chr(0x04)
message_type_ASPTM = {}
message_type_ASPTM[ASPAC] = 'ASP Active (ASPAC)'
message_type_ASPTM[ASPIA] = 'ASP Inactive (ASPIA)'
message_type_ASPTM[ASPAC_ACK] = 'ASP Active Acknowledgement (ASPAC ACK)'
message_type_ASPTM[ASPIA_ACK] = 'ASP Inactive Acknowledgement (ASPIA ACK)'

REG_REQ =  chr(0x01)
REG_RSP =  chr(0x02)
DEREG_REQ =  chr(0x03)
DEREG_RSP =  chr(0x04)
message_type_RKM = {}
message_type_RKM[REG_REQ] = 'Registration Request (REG REQ)'
message_type_RKM[REG_RSP] = 'Registration Request (REG REQ)'
message_type_RKM[DEREG_REQ] = 'Registration Request (REG REQ)'
message_type_RKM[DEREG_RSP] = 'Registration Request (REG REQ)'
 

message_class_type = {}
message_class_type[Management_Messages] = message_type_MGMT
message_class_type[Transfer_Messages] = message_type_Transfer_Messages
message_class_type[SSNM] = message_type_SSNM
message_class_type[ASPSM] = message_type_ASPSM
message_class_type[ASPTM] = message_type_ASPTM
message_class_type[RKM] = message_type_RKM

TAG_DESC = {}
TAG_TYPE = {}
Traffic_Mode_Type_Tag = chr(0x00)+chr(0x0b)
TAG_DESC[Traffic_Mode_Type_Tag] = 'Traffic Mode Type'
TAG_TYPE[Traffic_Mode_Type_Tag] = 'unsigned integer'

Override = 1
LoadShare = 2
Broadcast = 3
Traffic_Mode_Type = {}
Traffic_Mode_Type[Override] = 'Override'
Traffic_Mode_Type[LoadShare] = 'LoadShare'
Traffic_Mode_Type[Broadcast] = 'Broadcast'

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

