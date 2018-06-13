#!/usr/bin/python

########################################################################################
#
# Filename:    PCA_M3UAMessage.py
#  
# Description
# ===========
# M3UA Message Handler
#
#
# Author        : Michael Hsiao 
#
# Create Date   : 2016/09/10
# Desc          : Initial
##########################################################

import sys,string
import PCA_GenLib,struct
import PCA_XMLParser
import PCA_M3UAParameters
import PCA_SCCPMessage
#########################################################################
# Message Writer
#
#########################################################################
class Writer:


  #########################################################################
  # Init Header
  #
  ######################################################################## 
  
  message_length_hex = chr(0x00) + chr(0x00) + chr(0x00)+ chr(0x08)
  SLS = 0
      
  def __init__(self,XMLCFG):
    try:
      Msg = "Writer Init "
      PCA_GenLib.WriteLog(Msg,9)

      #0                   1                   2                   3
      #0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #| Version       | Reserved      | Message Class | Message Type |
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #| Message Length                                               |
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #\ \
      #/ /

      self.SCCPMessage = PCA_SCCPMessage.Writer(XMLCFG)
      Tag = "ROUTING_CONTEXT"
      self.routing_context = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))
      Tag = "OPC"
      self.opc = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))
      Tag = "DPC"
      self.dpc = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))
      Tag = "NI"
      self.ni = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))

      Msg = "Writer OK"
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "Writer Init Error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise


  ########################################################################
  # Return Message
  #
  #########################################################################
  def getASPSM_BEAT_Ack(self):
    try:

      message = PCA_M3UAParameters.version + PCA_M3UAParameters.reserve + PCA_M3UAParameters.ASPSM + PCA_M3UAParameters.ASPSM_BEAT_ACK + self.message_length_hex
      return message

    except:
     Msg = "getASPSM_BEAT Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
  ########################################################################
  # Return Message
  #
  #########################################################################
  def getASUP_UP(self):
    try:

      M3UA_ASUP_UP = PCA_M3UAParameters.version + PCA_M3UAParameters.reserve + PCA_M3UAParameters.ASPSM + PCA_M3UAParameters.ASPSM_ASPUP + self.message_length_hex
    
      return M3UA_ASUP_UP
    
    except:
     Msg = "getM3UA_ASUP_UP Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
  ########################################################################
  # Return Message
  #
  #########################################################################
  def getASUP_UP_Ack(self):
    try:

      M3UA_ASUP_UP_ACK = PCA_M3UAParameters.version + PCA_M3UAParameters.reserve + PCA_M3UAParameters.ASPSM + PCA_M3UAParameters.ASPSM_ASPUP_ACK + self.message_length_hex
      return M3UA_ASUP_UP_ACK

    except:
     Msg = "getM3UA_ASUP_UP_Ack Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	
  ########################################################################
  # Return Message
  #
  #########################################################################
  def getASP_Active(self):
    try:

      version = PCA_M3UAParameters.version
      reserve = PCA_M3UAParameters.reserve
      message_class = PCA_M3UAParameters.ASPTM
      message_type = PCA_M3UAParameters.ASPAC
      M3UA_header = version + reserve + message_class + message_type

      Tag = PCA_M3UAParameters.Traffic_Mode_Type_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",PCA_M3UAParameters.LoadShare)
      Traffic_mode_type = Tag + Length + Data

      Tag = PCA_M3UAParameters.Routing_Context_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",self.routing_context)
      Routing_context = Tag + Length + Data
      Msg = "M3UA_ASUP_UP Routing Context = <%s>" % (self.routing_context)
      PCA_GenLib.WriteLog(Msg,0)
     
      M3UA_data = M3UA_header + Traffic_mode_type + Routing_context
      message_length = len(M3UA_data) + 4
      message_length_hex = struct.pack("!i",message_length)

      M3UA_ASP_Active = M3UA_header + message_length_hex + Traffic_mode_type + Routing_context

      return M3UA_ASP_Active

    except:
     Msg = "getM3UA_ASUP_UP Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	


  ########################################################################
  # Return Message
  #
  #########################################################################
  def getASP_Active_Ack(self):
    try:

      version = PCA_M3UAParameters.version
      reserve = PCA_M3UAParameters.reserve
      message_class = PCA_M3UAParameters.ASPTM
      message_type = PCA_M3UAParameters.ASPAC_ACK
      M3UA_header = version + reserve + message_class + message_type

      Tag = PCA_M3UAParameters.Traffic_Mode_Type_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",PCA_M3UAParameters.LoadShare)
      Traffic_mode_type = Tag + Length + Data

      Tag = PCA_M3UAParameters.Routing_Context_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",self.routing_context)
      Routing_context = Tag + Length + Data
      Msg = "M3UA_ASUP_UP Routing Context = <%s>" % (self.routing_context)
      PCA_GenLib.WriteLog(Msg,0)
     
      M3UA_data = M3UA_header + Traffic_mode_type + Routing_context
      message_length = len(M3UA_data) + 4
      message_length_hex = struct.pack("!i",message_length)

      M3UA_ASP_Active = M3UA_header + message_length_hex + Traffic_mode_type + Routing_context

      return M3UA_ASP_Active

    except:
     Msg = "getM3UA_ASUP_UP_ack Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise

  ########################################################################
  # Return Message
  #
  #########################################################################
  def getSSNM(self,SSNM_TYPE):
    try:

      version = PCA_M3UAParameters.version
      reserve = PCA_M3UAParameters.reserve
      message_class = PCA_M3UAParameters.SSNM
      if SSNM_TYPE == "DUNA":
        message_type = PCA_M3UAParameters.DUNA
      else:
        message_type = PCA_M3UAParameters.DAVA
      M3UA_header = version + reserve + message_class + message_type

      Tag = PCA_M3UAParameters.Traffic_Mode_Type_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",PCA_M3UAParameters.LoadShare)
      Traffic_mode_type = Tag + Length + Data

      Tag = PCA_M3UAParameters.Routing_Context_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",self.routing_context)
      Routing_context = Tag + Length + Data
      Msg = "getSSNM Routing Context = <%s>" % (self.routing_context)
      PCA_GenLib.WriteLog(Msg,0)


      Tag = PCA_M3UAParameters.Affected_Point_Code_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",self.opc)
      Affected_Point_Code = Tag + Length + Data
     

      M3UA_data = M3UA_header + Traffic_mode_type + Routing_context + Affected_Point_Code
      message_length = len(M3UA_data) + 4
      message_length_hex = struct.pack("!i",message_length)

      M3UA_SSNM = M3UA_header + message_length_hex + Traffic_mode_type + Routing_context + Affected_Point_Code

      return M3UA_SSNM

    except:
     Msg = "getSSNM Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise

  ########################################################################
  # Return Message
  #
  #########################################################################
  def getPayloadData1(self,sccp_message,SLS):
    try:

      version = PCA_M3UAParameters.version
      reserve = PCA_M3UAParameters.reserve
      message_class = PCA_M3UAParameters.Transfer_Messages
      message_type = PCA_M3UAParameters.DATA
      M3UA_header = version + reserve + message_class + message_type

      Tag = PCA_M3UAParameters.Routing_Context_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",self.routing_context)
      Routing_context = Tag + Length + Data      
      
      protocol_data_tag = chr(0x02)+chr(0x10)
      
      OPC = struct.pack("!i",self.opc)
      DPC = struct.pack("!i",self.dpc)
      SI = chr(0x03)
      #NI = chr(0x02)
      NI = struct.pack("!B",self.ni)  
      MP = chr(0x00)
      

      protocol_data_msg = OPC + DPC + SI + NI + MP + SLS + sccp_message
      message_length = len(protocol_data_msg) + 4
      message_length_hex = struct.pack("!H",message_length)
      protocol_data = protocol_data_tag + message_length_hex + protocol_data_msg
      
      M3UA_data = M3UA_header + Routing_context + protocol_data 

      M3UA_data_len = len(M3UA_data) % 4
      M3UA_data_len_padding = 4 - M3UA_data_len

      message_padding = ''
      if M3UA_data_len_padding < 4:
        for i in range(M3UA_data_len_padding):
          M3UA_data = M3UA_data + chr(0x00)
          message_padding = message_padding + chr(0x00)
      
      message_length = len(M3UA_data) + 4
      message_length_hex = struct.pack("!i",message_length)

      
      M3UA_Payload = M3UA_header + message_length_hex +  Routing_context + protocol_data + message_padding

      
      return M3UA_Payload

    except:
     Msg = "getPayloadData Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
  ########################################################################
  # Return Message
  #
  #########################################################################
  def getPayloadData(self,map_type,parameter_list,parameter_list_request):
    try:

      version = PCA_M3UAParameters.version
      reserve = PCA_M3UAParameters.reserve
      message_class = PCA_M3UAParameters.Transfer_Messages
      message_type = PCA_M3UAParameters.DATA
      M3UA_header = version + reserve + message_class + message_type

      Tag = PCA_M3UAParameters.Routing_Context_Tag
      Length = struct.pack("!H",8)
      Data = struct.pack("!i",self.routing_context)
      Routing_context = Tag + Length + Data
      
      
      protocol_data_tag = chr(0x02)+chr(0x10)
      
      if map_type == "MO-FSM-segment":
        OPC = struct.pack("!i",self.opc)
      else:
        try:        
          dpc = parameter_list['M3UA DPC'][0]
          OPC = struct.pack("!i",dpc)
        except:        
          OPC = struct.pack("!i",self.opc)

      DPC = struct.pack("!i",self.dpc)
      SI = chr(0x03)
      NI = struct.pack("!B",self.ni)  
      MP = chr(0x00)
    

      try:        
        SLS = parameter_list['M3UA SLS'][1]
        
      except:        
        SLS = chr(0x04)      

      sccp_message = self.SCCPMessage.getMessage(map_type,parameter_list,parameter_list_request)
      protocol_data_msg = OPC + DPC + SI + NI + MP + SLS + sccp_message
      message_length = len(protocol_data_msg) + 4
      message_length_hex = struct.pack("!H",message_length)
      protocol_data = protocol_data_tag + message_length_hex + protocol_data_msg
      
      M3UA_data = M3UA_header + Routing_context + protocol_data 

      M3UA_data_len = len(M3UA_data) % 4
      M3UA_data_len_padding = 4 - M3UA_data_len

      message_padding = ''
      if M3UA_data_len_padding < 4:
        for i in range(M3UA_data_len_padding):
          M3UA_data = M3UA_data + chr(0x00)
          message_padding = message_padding + chr(0x00)
      
      message_length = len(M3UA_data) + 4
      message_length_hex = struct.pack("!i",message_length)
      
      M3UA_Payload = M3UA_header + message_length_hex +  Routing_context + protocol_data + message_padding
      return M3UA_Payload

    except:
     Msg = "getPayloadData Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
  ########################################################################
  # Return Message
  #
  #########################################################################
  def getMessage(self):
    try:
      return self.Message
    except:
     Msg = "getMessage Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
    
