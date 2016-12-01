#!/usr/bin/python

########################################################################################
#
# Filename:    PCA_SCCPMessage.py
#  
# Description
# ===========
# M3UA Message Handler
#
#
# Author        : Michael Hsiao 
#
# Create Date   : 2016/10/01
# Desc          : Initial
##########################################################

import sys,string
import PCA_GenLib,struct
import PCA_XMLParser
import PCA_SCCPParameters
import PCA_TCAPMessage
#########################################################################
# Message Writer
#
#########################################################################
class Writer:
	
	
  #########################################################################
  # Init Header
  #
  ########################################################################
    
  message_length_hex = chr(0x00) + chr(0x00) 
      
  def __init__(self,XMLCFG):
    try:
      Msg = "Writer Init "
      PCA_GenLib.WriteLog(Msg,9)
	
      self.TCAPMessage = PCA_TCAPMessage.Writer(XMLCFG)

      Tag = "MESSAGE_TYPE"
      self.message_type = int(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))

      Tag = "SC_ADDRESS"
      self.sc_address = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
      Msg = "sc_address = <%s> " % self.sc_address
      PCA_GenLib.WriteLog(Msg,1)
	
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
  def getMessage(self,map_type,parameter_list,parameter_list_request):
    try:	
      
      message_type = struct.pack("!b",self.message_type)
      Protocol_Class = chr(0x00) # parameter_list["SCCP Protocol Class"][1]
      
      #hoop_counter = parameter_list["SCCP Hop Counter"][1]
      hoop_counter = chr(0x0f)
      P_2_first_parameter = chr(0x04)

      ################################################
      # CdPA
      ################################################
      if map_type == "SRI-SM":
        TT = chr(0x00)
        Numbering_plan = chr(0x12) ## even number of digits ..
        NoA = chr(0x04)
        Digits = PCA_GenLib.converStringToReverseBCD(parameter_list['recipient'])
       
        GT = TT + Numbering_plan + NoA + Digits
        address_indicator = chr(0x12)
        if map_type == "SRI-SM":
          SSN = chr(0x06)
        else:
          SSN = chr(0x08)
        called_address = address_indicator + SSN + GT

      elif map_type == "MT-FSM":
        TT = chr(0x00)
        Numbering_plan = chr(0x12) ## even number of digits ..
        NoA = chr(0x04)
        Digits = PCA_GenLib.converStringToReverseBCD(parameter_list['NNN'])
       
        GT = TT + Numbering_plan + NoA + Digits
        address_indicator = chr(0x12)
        if map_type == "SRI-SM":
          SSN = chr(0x06)
        else:
          SSN = chr(0x08)
        called_address = address_indicator + SSN + GT
      else:
        # prepare data for MO-FSM ack
        TT = parameter_list["SCCP calling Translation Type"][1]
        Numbering_plan = parameter_list["SCCP calling Numbering plan"][1]
        NoA = parameter_list["SCCP calling Nature of Addr"][1]
        Digits = parameter_list["SCCP calling Digits"][1]
        len_of_called_address_digits = len(Digits)
        GT = TT + Numbering_plan + NoA + Digits
        called_address = parameter_list["SCCP calling Address Indicator"][1] + parameter_list["SCCP calling SSN"][1] + GT
     
      len_of_called_address_digits = len(Digits)
      P_2_second_parameter = struct.pack("!b",4 + 3 + len_of_called_address_digits + 2 )

      ################################################
      # CgPA
      ################################################
      if map_type == "SRI-SM" or map_type == "MT-FSM":
        TT = chr(0x00)
        Numbering_plan = chr(0x12) ## even number of digits ..
        NoA = chr(0x04)
        Digits = PCA_GenLib.converStringToReverseBCD(self.sc_address)
       
        GT = TT + Numbering_plan + NoA + Digits
        address_indicator = chr(0x12)
        SSN = chr(0x08)
        calling_address = address_indicator + SSN + GT
     
        
      else:
        # prepare data for MO-FSM ack
        TT = parameter_list["SCCP called Translation Type"][1]
        Numbering_plan = parameter_list["SCCP called Numbering plan"][1]
        NoA = parameter_list["SCCP called Nature of Addr"][1]
        Digits = parameter_list["SCCP called Digits"][1]
        GT = TT + Numbering_plan + NoA + Digits
        calling_address = parameter_list["SCCP called Address Indicator"][1] + parameter_list["SCCP called SSN"][1] + GT

      len_of_calling_address_digits = len(Digits)

      P_2_third_parameter = struct.pack("!b",4 + 3 + len_of_called_address_digits + 2 + 5 +  len_of_calling_address_digits )       

      option_parameter = chr(0x00)

      tcap_message = self.TCAPMessage.getMessage(map_type,parameter_list_request)
      called_address_hex_length = struct.pack("!B",len(called_address))
      calling_address_hex_length = struct.pack("!B",len(calling_address))
      tcap_message_hex_length = struct.pack("!B",len(tcap_message))
      
      sccp_data = message_type +  Protocol_Class + hoop_counter + P_2_first_parameter + P_2_second_parameter + P_2_third_parameter + option_parameter + called_address_hex_length + called_address + calling_address_hex_length + calling_address + tcap_message_hex_length + tcap_message
      
      self.Message = sccp_data

      #Msg = "DEBUG SCCP = *\n%s\n*" % PCA_GenLib.HexDump(self.Message)
      #PCA_GenLib.WriteLog(Msg,0)
      return self.Message
    except:
     Msg = "getMessage Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	
	
	
	
