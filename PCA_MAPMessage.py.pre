#!/usr/bin/python

########################################################################################
#
# Filename:    PCA_TCAPMessage.py
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

import sys,string,time
import PCA_GenLib,struct
import PCA_XMLParser
import PCA_MAPParameters

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
	
  ########################################################
  ##
  ########################################################
			
  def constructTLV(self,tag,tag_data):
    try:
       tag_length = struct.pack("!b",len(tag_data))
       tlv = tag + tag_length + tag_data
       return tlv	
    except:
      Msg = "constructTLV Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise
   ########################################################################
  # Return Message
  #
  #########################################################################
  def getMessage_ok(self):
    try:	
      MAP_Tag = chr(0x6c)

      tp_udhi = chr(0x00)
      tp_parameter_indicator = chr(0x01)
      tp_date = chr(0x61) + chr(0x01) + chr(0x10)
      tp_time = chr(0x11) + chr(0x01) + chr(0x10)
      tp_zone = chr(0x23)
      tp_sc_timestamp = tp_date + tp_time + tp_zone
      sms_pdu = tp_udhi + tp_parameter_indicator + tp_sc_timestamp

      tag = chr(0x30)
      tag_data = sms_pdu 
      un_def_1 = self.constructTLV(tag,tag_data)

      tag = chr(0x04)
      tag_data = un_def_1
      sm_rp_UI = self.constructTLV(tag,tag_data)

      tag = chr(0x02)
      tag_data = struct.pack("!b",PCA_MAPParameters.mo_ForwardSM)
      opCode = self.constructTLV(tag,tag_data)


      tag = chr(0x30)
      tag_data = opCode +  sm_rp_UI
      result_retres = self.constructTLV(tag,tag_data)


      tag = chr(0x02)
      tag_data = chr(0x00) 
      Invoke_Id = self.constructTLV(tag,tag_data)

      return_result_last = Invoke_Id + result_retres
      tag = chr(0xa2)
      tag_data = return_result_last 
      map_data = self.constructTLV(tag,tag_data)

      message_length = len(map_data) 
      message_length_hex = struct.pack("!b",message_length)

      map_message = MAP_Tag + message_length_hex + map_data
      self.Message = map_message

      #Msg = "DEBUG SCCP = *\n%s\n*" % PCA_GenLib.HexDump(self.Message)
      #PCA_GenLib.WriteLog(Msg,0)
      return self.Message
    except:
     Msg = "getMessage Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	
	
  ########################################################################
  # Return Message Error
  #
  #########################################################################
  def getMessageError(self):
    try:	
      MAP_Tag = chr(0xa3) # Error Tag

      tag = chr(0x02)
      tag_data = chr(0x24) 
      error_code = self.constructTLV(tag,tag_data)

      
      tag = chr(0x02)
      tag_data = chr(0x02)
      invoke_id = self.constructTLV(tag,tag_data)
 
      map_data = invoke_id + error_code

      message_length = len(map_data) 
      message_length_hex = struct.pack("!b",message_length)

      map_message = MAP_Tag + message_length_hex + map_data
      self.Message = map_message

      #Msg = "DEBUG MAP = *\n%s\n*" % PCA_GenLib.HexDump(self.Message)
      #PCA_GenLib.WriteLog(Msg,0)
      return self.Message
    except:
     Msg = "getMessage Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	
	
  ########################################################################
  # Return Message
  #
  #########################################################################
  def getMessage(self,map_type,parameter_list):
    try:	
      
      MAP_Tag = chr(0xa2)
      #if parameter_list["TCAP oid 1"][0] == "shortMsgMO_Relay_v3":
      if map_type == "MO-FSM-Ack":
        Msg = "construct MAP_MO_FSM Ack"
        PCA_GenLib.WriteLog(Msg,2)
        MAP_Tag = chr(0xa2)
        udhi = chr(0x01)



        tp_parameter_indicator = chr(0x00)
        

        CurrentSeconds = time.time()	
	date_tuple =  time.localtime(CurrentSeconds)		
	
	YY = "%04d" % date_tuple[0]
        YY = YY[2:4]
        MM = "%02d" % date_tuple[1]
        DD = "%02d" % date_tuple[2]
        HH = "%02d" % date_tuple[3]
        MI = "%02d" % date_tuple[4]
        SS = "%02d" % date_tuple[5]



        YYYYMMDD1 = YY + MM + DD
        YYYYMMDD = PCA_GenLib.converStringToReverseBCD(YYYYMMDD1)

        HHMISS1 = HH + MI + SS
        HHMISS = PCA_GenLib.converStringToReverseBCD(HHMISS1)
       


        TimeZone = chr(0x23)
        tp_sc_timestamp = YYYYMMDD + HHMISS + TimeZone
        SM_RP_UI_data_parameter = udhi + tp_parameter_indicator + tp_sc_timestamp


        
        tag = chr(0x04)
        tag_data = SM_RP_UI_data_parameter 
        SM_RP_UI_data = self.constructTLV(tag,tag_data)

        tag = chr(0x30)
        tag_data = SM_RP_UI_data
        SM_RP_UI = self.constructTLV(tag,tag_data)

        tag = chr(0x02)
        tag_data = parameter_list["MAP opCode"][1]
        opCode = self.constructTLV(tag,tag_data)


        tag = chr(0x30)
        tag_data = opCode + SM_RP_UI
        result_tretres = self.constructTLV(tag,tag_data)

        tag = chr(0x02)
        tag_data = chr(0x02)
        invoke_id = self.constructTLV(tag,tag_data)
 
        map_data = invoke_id + result_tretres
      elif map_type == "SRI-SM":
        Msg = "construct SRI-SM request"
        PCA_GenLib.WriteLog(Msg,2)
        MAP_Tag = chr(0xa1)
       
        noa = chr(0x91)
        #digits = chr(0x88)+chr(0x96)+chr(0x62)+chr(0x05)+chr(0x40)+chr(0x00)
        digits = PCA_GenLib.converStringToReverseBCD(self.sc_address)
        tag = chr(0x82)
        tag_data = noa + digits 
        sc_address = self.constructTLV(tag,tag_data)

        tag = chr(0x81)
        tag_data = chr(0x01)
        SM_RP_PRI = self.constructTLV(tag,tag_data)
        
        noa = chr(0x91)
       
        digits = PCA_GenLib.converStringToReverseBCD(parameter_list["recipient"])
        tag = chr(0x80)
        tag_data = noa + digits 
        msisdn = self.constructTLV(tag,tag_data)
        
        tag = chr(0x30)
        tag_data = msisdn + SM_RP_PRI + sc_address 
        address_info = self.constructTLV(tag,tag_data)

       
        tag = chr(0x02)
        tag_data = chr(0x2d)
        opCode = self.constructTLV(tag,tag_data)

          
        tag = chr(0x02)
        tag_data = chr(0x02)
        invoke_id = self.constructTLV(tag,tag_data)
        map_data = invoke_id + opCode + address_info

      elif map_type == "MT-FSM":
        Msg = "construct MT-FSM request"
        PCA_GenLib.WriteLog(Msg,2)
        MAP_Tag = chr(0xa1)
       
       
        TP_RP = chr(0x04)
        
        digits = PCA_GenLib.converStringToReverseBCD(parameter_list["originator"])
        address_len = struct.pack("!B",len(digits)*2)
        toa = chr(0x91)
        TP_OA = address_len + toa + digits
        TP_PID = chr(0x00)
        TP_DCS = chr(0x00)
         
         

        CurrentSeconds = time.time()	
	date_tuple =  time.localtime(CurrentSeconds)		
	
	YY = "%04d" % date_tuple[0]
        YY = YY[2:4]
        MM = "%02d" % date_tuple[1]
        DD = "%02d" % date_tuple[2]
        HH = "%02d" % date_tuple[3]
        MI = "%02d" % date_tuple[4]
        SS = "%02d" % date_tuple[5]



        YYYYMMDD1 = YY + MM + DD
        YYYYMMDD = PCA_GenLib.converStringToReverseBCD(YYYYMMDD1)

        HHMISS1 = HH + MI + SS
        HHMISS = PCA_GenLib.converStringToReverseBCD(HHMISS1)
        TP_SC_timestamp = YYYYMMDD + HHMISS  + chr(0x23)
        
        #TP_user_data = "abc123"
        #Msg = "##############################################################"
        #PCA_GenLib.WriteLog(Msg,1)
        #for key in sorted(parameter_list):           
         #    Msg = "<%s>=<%s>,hex=<%s>*" % (key,parameter_list[key][0],PCA_GenLib.getHexString(parameter_list[key][1]))
         #    PCA_GenLib.WriteLog(Msg,3)
            

        TP_user_data = parameter_list["sms_text"]
        
        TP_user_data_length = struct.pack("!B",len(TP_user_data))

        tag = chr(0x04)
        tag_data = TP_RP + TP_OA + TP_PID + TP_DCS + TP_SC_timestamp + TP_user_data_length + TP_user_data
        SM_RP_PRI = self.constructTLV(tag,tag_data)

        noa = chr(0x91)
        digits = PCA_GenLib.converStringToReverseBCD(self.sc_address)
        tag = chr(0x84)
        tag_data = noa + digits 
        sc_address = self.constructTLV(tag,tag_data)

        
        #noa = chr(0x91)
        digits = PCA_GenLib.converStringToReverseBCD(parameter_list["recipient_imsi"])
        tag = chr(0x80)
        #tag_data = noa + digits 
        tag_data = digits 
        imsi = self.constructTLV(tag,tag_data)
        
        tag = chr(0x30)
        tag_data = imsi + sc_address  + SM_RP_PRI 
        address_info = self.constructTLV(tag,tag_data)

       
        tag = chr(0x02)
        tag_data = chr(0x2c)
        opCode = self.constructTLV(tag,tag_data)

          
        tag = chr(0x02)
        tag_data = chr(0x02)
        invoke_id = self.constructTLV(tag,tag_data)
        map_data = invoke_id + opCode + address_info

      else:
        MAP_Tag = chr(0xa3)
        tag = chr(0x02)
        tag_data = chr(0x24) 
        result_tretres = self.constructTLV(tag,tag_data)

        tag = chr(0x02)
        tag_data = chr(0x02)
        invoke_id = self.constructTLV(tag,tag_data)
 
        map_data = invoke_id + result_tretres

      message_length = len(map_data) 
      message_length_hex = struct.pack("!b",message_length)

      map_message = MAP_Tag + message_length_hex + map_data
      self.Message = map_message

      #Msg = "DEBUG MAP = *\n%s\n*" % PCA_GenLib.HexDump(self.Message)
      #PCA_GenLib.WriteLog(Msg,0)
      return self.Message
    except:
     Msg = "getMessage Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	
		
	
