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

import sys,string,random
import PCA_GenLib,struct
import PCA_XMLParser
import PCA_TCAPParameters
import PCA_MAPMessage
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
  tcap_tid = int(random.random()*10000)
      
  def __init__(self,XMLCFG):
    try:
      Msg = "Writer Init "
      PCA_GenLib.WriteLog(Msg,9)
	
      self.MAPMessage = PCA_MAPMessage.Writer(XMLCFG)
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
  # Return Error Message
  #
  #########################################################################
  def getMessageError(self):
    try:	

     
      #

      #<TCAP tcap_begin:62>=<4804010000006b1a281806  ......
      #    <TCAP Originating TID:48>=<01000000>*

      #  <TCAP dialog_portion:6b>=<2818060700118605010101a00d600ba109060704000001001503>*
      #    
      #    <TCAP external_tag:28>=<060700118605010101a00d600ba109060704000001001503>*    
      #       <TCAP oid:06>=<00118605010101>*
 
      #       <TCAP Single_ASN1_Type:a0>=<600ba109060704000001001503>*
      #         <TCAP dialog_request:60>=<a109060704000001001503>*
      #           <TCAP Application_Context:a1>=<060704000001001503>*
      #             <TCAP Application_Context_name:06 >=<04000001001503>*

      # <MAP component_type_invoke:a1>=<0201020.......82009099041411000c918896820000200000020661f138269b01>
      # <MAP invoke_id:02>=<02>
      # <MAP opCode:02>=<mo-ForwardSM>


      
      ###############################################
      # Transaction Portion 
      ###############################################
      tag = chr(0x49)
      tag_data = chr(0x94)+chr(0x00)+chr(0x00)+chr(0x00)
      transaction_portion = self.constructTLV(tag,tag_data)



      ###############################################
      # Dialog Portion 
      ###############################################


      Application_Context_name = chr(0x04) + chr(0x00)+ chr(0x00) + chr(0x01) + chr(0x00)+ chr(0x15) + chr(0x03)
      Application_Context_name_Tag = chr(0x06)
      Application_Context = self.constructTLV(Application_Context_name_Tag,Application_Context_name)
      Application_Context_Tag = chr(0xa1)
      Application_Context_TLV = self.constructTLV(Application_Context_Tag,Application_Context)


      app_result_user_diag_tag = chr(0x02)
      app_result_user_diag_value = chr(0x00)
      app_result_user_diag = self.constructTLV(app_result_user_diag_tag,app_result_user_diag_value)
      
      result_user_diag_tag = chr(0xa1)
      result_user_diag_TLV = self.constructTLV(result_user_diag_tag,app_result_user_diag)
      result_source_diag_tag = chr(0xa3)
      result_source_diag_TLV = self.constructTLV(result_source_diag_tag,result_user_diag_TLV)


      app_result_tag = chr(0x02)
      app_result_value = chr(0x00)
      app_result = self.constructTLV(app_result_tag,app_result_value)
      result_tag = chr(0xa2)
      result_TLV = self.constructTLV(result_tag,app_result)

      
      #dialog_response = self.constructTLV(Application_Context_Tag,Application_Context)
      dialog_response = Application_Context_TLV+result_TLV+result_source_diag_TLV
      dialog_response_tag = chr(0x61)
      dialog_response_TLV = self.constructTLV(dialog_response_tag,dialog_response)
      
      #Single_ASN1 = self.constructTLV(dialog_response_tag,dialog_response) 
      Single_ASN1_Tag = chr(0xa0)
      Single_ASN1_TLV = self.constructTLV(Single_ASN1_Tag,dialog_response_TLV) 

      oid_tag = chr(0x06)
      oid_data = chr(0x00)+chr(0x11) + chr(0x86)+ chr(0x05) + chr(0x01)+ chr(0x01)+chr(0x01)
      oid_tlv = self.constructTLV(oid_tag,oid_data)
      

      tcap_external = oid_tlv + Single_ASN1_TLV

      tcap_external_tag = chr(0x28)     
      tcap_external_tlv = self.constructTLV(tcap_external_tag,tcap_external)
      
      dialog_portion_tag = chr(0x6b)     
      dialog_portion = self.constructTLV(dialog_portion_tag,tcap_external_tlv)

      
      
      ###############################################
      # Component Portion -- MAP
      ###############################################
      tag = chr(0x6c)
      tag_data = self.MAPMessage.getMessage()
      component_portion = self.constructTLV(tag,tag_data)
     
      tcap_data = transaction_portion  +  dialog_portion + component_portion


      message_length = len(tcap_data) 
      message_length_hex = struct.pack("!B",message_length)

      TCAP_Tag = chr(0x64)
      tcap_message = TCAP_Tag + message_length_hex + tcap_data
      self.Message = tcap_message

      Msg = "DEBUG TCAP = *\n%s\n*" % PCA_GenLib.HexDump(self.Message)
      PCA_GenLib.WriteLog(Msg,3)
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

     
      #

      #<TCAP tcap_begin:62>=<4804010000006b1a281806  ......
      #    <TCAP Originating TID:48>=<01000000>*

      #  <TCAP dialog_portion:6b>=<2818060700118605010101a00d600ba109060704000001001503>*
      #    
      #    <TCAP external_tag:28>=<060700118605010101a00d600ba109060704000001001503>*    
      #       <TCAP oid:06>=<00118605010101>*
 
      #       <TCAP Single_ASN1_Type:a0>=<600ba109060704000001001503>*
      #         <TCAP dialog_request:60>=<a109060704000001001503>*
      #           <TCAP Application_Context:a1>=<060704000001001503>*
      #             <TCAP Application_Context_name:06 >=<04000001001503>*

      # <MAP component_type_invoke:a1>=<0201020.......82009099041411000c918896820000200000020661f138269b01>
      # <MAP invoke_id:02>=<02>
      # <MAP opCode:02>=<mo-ForwardSM>

      if map_type == "MO-FSM-Ack":
        TCAP_Tag = chr(0x64)
        ###############################################
        # Transaction Portion 
        ###############################################
        tag = chr(0x49)
        tag_data = parameter_list["TCAP Originating TID"][1]
        transaction_portion = self.constructTLV(tag,tag_data)
        ###############################################
        # Dialog Portion 
        ###############################################

        Application_Context_name = parameter_list["TCAP oid 1"][1]
        Application_Context_name_Tag = chr(0x06)
        Application_Context = self.constructTLV(Application_Context_name_Tag,Application_Context_name)
        Application_Context_Tag = chr(0xa1)
        Application_Context_TLV = self.constructTLV(Application_Context_Tag,Application_Context)


        app_result_user_diag_tag = chr(0x02)
        app_result_user_diag_value = chr(0x00)
        app_result_user_diag = self.constructTLV(app_result_user_diag_tag,app_result_user_diag_value)
      
        result_user_diag_tag = chr(0xa1)
        result_user_diag_TLV = self.constructTLV(result_user_diag_tag,app_result_user_diag)
        result_source_diag_tag = chr(0xa3)
        result_source_diag_TLV = self.constructTLV(result_source_diag_tag,result_user_diag_TLV)

        app_result_tag = chr(0x02)
        app_result_value = chr(0x00)
        app_result = self.constructTLV(app_result_tag,app_result_value)
        result_tag = chr(0xa2)
        result_TLV = self.constructTLV(result_tag,app_result)

      
        #dialog_response = self.constructTLV(Application_Context_Tag,Application_Context)
        dialog_response = Application_Context_TLV+result_TLV+result_source_diag_TLV
        dialog_response_tag = chr(0x61)
        dialog_response_TLV = self.constructTLV(dialog_response_tag,dialog_response)
      
        #Single_ASN1 = self.constructTLV(dialog_response_tag,dialog_response) 
        Single_ASN1_Tag = chr(0xa0)
        Single_ASN1_TLV = self.constructTLV(Single_ASN1_Tag,dialog_response_TLV) 

        oid_tag = chr(0x06)
        oid_data = parameter_list["TCAP oid"][1]
        oid_tlv = self.constructTLV(oid_tag,oid_data)
      

        tcap_external = oid_tlv + Single_ASN1_TLV

        tcap_external_tag = chr(0x28)     
        tcap_external_tlv = self.constructTLV(tcap_external_tag,tcap_external)
      
        dialog_portion_tag = chr(0x6b)     
        dialog_portion = self.constructTLV(dialog_portion_tag,tcap_external_tlv)
      elif map_type == "SRI-SM":
        TCAP_Tag = chr(0x62)
        ###############################################
        # Transaction Portion 
        ###############################################
        tag = chr(0x48)
        tag_data = struct.pack("!I",self.tcap_tid)
        self.tcap_tid = self.tcap_tid + 1
        transaction_portion = self.constructTLV(tag,tag_data)
        ###############################################
        # Dialog Portion 
        ###############################################

        Application_Context_name = chr(0x04)+chr(0x00)+chr(0x00)+chr(0x01)+chr(0x00)+chr(0x14)+chr(0x03)
        Application_Context_name_Tag = chr(0x06)
        Application_Context = self.constructTLV(Application_Context_name_Tag,Application_Context_name)
        Application_Context_Tag = chr(0xa1)
        Application_Context_TLV = self.constructTLV(Application_Context_Tag,Application_Context)

        
        dialog_request = Application_Context_TLV
        dialog_request_tag = chr(0x60)
        dialog_request_TLV = self.constructTLV(dialog_request_tag,dialog_request)
      
       
        Single_ASN1_Tag = chr(0xa0)
        Single_ASN1_TLV = self.constructTLV(Single_ASN1_Tag,dialog_request_TLV) 

        oid_tag = chr(0x06)
        oid_data = chr(0x00)+chr(0x11)+chr(0x86)+chr(0x05)+chr(0x01)+chr(0x01)+chr(0x01)
        oid_tlv = self.constructTLV(oid_tag,oid_data)
      

        tcap_external = oid_tlv + Single_ASN1_TLV

        tcap_external_tag = chr(0x28)     
        tcap_external_tlv = self.constructTLV(tcap_external_tag,tcap_external)
      
        dialog_portion_tag = chr(0x6b)     
        dialog_portion = self.constructTLV(dialog_portion_tag,tcap_external_tlv)
      
      elif map_type == "MT-FSM":
        TCAP_Tag = chr(0x62)
        ###############################################
        # Transaction Portion 
        ###############################################
        tag = chr(0x48)
        tag_data = struct.pack("!I",self.tcap_tid)
        self.tcap_tid = self.tcap_tid + 1
        transaction_portion = self.constructTLV(tag,tag_data)
        ###############################################
        # Dialog Portion 
        ###############################################

        Application_Context_name = chr(0x04)+chr(0x00)+chr(0x00)+chr(0x01)+chr(0x00)+chr(0x19)+chr(0x03)
        Application_Context_name_Tag = chr(0x06)
        Application_Context = self.constructTLV(Application_Context_name_Tag,Application_Context_name)
        Application_Context_Tag = chr(0xa1)
        Application_Context_TLV = self.constructTLV(Application_Context_Tag,Application_Context)

        
        dialog_request = Application_Context_TLV
        dialog_request_tag = chr(0x60)
        dialog_request_TLV = self.constructTLV(dialog_request_tag,dialog_request)
      
       
        Single_ASN1_Tag = chr(0xa0)
        Single_ASN1_TLV = self.constructTLV(Single_ASN1_Tag,dialog_request_TLV) 

        oid_tag = chr(0x06)
        oid_data = chr(0x00)+chr(0x11)+chr(0x86)+chr(0x05)+chr(0x01)+chr(0x01)+chr(0x01)
        oid_tlv = self.constructTLV(oid_tag,oid_data)
      

        tcap_external = oid_tlv + Single_ASN1_TLV

        tcap_external_tag = chr(0x28)     
        tcap_external_tlv = self.constructTLV(tcap_external_tag,tcap_external)
      
        dialog_portion_tag = chr(0x6b)     
        dialog_portion = self.constructTLV(dialog_portion_tag,tcap_external_tlv)
      else:
        Msg = "unknow map_type = %s" % map_type
        PCA_GenLib.WriteLog(Msg,1)
 
      ###############################################
      # Component Portion -- MAP
      ###############################################
      tag = chr(0x6c)
      tag_data = self.MAPMessage.getMessage(map_type,parameter_list)
      component_portion = self.constructTLV(tag,tag_data)
     
      tcap_data = transaction_portion  +  dialog_portion + component_portion


      message_length = len(tcap_data) 
      message_length_hex = struct.pack("!B",message_length)

      
      tcap_message = TCAP_Tag + message_length_hex + tcap_data
      self.Message = tcap_message

      Msg = "DEBUG TCAP = *\n%s\n*" % PCA_GenLib.HexDump(self.Message)
      PCA_GenLib.WriteLog(Msg,3)
      return self.Message
    except:
     Msg = "getMessage Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	

		
