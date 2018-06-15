########################################################################################
#
# Filename:    PCA_TCAPParser.py
#  
# Description
# ===========
# 
#
# Author        : Michael Hsiao 
#
# Create Date   : 2016/09/24
# Desc          : Initial

########################################################################################

import sys,string,struct,time
import PCA_GenLib
import PCA_Parser
import PCA_XMLParser
import PCA_MAPParameters
import PCA_DLL
import smspdu  

###    Message Handler
##############################################################################
class Handler(PCA_Parser.ContentHandler):

  attrs = None
  tcap_otid = ''
  tcap_dtid = ''
  Message = ""
  MAP_Message = {}
  dup_tag = 0
  sri_resp_NNN = "000000000"
  sri_resp_imsi = "231011400000188f"
  NNN = ''
  imsi = ''
     
  def __init__(self,XMLCFG):
    PCA_Parser.ContentHandler.__init__(self)
    self.Message = {}
    Tag = "NNN"
    self.sri_resp_NNN = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
    
    Tag = "SRI_RESP_IMSI"
    self.sri_resp_imsi = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
    
  def startDocument(self):
       self.ExtraSocketData = ''
       self.IsApplicationMessage = 0
       self.Operation = chr(0x00)
       self.TID='na'
       self.Message = ''
       self.MAP_Message = {}
       self.dup_tag = 0
       self.opCode = ''

  def startElement(self, name, attrs):
    try:
      Msg = "startElement init"
      PCA_GenLib.WriteLog(Msg,9)
     
      name = "MAP %s" % name
      self.MessageName = name

      self.attrs = attrs
      if name == "version":
        self.version =  attrs
      if name == "otid":
        self.tcap_otid =  attrs

      Msg = "startElement OK"
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "startElement Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise


  def characters(self,content):
    try:
    
      Msg = "characters Init "
      PCA_GenLib.WriteLog(Msg,9)
      self.MAP_Message[self.MessageName] = (content,self.attrs)

      Msg = "%-20s=<%-25s>,Hex=%s" % (self.MessageName ,content,PCA_GenLib.HexDump(self.attrs))
      PCA_GenLib.WriteLog(Msg,3)
      Msg = "%s=%s" % (self.MessageName ,content)
      PCA_GenLib.WriteLog(Msg,1)
      if self.MessageName == "MAP opCode":
        self.opCode = content
      elif self.MessageName == "MAP imsi value":
        self.imsi = content
      elif self.MessageName == "MAP NNN value":
        self.NNN = content
    
     
      Msg = "characters OK"
      PCA_GenLib.WriteLog(Msg,9)

    except:
      Msg = "characters Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise


  def endDocument(self,data,debugstr):
    try:
    
      self.DebugStr = debugstr
      
    except:
      Msg = "startElement Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise
  

  def getHandlerResponse(self):	
    try:
        Msg = "getHandlerResponse Init "
        PCA_GenLib.WriteLog(Msg,9)

        MAP_Tag = chr(0xa2)
       
        noa = chr(0x91)
        
        
        nnn_bcd = PCA_GenLib.converStringToReverseBCD(self.sri_resp_NNN)
        tag = chr(0x81)
        tag_data = noa + nnn_bcd
        locationinfo_with_LMSI = self.constructTLV(tag,tag_data)

        tag = chr(0xa0)
        tag_data = locationinfo_with_LMSI
        location_data = self.constructTLV(tag,tag_data)

        digits = PCA_GenLib.converStringToReverseBCD(self.sri_resp_imsi)
        
     
        tag = chr(0x04)
        tag_data = digits 
        IMSI_data = self.constructTLV(tag,tag_data)

        tag = chr(0x30)
        tag_data = IMSI_data + location_data 
        recipient_info = self.constructTLV(tag,tag_data)      
      
        if self.opCode != "reportSM-DeliveryStatus":
          tag = chr(0x02)
          tag_data = chr(0x2d)
          opCode = self.constructTLV(tag,tag_data)
        else:
          tag = chr(0x02)
          tag_data = chr(0x2f)
          opCode = self.constructTLV(tag,tag_data)
        
        tag = chr(0x30)
        tag_data = opCode + recipient_info
        result_tretres = self.constructTLV(tag,tag_data)
         
        tag = chr(0x02)
        try:
          #tag_data = parameter_list["MAP invoke value"][1]
          tag_data = self.MAP_Message["MAP invoke_id"][1]
        except:
          tag_data = chr(0x7d)
        
        invoke_id = self.constructTLV(tag,tag_data)

        #reportSM-DeliveryStatus

        # If send SRI-Error 
    ##Unknown subscriber;
#- Call Barred;
#- Teleservice Not Provisioned;
#- Absent Subscriber_SM;
#- Facility Not Supported;
#- System failure;
#- Unexpected Data Value;
#- Data missing.


        tag = chr(0x02)
        #tag_data = chr(0x01) # 1 UNKNOWN_SUBSCRIBER - SMSC delete message
        #tag_data = chr(0x05) # 5 UNIDENTIFIED_SUBSCRIBER
        #tag_data = chr(0x06) # 6 ABSENT_SUBSCRIBER_SM
        #tag_data = chr(0x09) # 9 ILLEGAL_SUBSCRIBER - SMSC delete message
        #tag_data = chr(0x0b) # 11 TS_NOT_PROVISIONED  - SMSC delete message
        #tag_data = chr(0x0c) # 12 ILLEGAL_EQUIPMENT - SMSC delete message
        #tag_data = chr(0x0d) # 13 CALL_BARRED  - SMSC delete message
        #tag_data = chr(0x15) # 21 FACILITY_NOT_SUPPORTED
        #tag_data = chr(0x1b) # 27 ABSENT_SUBSCRIBER
        tag_data = chr(0x1f) # 31 SUBSCRIBER_BUSY_FOR_MT 
        #tag_data = chr(0x20) # 32 DELIVERY_FAILURE
        #tag_data = chr(0x22) # 34 SYSTEM_FAILURE
        #tag_data = chr(0x23) # 35 DATA_MISSING
        #tag_data = chr(0x24) # 36 UNEXPECTED_DATA_VALUE
   

        error_code = self.constructTLV(tag,tag_data)

        

        if self.opCode != "reportSM-DeliveryStatus":
          return_error_test = 0
          if return_error_test == 0:
            map_data = invoke_id + result_tretres
          else:
            MAP_Tag = chr(0xa3)
            map_data = invoke_id + error_code
        else:
          map_data = invoke_id

        message_length = len(map_data) 
        message_length_hex = struct.pack("!b",message_length)

        map_message = MAP_Tag + message_length_hex + map_data
        self.Message = map_message
        
        #Msg = "Sleep 20 seconds"
        #PCA_GenLib.WriteLog(Msg,1)        
        #time.sleep(20)
        
        Msg = "getHandlerResponse OK"
        PCA_GenLib.WriteLog(Msg,9)

        return self.Message

    except:
      Msg = "getHandlerResponse  error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise
 
#  def getSRI_SM_resp(self):
#       return (self.imsi,self.NNN)
#########################################################################
# 
#
#########################################################################
class Parser(PCA_Parser.Parser):
  DebugStr = ""
  ResponseCode = "NA"
  tag_index = 0
  app_context = 'na'
  invoke_id = 0
  Is_TCAP_begin = 0
  app_context = 'undef'

  def set_handler(self,name,attrs,content):
    self._cont_handler.startElement(name, attrs)        		
    self._cont_handler.characters(content)
    self._cont_handler.endElement(name)



  def parseTLV(self,data):
    try:
      Msg = "parseTLV Init "
      PCA_GenLib.WriteLog(Msg,9)

      source = data
      tlv_desc = 'na'
      tlv_type = 'na'
      name = 'na'
      number_of_tlv = 0
      
      Msg = "MAP shortMsgGateway SRI parseTLV data =\n%s" % PCA_GenLib.HexDump(source)
      PCA_GenLib.WriteLog(Msg,0)
      tag = ""
      
      while len(source) > 0:
        number_of_tlv = number_of_tlv + 1
        if number_of_tlv > 100:
          Msg = "number of TLV > 100 "
          PCA_GenLib.WriteLog(Msg,0)
          break
        
        self.tag_index = self.tag_index + 1
        name = "Tag"
        attrs = source[0]
        tag_desc = "na"
        try:
         
          tag_desc = PCA_MAPParameters.Tag_Desc[attrs]
          content = tag_desc
          if content == "invoke_id":
            if self.invoke_id == 1:
              tag_desc = "opCode"
              content = tag_desc   
              self.invoke_id = 2          
            else:
              self.invoke_id = 1             
          else:             
             content = tag_desc
        except:          
          content = "undef:%s" % PCA_GenLib.getHexString(attrs)

        #tag = content
        #tag = "%s:%s" % (content,PCA_GenLib.getHexString(attrs))
        tag = "%s" % content
        
        #self.set_handler(name,chr(0x00),content)
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

        tag_class = ord(attrs) & 0xc0
        tag_class = tag_class >> 6
        Tag_Type = 'Primitive'
        if (ord(attrs) & 0x20):          
          attrs = source[0:2]
          content = PCA_GenLib.getHexString(attrs)
          Tag_Type = 'Constructor'
        else:
          
          content = ord(attrs)
          Tag_Type = 'Primitive'

        name = "tag type"
        content = Tag_Type
        

        Tag_form = "Extended format"
        if (ord(source[0]) & 0x1f) == 0x1f:
          Tag_form = "Extended format"
          source = source[2:]
          #source = source[1:]
        else:
          Tag_form = "One octet format"
          source = source[1:]
        name = "tag form"
        content = Tag_form
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
          
         
        name = "length"
        name = "%s length" % tag
        attrs = source[0]
        content = ord(attrs)  
        tag_length_form = "short"
        if content & 0x80:
           tag_length_form = "long"
           long_tag_length = chr(content & 0x7F) + source[1]
           content = struct.unpack("!H",long_tag_length)[0]
           tag_length = content
          
        else:
           tag_length_form = "short"
           content = struct.unpack("!B",attrs)[0]
           tag_length = content
           
        #self.set_handler(name,attrs,content)
        name = "%s %s" % (tag_length_form,name)
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
        
        if tag_length_form == "short":
          source = source[1:]
        else:
          source = source[2:]

        name = "value"
        name = "%s value" % tag
       

        attrs = source[0:tag_length]

        # OpCode
        if self.invoke_id == 2 and tag_desc == "opCode":
          content = ord(attrs)
          content = PCA_MAPParameters.op_code[content]
        elif tag_desc == "Originator_address" or tag_desc == "SC_Address" or tag_desc == "msisdn":
          TOA = PCA_GenLib.getHexString(attrs[0])
          content = PCA_GenLib.getHexBCDString(attrs[1:])
          content = "%s:%s" % (TOA,content)
        else:
         content = PCA_GenLib.getHexString(attrs)
        
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
        #self.set_handler(tag,attrs,content)
       
        if Tag_Type == 'Constructor':
           self.parseTLV(attrs)
           # DEBUG ONLY
           self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
           self.set_handler(tag,attrs,content)

        #elif tag_desc == "SM_RP_UI" :
           
        #   if self.Is_TCAP_begin == 1:
        #     self.parseGSM0340_request(attrs)
        #   else:
        #     if self.app_context == "shortMsgGateway_SRI_v3":
        #       # SRI response 
        #       self.parseGSM0340_SRI_SM_response(attrs)
        #     else:
        #       self.parseGSM0340_response(attrs)
        else:
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
          self.set_handler(tag,attrs,content)
        
        try:
          source = source[tag_length:]
        except IndexError:
          Msg = "parseTLV index error : <%s>,<%s>,name=<%s> " % (sys.exc_type,sys.exc_value,name)
          PCA_GenLib.WriteLog(Msg,0)
          break


      Msg = "parseTLV Ok "
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "parseTLV error : <%s>,<%s>,name=<%s> " % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,0)
      #Msg = "dump source data =<\n%s\n>" % PCA_GenLib.HexDump(source)
      #PCA_GenLib.WriteLog(Msg,0)


        
  def parse(self, source,Is_TCAP_begin,app_context):
    try:
      Msg = "parser init"
      PCA_GenLib.WriteLog(Msg,9)	
      orig_data = source
      name = 'none'	
      self.StartParsing = 0
      TID = "na"
      content = "na"

      Msg = "MAP SRI-SM data =<\n%s\n>" % PCA_GenLib.HexDump(source)
      PCA_GenLib.WriteLog(Msg,3)

      if (source != None)  : 
        self._cont_handler.startDocument()
        self.StartParsing = 1
        
      
        self.DebugStr = ""  
        name = "MAP Tag"
        attrs = source[0]
        Tag_Type = 'Primitive'
        if (ord(attrs) & 0x40):
            name = "%s-Constructor" % name
            attrs = source[0:2]
            content = PCA_GenLib.getHexString(attrs)
        else:
            name = "%s-Primitive" % name
            content = ord(attrs)
            self.set_handler(name,attrs,content)
        
        if Tag_Type == 'Primitive':
            source = source[1:]
        else:
            source = source[2:]

        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
        name = "length"
        attrs = source[0]
        content = ord(attrs)
        tag_length = content
        self.set_handler(name,attrs,content)
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

        source = source[1:]
        name = "value"
        attrs = source[0:tag_length]
        content = PCA_GenLib.getHexString(attrs)
        self.set_handler(name,attrs,content)
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
        
        
        #self.parseTLV(attrs)
        source = attrs
        name = "invoke"
        tag_name = name
        attrs = source[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        source = source[1:]
        name = "length"
        attrs = source[0]
        content = ord(attrs)
        tag_length = content
        self.set_handler(name,attrs,content)
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

        source = source[1:]
        #name = "invoke value"
        name = "invoke_id"
        attrs = source[0]
        content = ord(attrs)
        tag_value = content
        self.set_handler(name,attrs,content)
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)


        Msg = "MAP SRI-SM Is_TCAP_begin = <%s>" % Is_TCAP_begin
        PCA_GenLib.WriteLog(Msg,3)

        # SRI request
        if Is_TCAP_begin == 1:
          Msg = "MAP SRI-SM DEBUG data begin =<\n%s\n>" % PCA_GenLib.HexDump(source)
          PCA_GenLib.WriteLog(Msg,3)
          source = source[1:]
          name = "opCode"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)


          source = source[1:]
          name = "opCode length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content
          self.set_handler(name,attrs,content)

          source = source[1:]
          name = "opCode"
          attrs = source[0]
          content = ord(attrs)

          op_code = 'na'
          try:
            tag_value = PCA_MAPParameters.op_code[content]
            op_code = tag_value
            #Msg = "MAP opcode = <%s>" % tag_value
            #PCA_GenLib.WriteLog(Msg,1)
          except:
            Msg = "unknow opCode Value = %s" % content
            PCA_GenLib.WriteLog(Msg,0)
          
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)


          
          source = source[1:]
          name = "msisdn tag"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)

          source = source[1:]
          name = "msisdn tag length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content
          #self.set_handler(name,attrs,content)

          source = source[1:]
          name = "msisdn tag value"
          attrs = source[0:tag_length]	
          tag_value = PCA_GenLib.getHexString(attrs)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)

        
          source = attrs
          name = "msisdn"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)

          source = source[1:]
          name = "length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content
          
          source = source[1:]
          name = "msisdn value"        
          attrs = source[1:tag_length]
          tag_value = PCA_GenLib.getHexBCDString(attrs)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)
          source = source[tag_length:]
          if op_code != "reportSM-DeliveryStatus":
            
            name = "Priority Flag"
            tag_name = name
            attrs = source[0]
            content = ord(attrs)

            source = source[1:]
            name = "length"
            attrs = source[0]
            content = ord(attrs)
            tag_length = content

            source = source[1:]
            name = "Priority Flag value"        
            attrs = source[0:tag_length]
            tag_value = PCA_GenLib.getHexString(attrs)
            self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
            self.set_handler(name,attrs,tag_value)
            source = source[1:]
        
           
          name = "sc-address"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)

          source = source[1:]
          name = "sc-address length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content
          
          source = source[1:]
          name = "sc-address value"        
          attrs = source[1:tag_length]
          tag_value = PCA_GenLib.getHexBCDString(attrs)
          Msg = "sc_address = <%s>" % tag_value
          PCA_GenLib.WriteLog(Msg,3)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)

          source = source[tag_length:]
          if op_code == "reportSM-DeliveryStatus":
            name = "sm-DeliveryOutcom"            
            attrs = source[2]
            content = ord(attrs)
            self.set_handler(name,attrs,content)
            Msg = "name = %s , value = %s" % (name,content)
            PCA_GenLib.WriteLog(Msg,3)
            
        else: 
          # SRI response
          Msg = "MAP SRI-SM DEBUG data end =<\n%s\n>" % PCA_GenLib.HexDump(source)
          PCA_GenLib.WriteLog(Msg,3)
          source = source[1:]
          name = "resultretres"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)

          source = source[1:]
          name = "length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content

          source = source[1:]
          name = "resultretres value"
          attrs = source[0:tag_length]

          source = attrs
          name = "opCode"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)

          source = source[1:]
          name = "length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content

          source = source[1:]
          name = "opCode"
          attrs = source[0]
          content = ord(attrs)
          try:
            tag_value = PCA_MAPParameters.op_code[content]
          except:
            Msg = "unknow opCode Value = %s" % content
            PCA_GenLib.WriteLog(Msg,0)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)

          source = source[1:]
          name = "sm-rp-UI"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)

          source = source[1:]
          name = "length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content
          #self.set_handler(name,attrs,content)

          source = source[1:]
          name = "sm-rp-UI value"
          attrs = source[0:tag_length]	
          tag_value = PCA_GenLib.getHexString(attrs)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)

        
          source = attrs
          name = "imsi"
          tag_name = name 
          attrs = source[0]
          content = ord(attrs)

          source = source[1:]
          name = "length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content

          source = source[1:]
          name = "imsi value"        
          attrs = source[0:tag_length]
          tag_value = PCA_GenLib.getHexIMSIString(attrs)[0:15]
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)

          source = source[tag_length:]
          name = "location-info-with-LMSI"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)

          source = source[1:]
          name = "length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content

          source = source[1:]
          name = "location-info-with-LMSI value"        
          attrs = source[0:tag_length]
          tag_value = PCA_GenLib.getHexString(attrs)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)

          source = attrs
          name = "NNN"
          tag_name = name
          attrs = source[0]
          content = ord(attrs)

          source = source[1:]
          name = "length"
          attrs = source[0]
          content = ord(attrs)
          tag_length = content

          source = source[1:]
          name = "NNN value"        
          attrs = source[1:tag_length]        
          #tag_value = PCA_GenLib.getHexString(attrs)
          tag_value = PCA_GenLib.getHexBCDString(attrs)
          self.set_handler(name,tag_value,tag_value)

        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
        #self.set_handler(name,attrs,tag_value)

        #source = source[1:]
        #name = "location GT"        
        #attrs = source      
        #content = PCA_GenLib.getHexBCDString(attrs)
        #self.set_handler(name,attrs,content)

        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)

      if self.StartParsing == 1:
        self._cont_handler.endDocument(orig_data,self.DebugStr)
        
      Msg = "parser OK"
      PCA_GenLib.WriteLog(Msg,9)
    
    except:
      Msg = "parser  :<%s>,<%s>,name=<%s>" % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,2)
      Msg = "orig data =\n%s" % PCA_GenLib.HexDump(orig_data)
      PCA_GenLib.WriteLog(Msg,2)
      self.set_handler("opCode","sendRoutingInfoForSM","sendRoutingInfoForSM")
      #raise
        
        
