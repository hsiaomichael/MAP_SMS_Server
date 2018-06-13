########################################################################################
#
# Filename:    PCA_M3UAResponseParser.py
#  
# Description
# ===========
# 
#
# Author        : Michael Hsiao 
#
# Create Date   : 2016/12/01
# Desc          : Initial

########################################################################################

import sys,string,struct
import PCA_GenLib
import PCA_Parser
import PCA_XMLParser
import PCA_M3UAParameters
import PCA_SCCPParser
import PCA_M3UAMessage
  
##############################################################################
###    Message Handler   	
##############################################################################
class Handler(PCA_Parser.ContentHandler):	
	
  attrs = None	
  tcap_otid = ''
  tcap_dtid = ''
  Message = None
  SLS = chr(0x04)
  SI = chr(0x03)
  NI = chr(0x02)
  MP = chr(0x00)
  protocol_data_tag = chr(0x02)+chr(0x10)
  MessageName = ''
  TID = ''
  
  def __init__(self,XMLCFG):
    PCA_Parser.ContentHandler.__init__(self)
    self.Message = None
    self.M3UAMessage = PCA_M3UAMessage.Writer(XMLCFG)
    self.XMLCFG = XMLCFG
    Tag = "OPC"
    self.opc = struct.pack("!i",string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)))
    Tag = "DPC"
    self.dpc = struct.pack("!i",string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)))
    Tag = "NI"
    self.NI = struct.pack("!B",string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)))


    Tag = "ROUTING_CONTEXT"
    self.routing_context = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))

    version = PCA_M3UAParameters.version
    reserve = PCA_M3UAParameters.reserve
    message_class = PCA_M3UAParameters.Transfer_Messages
    message_type = PCA_M3UAParameters.DATA
    self.M3UA_header = version + reserve + message_class + message_type
	  
    Tag = PCA_M3UAParameters.Routing_Context_Tag
    Length = struct.pack("!H",8)
    Data = struct.pack("!i",self.routing_context)
    self.Routing_context = Tag + Length + Data
    self.Traffic_Type = "IN"

	
  def startDocument(self):
       self.ExtraSocketData = ''
       self.IsApplicationMessage = 0
       self.Operation = chr(0x00)
       self.TID='na'
       self.Message = None
       self.SCCP_DebugStr = ''
       
	
  def startElement(self, name, attrs):
    try:
      Msg = "startElement init"
      PCA_GenLib.WriteLog(Msg,9)
      self.MessageName = name
      self.attrs = attrs
      #self.Message[name] = attrs
      if name == "version":			
        self.version =  attrs

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

      Msg = "%-15s=<%-25s>,Hex=%s" % (self.MessageName ,content,PCA_GenLib.HexDump(self.attrs))
      #Msg = "<%s>=<%s>,Hex=%s" % (self.MessageName ,content,PCA_GenLib.HexDump(self.attrs))
      PCA_GenLib.WriteLog(Msg,3)
      if self.MessageName == "Traffic Type":
        self.Traffic_Type = content
      elif self.MessageName == "protocol_data":
         ####################################################
         # Parsing SCCP
         ####################################################   

        SCCP_Message = content
        sccp_parser = PCA_SCCPParser.Parser()
        sccp_handler = PCA_SCCPParser.Handler(self.XMLCFG)
        sccp_parser.setContentHandler(sccp_handler)
        sccp_parser.parse(SCCP_Message,self.Traffic_Type)
        sccp_response_message = sccp_handler.getHandlerResponse()
        
        SCCP_ServerID = sccp_handler.getTID()
        self.SCCP_DebugStr = sccp_handler.getDebugStr()
        (self.orig_tid,self.dest_tid) = sccp_handler.getTCAP_ID()
        
        protocol_data_msg = self.opc + self.dpc + self.SI + self.NI + self.MP + self.SLS + sccp_response_message
        message_length = len(protocol_data_msg) + 4
        message_length_hex = struct.pack("!H",message_length)
        protocol_data = self.protocol_data_tag + message_length_hex + protocol_data_msg
      
        M3UA_data = self.M3UA_header + self.Routing_context + protocol_data 

        M3UA_data_len = len(M3UA_data) % 4
        M3UA_data_len_padding = 4 - M3UA_data_len

        message_padding = ''
        if M3UA_data_len_padding < 4:
          for i in range(M3UA_data_len_padding):
            M3UA_data = M3UA_data + chr(0x00)
            message_padding = message_padding + chr(0x00)
      
        message_length = len(M3UA_data) + 4
        message_length_hex = struct.pack("!i",message_length)
      
        self.Message = self.M3UA_header + message_length_hex +  self.Routing_context + protocol_data + message_padding    
      
        Msg = "send Payload Data (DATA) Response back to client"
        PCA_GenLib.WriteLog(Msg,2)   
        #self.Message = self.M3UAMessage.getPayloadData(sccp_response_message)   
      elif self.MessageName == "SLS":
        self.SLS = self.attrs
      elif self.MessageName == "Message Type":   
        Msg = "recv : %s " % content
        PCA_GenLib.WriteLog(Msg,2)     
        if content == "Payload Data (DATA)":
          Msg = "Got Payload Data (DATA)"
          PCA_GenLib.WriteLog(Msg,2)
        elif content == "ASP Up (ASPUP)":
          self.Message = self.M3UAMessage.getASUP_UP_Ack()
          Msg = "send ASUP_UP_Ack back to client"
          PCA_GenLib.WriteLog(Msg,1)
        elif content == "ASP Active (ASPAC)":
          self.Message = self.M3UAMessage.getASP_Active_Ack()
          Msg = "send ASP Active (ASPAC)_Ack back to client"
          PCA_GenLib.WriteLog(Msg,1)
        elif content == "Heartbeat (BEAT)":
          self.Message = self.M3UAMessage.getASPSM_BEAT_Ack()
          Msg = "send Heartbeat (BEAT)_Ack back to client"
          PCA_GenLib.WriteLog(Msg,2)        
        elif content == "Heartbeat Acknowledgement (BEAT ACK)":
          self.Message = None
          Msg = "Heartbeat (BEAT)_Ack no response"
          PCA_GenLib.WriteLog(Msg,2)
          
        elif content == "Destination State Audit (DAUD)":          
          Msg = "Destination State Audit (DAUD) send DAVA back"
          PCA_GenLib.WriteLog(Msg,1)
          self.Message = self.M3UAMessage.getSSNM("DAVA")
        elif content == "Destination Available (DAVA)":  
          Msg = "Destination Available (DAVA) no response back"
          PCA_GenLib.WriteLog(Msg,1)
          self.Message = None
        elif content == "ASP Active Acknowledgement (ASPAC ACK)":  
          Msg = "ASP Active Acknowledgement (ASPAC ACK) no response back"
          PCA_GenLib.WriteLog(Msg,1)
          self.Message = None
        elif content == "ASP Up (ASPUP) ACK":  
          Msg = "ASP Up (ASPUP) ACK no response back"
          PCA_GenLib.WriteLog(Msg,2)
          self.Message = None
        else:
          Msg = "UNDEF Message Type = <%s>" % content
          PCA_GenLib.WriteLog(Msg,1)
      else:
        Msg = "No action for this yet"
        PCA_GenLib.WriteLog(Msg,3)

      Msg = "characters OK"
      PCA_GenLib.WriteLog(Msg,9)

    except:
      Msg = "characters Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise

  def endDocument(self,data,debugstr):
    try:      
      self.DebugStr = debugstr  + self.SCCP_DebugStr      	
    except:
      Msg = "startElement Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise  

  def getHandlerResponse(self):	
    try:
      Msg = "getHandlerResponse Init "
      PCA_GenLib.WriteLog(Msg,9)        

      Msg = "getHandlerResponse OK"
      PCA_GenLib.WriteLog(Msg,9)

      return self.Message
    except:
      Msg = "getHandlerResponse  error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise
    

#########################################################################
# 
#
#########################################################################
class Parser(PCA_Parser.Parser):
  DebugStr = "NA"
  ResponseCode = "NA"

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
      while len(source) > 0:
        #Msg = "parseTLV len = %s data =\n%s " % (len(source),PCA_GenLib.HexDump(source))
        #PCA_GenLib.WriteLog(Msg,0)
        name = "Tag"
        attrs = source[0:2]
        try:
          content =  PCA_M3UAParameters.TAG_DESC[attrs]
          tlv_desc = content
        except:
          content = "unknow tag =<%s>" % PCA_GenLib.HexDump(attrs)
        tag_name = content

        try:
          tlv_type = PCA_M3UAParameters.TAG_TYPE[attrs]
        except:
          tlv_type = "unknow tag type =<%s>" % PCA_GenLib.HexDump(attrs)
        
        self.set_handler(name,attrs,content) 
        source = source[2:]
        name = "Length"
        attrs = source[0:2]
        content = struct.unpack("!H",attrs)[0]
        content = content - 4
        length = content 
        self.set_handler(name,attrs,content)

        source = source[2:]
        name = "Value"
        attrs = source[0:length]
        if tlv_type == 'unsigned integer' and length == 2 :
          content = struct.unpack("!H",attrs)[0]
        elif tlv_type == 'unsigned integer' and length == 4 :
          content = struct.unpack("!i",attrs)[0]
        elif tlv_type == 'string':
          content = attrs
        else:
          content = "tag data =<\n%s\n>" % PCA_GenLib.HexDump(attrs)        
       
        protocol_data = attrs
        Msg = "tag_len = <%s>,protocol data length=<%s> =<\n%s\n>" % (length,len(protocol_data),PCA_GenLib.HexDump(protocol_data))
        PCA_GenLib.WriteLog(Msg,3)
 
        if tlv_desc != 'Protocol_Data':
          if tag_name == "Traffic Mode Type":
             try:
               content = PCA_M3UAParameters.Traffic_Mode_Type[content]
             except:
               content = "undef_traffic_mode_type_value %s" % content

          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,content)
          self.set_handler(tag_name,attrs,content)

        ####################################################
        # MTP3
        ####################################################
        if tlv_desc == 'Protocol_Data':
          name = "OPC"
          attrs = protocol_data[0:4]
          content = struct.unpack("!i",attrs)[0]
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          protocol_data = protocol_data[4:]
          name = "DPC"
          attrs = protocol_data[0:4]
          content = struct.unpack("!i",attrs)[0]
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          protocol_data = protocol_data[4:]
          name = "SI"
          attrs = protocol_data[0]
          content = ord(attrs)
          if content == 3:
           content = "SCCP"	
          else:
           content = "undefined in parameters value = %s "	% content
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          protocol_data = protocol_data[1:]
          name = "NI"
          attrs = protocol_data[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          protocol_data = protocol_data[1:]
          name = "MP"
          attrs = protocol_data[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          protocol_data = protocol_data[1:]
          name = "SLS"
          attrs = protocol_data[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          protocol_data = protocol_data[1:]
          name = "protocol_data"
          attrs = chr(0x00)
          content = protocol_data
          self.set_handler(name,attrs,content)
          
        source = source[length:]

      Msg = "parseTLV Ok "
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "parseTLV error : <%s>,<%s>,name=<%s> " % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,2)
      #Msg = "dump source data =<\n%s\n>" % PCA_GenLib.HexDump(source)
      #PCA_GenLib.WriteLog(Msg,0)

  def parse(self, source,Traffic_Type):
    try:
      Msg = "parser init"
      PCA_GenLib.WriteLog(Msg,9)	
      orig_data = source
      name = 'none'	
      self.StartParsing = 0
      TID = "na"
 
      #0                   1                   2                   3
      #0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #| Version       | Reserved      | Message Class | Message Type |
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #| Message Length                                               |
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #\ \
      #/ /
 
      if (source != None)  : 
        self._cont_handler.startDocument()
        self.StartParsing = 1

        name = "Traffic Type"
        attrs = Traffic_Type
        content = Traffic_Type
        self.set_handler(name,attrs,content)

        name = "Version"
        attrs = source[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        source = source[1:]
        name = "Reserved"
        attrs = source[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        source = source[1:]
        name = "Message Class"
        attrs = source[0]
        message_class = attrs
        try:
          content = PCA_M3UAParameters.message_class[attrs]
        except:
          content = "Reserved"
        self.set_handler(name,attrs,content)
        self.DebugStr = "<%s>=<%s>" % (name,content)
        
        source = source[1:]
        name = "Message Type"
        attrs = source[0]
        try:
          message_class_type = PCA_M3UAParameters.message_class_type[message_class]
          content = message_class_type[attrs]
        except:
          Msg = "Undef message class"
          PCA_GenLib.WriteLog(Msg,0)
          content = "Reserved"
        self.set_handler(name,attrs,content)
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

        source = source[1:]
        name = "Message Length"
        attrs = source[0:4]
        content = struct.unpack("!i",attrs)[0]
        self.set_handler(name,attrs,content)
   

        source = source[4:]
        if len(source) != 0:
          #Msg = "rest data =\n%s" % PCA_GenLib.HexDump(source)
          #PCA_GenLib.WriteLog(Msg,0)
          Msg = "calling parse TLV"
          PCA_GenLib.WriteLog(Msg,2)
          self.parseTLV(source)

      if self.StartParsing == 1:
        self._cont_handler.endDocument(orig_data,self.DebugStr)

      Msg = "parser OK"
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "parser  :<%s>,<%s>,name=<%s>" % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,0)
      Msg = "orig data =\n%s" % PCA_GenLib.HexDump(orig_data)
      PCA_GenLib.WriteLog(Msg,0)
      raise
    