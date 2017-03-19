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

import sys,string,struct
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
  Message = {}
  dup_tag = 0
  def __init__(self):
	PCA_Parser.ContentHandler.__init__(self)
	self.Message = {}
		
  def startDocument(self):
       self.ExtraSocketData = ''
       self.IsApplicationMessage = 0
       self.Operation = chr(0x00)
       self.TID='na'
       self.Message = {}
       self.dup_tag = 0
	
  def startElement(self, name, attrs):
    try:
      Msg = "startElement init"
      PCA_GenLib.WriteLog(Msg,9)

      #Msg = "name=<%s>,attrs=<%s>" % (name,PCA_GenLib.HexDump(attrs))
      #PCA_GenLib.WriteLog(Msg,0)
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
			
      Msg = "%-20s=<%-25s>,Hex=%s" % (self.MessageName ,content,PCA_GenLib.HexDump(self.attrs))
      PCA_GenLib.WriteLog(Msg,3)

      try:
         if self.Message[self.MessageName] != None :
            x=1 
         self.dup_tag = self.dup_tag + 1
         name = "%s %s" % (self.MessageName,self.dup_tag)
         self.Message[name] = (content,self.attrs)
      except:
         self.Message[self.MessageName] = (content,self.attrs)
         
			
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


  def parseGSM0340_request(self,data):
    try:
        Msg = "parseGSM0340_request Init "
        PCA_GenLib.WriteLog(Msg,9)
        Msg = "GSM 0340 data =\n%s" % PCA_GenLib.HexDump(data)
        PCA_GenLib.WriteLog(Msg,3)
      
        gsm_0340_pdu = data
        tag = gsm_0340_pdu[0]
        TP_MR = gsm_0340_pdu[1]

        source = gsm_0340_pdu[2:]
        
        name = "GSM0340 recipient length"
	attrs = source[0]
	content = ord(attrs)
        tag_length = content
        tag_length = tag_length / 2
       
        self.set_handler(name,attrs,tag_length)

        source = source[1:]
        name = "GSM0340 recipient address"
	attrs = source[0:tag_length+1]
        toa = PCA_GenLib.getHexString(attrs[1])
        #tag_value = "%s:%s" % (toa,PCA_GenLib.getHexBCDString(attrs[1:]))
        tag_value = "%s" % (PCA_GenLib.getHexBCDString(attrs[1:]))
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,tag_value)
        self.set_handler(name,attrs,tag_value)
        
        source = source[tag_length+1:]
        pid = source[0]
        dcs = source[1]
        validity_period = source[2]
         
        name = "GSM0340 user data length"
        attrs = source[3]
        content = ord(attrs)
        user_data_length = content
        #self.set_handler(name,attrs,content)


        source = source[4:]
        tag_name = "GSM0340 sms text"
	attrs = source[0:user_data_length]
        tag_value = smspdu.pdu.unpack7bit(attrs)
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
        self.set_handler("sms text",attrs,tag_value)

      
        Msg = "parseGSM0340_request ok "
        PCA_GenLib.WriteLog(Msg,9)

    except:
      Msg = "parseGSM0340_request error : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      #raise


  def parseGSM0340_response(self,data):
    try:
        Msg = "parseGSM0340_response Init "
        PCA_GenLib.WriteLog(Msg,9)
        Msg = "GSM 0340 data =\n%s" % PCA_GenLib.HexDump(data)
        PCA_GenLib.WriteLog(Msg,3)
      
        
        name = "GSM0340 tp_udhi"
        attrs = data[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        name = "GSM0340 tp_mti"
        attrs = data[1]
        content = ord(attrs)
        self.set_handler(name,attrs,content)
        
        name = "GSM0340 tp_date"
        attrs = data[2:5]
        content = PCA_GenLib.getHexString(attrs)
        content = "%s%s%s%s%s%s" % (content[1],content[0],content[3],content[2],content[5],content[4])
        self.set_handler(name,attrs,content)
        
        name = "GSM0340 tp_time"
        attrs = data[5:8]
        content = PCA_GenLib.getHexString(attrs)
        content = "%s%s%s%s%s%s" % (content[1],content[0],content[3],content[2],content[5],content[4])
        self.set_handler(name,attrs,content)

        name = "GSM0340 tp_timezone"
        attrs = data[8]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        Msg = "parseGSM0340_response ok "
        PCA_GenLib.WriteLog(Msg,9)

    except:
      Msg = "parseGSM0340_response error : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      #raise

  def parseGSM0340_SRI_SM_response(self,data):
    try:
        Msg = "parseGSM0340_SRI_SM_response Init "
        PCA_GenLib.WriteLog(Msg,9)
        Msg = "GSM 0340 data =\n%s" % PCA_GenLib.HexDump(data)
        PCA_GenLib.WriteLog(Msg,1)
      
        
        name = "GSM0340 tp_udhi"
        attrs = data[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        name = "GSM0340 tp_mti"
        attrs = data[1]
        content = ord(attrs)
        self.set_handler(name,attrs,content)
        
        name = "GSM0340 tp_date"
        attrs = data[2:5]
        content = PCA_GenLib.getHexString(attrs)
        content = "%s%s%s%s%s%s" % (content[1],content[0],content[3],content[2],content[5],content[4])
        self.set_handler(name,attrs,content)
        
        name = "GSM0340 tp_time"
        attrs = data[5:8]
        content = PCA_GenLib.getHexString(attrs)
        content = "%s%s%s%s%s%s" % (content[1],content[0],content[3],content[2],content[5],content[4])
        self.set_handler(name,attrs,content)

        name = "GSM0340 tp_timezone"
        attrs = data[8]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        Msg = "parseGSM0340_SRI_SM_response ok "
        PCA_GenLib.WriteLog(Msg,9)

    except:
      Msg = "parseGSM0340_SRI_SM_response error : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      #raise

  def parseTLV(self,data):
    try:
      Msg = "parseTLV Init "
      PCA_GenLib.WriteLog(Msg,9)

      source = data
      tlv_desc = 'na'
      tlv_type = 'na'
      name = 'na'
      number_of_tlv = 0
      
      #Msg = "MAP parseTLV data =\n%s" % PCA_GenLib.HexDump(source)
      #PCA_GenLib.WriteLog(Msg,0)
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
           #tag_length = struct.unpack("!B"
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
          #content = "%s:%s" % (TOA,content)
        else:
         content = PCA_GenLib.getHexString(attrs)
        
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
        #self.set_handler(tag,attrs,content)
       
        if Tag_Type == 'Constructor':
           self.parseTLV(attrs)
           # DEBUG ONLY
           self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
           self.set_handler(tag,attrs,content)

        elif tag_desc == "SM_RP_UI" :
           
           if self.Is_TCAP_begin == 1:
             self.parseGSM0340_request(attrs)
           else:
             if self.app_context == "shortMsgGateway_SRI_v3":
               # SRI response 
               self.parseGSM0340_SRI_SM_response(attrs)
             else:
               self.parseGSM0340_response(attrs)
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
      self.tag_index = 0
      self.Is_TCAP_begin = Is_TCAP_begin
      self.app_context = app_context

      Msg = "MAP data =<\n%s\n>" % PCA_GenLib.HexDump(source)
      PCA_GenLib.WriteLog(Msg,3)
      ############################################
      # Message Type Tag
      # Total Message Length			
      #   Transaction Portion Information Element
      #   Dialogue Portion Information Element
      #       Dialog Portion Tag + External Tag +  OID Tag 
      #       Structed Tag + ASN.1 Type Tag + application context name
      #       Dialog Request Tag + Dialog Request length + 
      #         Component Portion Tag
      #         Component Portion Length
      #           Component Type Tag
      #           Component Type Length
			
      if (source != None)  : 
        self._cont_handler.startDocument()
	self.StartParsing = 1

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
	        		
		
	  

