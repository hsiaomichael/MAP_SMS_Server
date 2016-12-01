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
        name = "invoke value"
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
          try:
            tag_value = PCA_MAPParameters.op_code[content]
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
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,tag_name,tag_value)
          self.set_handler(name,attrs,tag_value)

          source = source[tag_length:]
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
          tag_value = PCA_GenLib.getHexString(attrs)
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
	  

