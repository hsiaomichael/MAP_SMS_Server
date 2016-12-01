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
import PCA_TCAPParameters
import PCA_MAPParser
import PCA_DLL
  
##############################################################################
###    Message Handler   	
##############################################################################

##############################################################################
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
      name = "TCAP %s" % name
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
  Is_TCAP_begin = 0
  

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
          #content = "%s:%s" % (PCA_TCAPParameters.Tag_Desc[attrs],PCA_GenLib.getHexString(attrs))
          tag_desc = PCA_TCAPParameters.Tag_Desc[attrs]
          content = tag_desc
        except:
          #content = "undef:%s" % PCA_GenLib.getHexString(attrs)
          content = "undef:%s" % PCA_GenLib.getHexString(attrs)

        #tag = content
        ##tag = "%s:%s" % (content,PCA_GenLib.getHexString(attrs))
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
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
       # name = "%s form" % tag
        #self.set_handler(name,chr(0x00),Tag_Type)
        
        #name = "%s-%s" % (name,PCA_TCAPParameters.tag_class[tag_class])
        #if Tag_Type == 'Primitive':
        #  attrs = struct.pack("!b",ord(attrs) & 0x1f)
        #name = "%s %s" % (tag,tag_index)
	#self.set_handler(name,attrs,content)
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

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
       
        if tag_desc == "oid":
          try:
             content = PCA_GenLib.getOctString(attrs)             
             self.app_context = PCA_TCAPParameters.app_context[content]
             Msg = "app_context = %s" % self.app_context
             PCA_GenLib.WriteLog(Msg,3)
             self.DebugStr = "%s,<application>=<%s>" % (self.DebugStr,self.app_context)
             content = self.app_context
          except:
            Msg = "undef ctx %s" % PCA_GenLib.getOctString(attrs)
            PCA_GenLib.WriteLog(Msg,3)
            content = "undef ctx %s" % PCA_GenLib.getOctString(attrs)
        elif tag_desc == "tcap_begin":
          self.Is_TCAP_begin = 1
          content = PCA_GenLib.getHexString(attrs)
        elif tag_desc == "tcap_end":
          self.Is_TCAP_begin = 0
          content = PCA_GenLib.getHexString(attrs)
        else:        
          
          content = PCA_GenLib.getHexString(attrs)
       
        
        if Tag_Type == 'Constructor':
          if tag_desc == "component_portion":
            Msg = "GSM 0340 layer , not parsing now"
            PCA_GenLib.WriteLog(Msg,3)
            ####################################################
            # Parsing MAP
            #################################################### 
            Msg = "MAP application data =<\n%s\n>" % PCA_GenLib.HexDump(attrs)
            PCA_GenLib.WriteLog(Msg,3)

	    dll_file_name = self.app_context
            Msg = "dll_file_name = <%s>" % dll_file_name
            PCA_GenLib.WriteLog(Msg,3)
	    
            #dll_file_name = "PCA_MAPParser"
	    Script_File = PCA_DLL.DLL(dll_file_name)			
	    factory_function="Parser"
	    factory_component = Script_File.symbol(factory_function)
	    parser = factory_component()		
	    Script_File = PCA_DLL.DLL(dll_file_name)
	    factory_function="Handler"
	    factory_component = Script_File.symbol(factory_function)
	    handler = factory_component()			
	    parser.setContentHandler(handler)
	    parser.parse(attrs,self.Is_TCAP_begin,self.app_context)
            response_message = handler.getHandlerResponse()
            self.set_handler('map_msg_dict',chr(0x00),response_message)
            response_ServerID = handler.getTID()
            response_DebugStr = handler.getDebugStr()
            self.DebugStr = "%s,<MAP MSG>=%s" % (self.DebugStr,response_DebugStr)

          else:
            self.parseTLV(attrs)
            self.set_handler(tag,attrs,content)
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


  def parse(self, source):
    try:
   
      Msg = "parser init"
      PCA_GenLib.WriteLog(Msg,9)	
      orig_data = source
      name = 'none'	
      self.StartParsing = 0
      TID = "na"
      content = "na"
      self.tag_index = 0
      self.Is_TCAP_begin = 0
      Msg = "TCAP data =<\n%s\n>" % PCA_GenLib.HexDump(source)
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
	        		
		
	  

