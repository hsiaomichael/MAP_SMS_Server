########################################################################################
#
# Filename:    PCA_M3UAParser.py
#  
# Description
# ===========
# 
#
# Author        : Michael Hsiao 
#
# Create Date   : 2016/09/11
# Desc          : Initial

########################################################################################

import sys,string,struct
import PCA_GenLib
import PCA_Parser
import PCA_XMLParser
import PCA_M3UAParameters
import PCA_SCCPParser
  
##############################################################################
###    Message Handler   	
##############################################################################
class Handler(PCA_Parser.ContentHandler):	
	
  attrs = None	
  tcap_otid = ''
  tcap_dtid = ''
  Message = {}
  def __init__(self):
	PCA_Parser.ContentHandler.__init__(self)
	self.Message = {}
		
  def startDocument(self):
       self.ExtraSocketData = ''
       self.IsApplicationMessage = 0
       self.Operation = chr(0x00)
       self.TID='na'
       self.Message = {}
	
  def startElement(self, name, attrs):
    try:
      Msg = "startElement init"
      PCA_GenLib.WriteLog(Msg,9)

      #Msg = "name=<%s>,attrs=<%s>" % (name,PCA_GenLib.HexDump(attrs))
      #PCA_GenLib.WriteLog(Msg,0)

      name = "M3UA %s" % name
      self.MessageName = name
      self.attrs = attrs
      self.Message[name] = attrs
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
      PCA_GenLib.WriteLog(Msg,3)
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
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

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
          #Msg = "rest protocol data =<\n%s\n>" % PCA_GenLib.HexDump(protocol_data)
          #PCA_GenLib.WriteLog(Msg,0)
          ####################################################
          # Parsing SCCP
          ####################################################         
          
          SCCP_Message = protocol_data
          sccp_parser = PCA_SCCPParser.Parser()		
          sccp_handler = PCA_SCCPParser.Handler()
	  sccp_parser.setContentHandler(sccp_handler)
	  sccp_parser.parse(SCCP_Message)
	  sccp_response_message = sccp_handler.getHandlerResponse()

        
          self.set_handler('sccp_msg_dict',chr(0x00),sccp_response_message)
	  SCCP_ServerID = sccp_handler.getTID()
          SCCP_DebugStr = sccp_handler.getDebugStr()
          
          

          Msg = "SCCP DebutStr = %s" % SCCP_DebugStr
          PCA_GenLib.WriteLog(Msg,2)
          self.DebugStr = "%s,SCCP MSG = %s" % (self.DebugStr,SCCP_DebugStr)
          #break
        #Msg = "parseTLV len of sccp message = %s ,data_length=%s, data=\n%s " % (length,len(source),PCA_GenLib.HexDump(source))
        #PCA_GenLib.WriteLog(Msg,0)
        source = source[length:]



      Msg = "parseTLV Ok "
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "parseTLV error : <%s>,<%s>,name=<%s> " % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,2)
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
        #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)


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
	        		
		
	  
#######################################################	   
# Main Program 
#######################################################   
if __name__ == '__main__':

  def MainTest(XMLCFG):
    try:
      print 'Start Program ...'
      try:
        PCA_GenLib.DBXMLCFGInit(XMLCFG)	
	import PCA_M3UAMessage
        M3UAMessage = PCA_M3UAMessage.Writer(XMLCFG)
        try:
          #Message = M3UAMessage.getASUP_UP()
          Message = M3UAMessage.getASP_Active()
          Msg = "message = *\n%s\n*" % PCA_GenLib.HexDump(Message)
          PCA_GenLib.WriteLog(Msg,1)

          parser = Parser()		
          handler = Handler()
	  parser.setContentHandler(handler)
	  parser.parse(Message)
	  response_message = handler.getHandlerResponse()
	  ServerID = handler.getTID()
          DebugStr = handler.getDebugStr()
	  print "DebutStr = %s" % DebugStr
       			
        finally:
          x=1
      finally:
        PCA_GenLib.CloseLog()
      return 0
    except:
      print '\n\n uncaught ! < ',sys.exc_type,sys.exc_value,' >'
      import traceback
      traceback.print_exc()  
      raise

#################################################################
  try:	
  	print "Open cfg file"
	XMLCFG =  open("M3UAMessage.cfg","r").read()
	MainTest(XMLCFG)
  except:
  	print "Error or .cfg configuration file not found"
 	print "Msg = : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
 	import traceback
	traceback.print_exc()  	
  	sys.exit()
	
	


