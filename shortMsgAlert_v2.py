########################################################################################
#
# Filename:    shortMsgAlert_v2.py
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



class Handler(PCA_Parser.ContentHandler): 

  attrs = None 
  tcap_otid = ''
  tcap_dtid = ''
  Message = {}
  dup_tag = 0
  def __init__(self,XMLCFG):
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
      PCA_GenLib.WriteLog(Msg,2)

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

        MAP_Tag = chr(0xa2)
        tag = chr(0x02)
        try:
          #tag_data = parameter_list["MAP invoke value"][1]
          tag_data = self.MAP_Message["MAP invoke_id"][1]
        except:
          tag_data = chr(0x7d)
        
        invoke_id = self.constructTLV(tag,tag_data)

        map_data = invoke_id

        message_length = len(map_data) 
        message_length_hex = struct.pack("!b",message_length)

        map_message = MAP_Tag + message_length_hex + map_data
        self.Message = map_message
        
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

        
      if self.StartParsing == 1:
        self._cont_handler.endDocument(orig_data,self.DebugStr)
          
      Msg = "parser OK"
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "parser  :<%s>,<%s>,name=<%s>" % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,1)
      Msg = "orig data =\n%s" % PCA_GenLib.HexDump(orig_data)
      PCA_GenLib.WriteLog(Msg,1)
      #self.set_handler("opCode","sendRoutingInfoForSM","sendRoutingInfoForSM")
   

