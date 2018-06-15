########################################################################################
#
# Filename:    PCA_SCCPParser.py
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
import PCA_SCCPParameters
import PCA_TCAPParser


##############################################################################
###    Message Handler 
##############################################################################
class Handler(PCA_Parser.ContentHandler): 
 
  attrs = None 
  Message = ''
  TCAP_DebugStr = ''
  SCCP_Message = {}
  tcap_response_message = ""

  def __init__(self,XMLCFG):
        PCA_Parser.ContentHandler.__init__(self)
        self.Message = ""
        self.XMLCFG = XMLCFG
        
        Tag = "MESSAGE_TYPE"
        message_type = int(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))
        self.message_type = struct.pack("!b",message_type)

        Tag = "GT"
        self.GT = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
        Msg = "GT = <%s> " % self.GT
        PCA_GenLib.WriteLog(Msg,2)
        Tag = "SC_ADDRESS"
        self.sc_address = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
        Msg = "sc_address = <%s> " % self.sc_address
        PCA_GenLib.WriteLog(Msg,2)

        self.SCCP_Message = {}
        self.Traffic_Type = "IN"
       
  def startDocument(self):
       self.ExtraSocketData = ''
       self.IsApplicationMessage = 0
       self.Operation = chr(0x00)
       self.TID='na'
       self.Message = ''
       
  def startElement(self, name, attrs):
    try:
      Msg = "startElement init"
      PCA_GenLib.WriteLog(Msg,9)

      #Msg = "name=<%s>,attrs=<%s>" % (name,PCA_GenLib.HexDump(attrs))
      #PCA_GenLib.WriteLog(Msg,0)
      self.attrs = attrs
      name = "SCCP %s" % name
      self.MessageName = name
      #self.Message[name] = attrs
      self.attrs = attrs
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
 
      Msg = "%-20s=<%-25s>,Hex=%s" % (self.MessageName ,content,PCA_GenLib.HexDump(self.attrs))
      PCA_GenLib.WriteLog(Msg,2)
     
      self.SCCP_Message[self.MessageName] = (content,self.attrs)
        
      if self.MessageName == "Traffic Type":
         self.Traffic_Type = content
      elif self.MessageName == "SCCP calling Digits": 
        Msg = "CgPA = <%s>" % content
        PCA_GenLib.WriteLog(Msg,2)
      elif self.MessageName == "SCCP called Digits": 
        Msg = "CdPA = <%s>" % content
        PCA_GenLib.WriteLog(Msg,2)
      elif self.MessageName == "SCCP tcap_parameter":

        TCAP_Message = self.attrs
        tcap_parser = PCA_TCAPParser.Parser()
        tcap_handler = PCA_TCAPParser.Handler(self.XMLCFG)
        tcap_parser.setContentHandler(tcap_handler)
        tcap_parser.parse(TCAP_Message)
        self.tcap_response_message = tcap_handler.getHandlerResponse()
        TCAP_ServerID = tcap_handler.getTID()
        self.TCAP_DebugStr = tcap_handler.getDebugStr()
        (self.orig_tid,self.dest_tid) = tcap_handler.getTCAP_ID()
        (self.imsi,self.NNN) = tcap_handler.getSRI_SM_resp()
        #Msg = "sri-sm response ,imsi=<%s>,NNN=<%s>, ready send MT-FSM" % (self.imsi,self.NNN)
        #PCA_GenLib.WriteLog(Msg,2) 
        
     

      else:
        Msg = "%s=%s" % (self.MessageName ,content)
        PCA_GenLib.WriteLog(Msg,2)

      Msg = "characters OK"
      PCA_GenLib.WriteLog(Msg,9)
 
    except:
      Msg = "characters Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise


  def endDocument(self,data,debugstr):
    try: 
        self.DebugStr = "%s,TCAP MSG=%s" % (debugstr,self.TCAP_DebugStr) 
    except:
        Msg = "startElement Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
        PCA_GenLib.WriteLog(Msg,0)
        raise
  
  def getHandlerResponse(self):	
    try:
        Msg = "getHandlerResponse Init "
        PCA_GenLib.WriteLog(Msg,9)

        Msg = "Traffic Type = <%s> " % self.Traffic_Type
        PCA_GenLib.WriteLog(Msg,2)

        Protocol_Class = chr(0x80)
       
        hoop_counter = chr(0x0f)
        P_2_first_parameter = chr(0x04)
        # CgPA
        TT = self.SCCP_Message["SCCP called Translation Type"][1]
        Numbering_plan = self.SCCP_Message["SCCP called Numbering plan"][1]
        NoA = self.SCCP_Message["SCCP called Nature of Addr"][1]
        Digits = self.SCCP_Message["SCCP called Digits"][1]
        GT = TT + Numbering_plan + NoA + Digits
        calling_address = self.SCCP_Message["SCCP called Address Indicator"][1] + self.SCCP_Message["SCCP called SSN"][1] + GT
        len_of_calling_address_digits = len(Digits)
        
        option_parameter = chr(0x00)
        # CdPA
        TT = self.SCCP_Message["SCCP calling Translation Type"][1]
        Numbering_plan = self.SCCP_Message["SCCP calling Numbering plan"][1]
        NoA = self.SCCP_Message["SCCP calling Nature of Addr"][1]
        Digits = self.SCCP_Message["SCCP calling Digits"][1]
        len_of_called_address_digits = len(Digits)
        GT = TT + Numbering_plan + NoA + Digits
        called_address = self.SCCP_Message["SCCP calling Address Indicator"][1] + self.SCCP_Message["SCCP calling SSN"][1] + GT

        called_address_hex_length = struct.pack("!B",len(called_address))
        calling_address_hex_length = struct.pack("!B",len(calling_address))
        tcap_message = self.tcap_response_message
        tcap_message_hex_length = struct.pack("!B",len(tcap_message))
 
        P_2_second_parameter = struct.pack("!b",4 + 3 + len_of_called_address_digits + 2 )
        P_2_third_parameter = struct.pack("!b",4 + 3 + len_of_called_address_digits + 2 + 5 +  len_of_calling_address_digits )               
        sccp_data = self.message_type +  Protocol_Class + hoop_counter + P_2_first_parameter + P_2_second_parameter + P_2_third_parameter + option_parameter + called_address_hex_length + called_address + calling_address_hex_length + calling_address + tcap_message_hex_length + tcap_message
      
        self.Message = sccp_data

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
  TCAP_dtid = ''

  def set_handler(self,name,attrs,content):
    self._cont_handler.startElement(name, attrs)        		
    self._cont_handler.characters(content)
    self._cont_handler.endElement(name)

  def parseAddress(self,data,length,address_type):
    try:
      Msg = "parseAddress Init "
      PCA_GenLib.WriteLog(Msg,9)

      source = data[0:length]
      tlv_desc = 'na'
      tlv_type = 'na'
      name = 'na'
      Msg = "Address length = <%s> data =\n%s" % (length,PCA_GenLib.HexDump(source))
      PCA_GenLib.WriteLog(Msg,2)
      while len(source) > 0:

        name = "Address Indicator"
        name = "%s %s" % (address_type,name)
        attrs = source[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)
        source = source[1:]
        if (content & 0x01):
          name = "%s Address PC" % address_type
          self.set_handler(name,attrs,"Point Code Present")
          self.DebugStr = "%s <Point Code Present>" % self.DebugStr
          name = "PC"
          name = "%s %s" % (address_type,name)
          attrs = source[0:2]
          content = struct.unpack("!H",attrs[1]+attrs[0])[0]
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          source = source[2:]
          name = "SSN"
          name = "%s %s" % (address_type,name)
          attrs = source[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

          #source = source[1:]

        else:
          self.DebugStr = "%s <Point Code Not Present>" % self.DebugStr
          name = "%s Address PC" % address_type
          self.set_handler(name,attrs,"Point Code Not Present")
          name = "SSN"
          name = "%s %s" % (address_type,name)
          attrs = source[0]
          content = ord(attrs)
          self.set_handler(name,attrs,content)
          self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)


        source = source[1:]
        name = "Translation Type"
        name = "%s %s" % (address_type,name)
        attrs = source[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)

        source = source[1:]
        name = "Numbering plan"
        name = "%s %s" % (address_type,name)
        attrs = source[0]
        content = ord(attrs)
        content = content & 0xF0
        content = content >> 4
        self.set_handler(name,attrs,content)
       
        name = "Encoding scheme"
        name = "%s %s" % (address_type,name)
        attrs = source[0]	
        content = ord(attrs)
        content = content & 0x0F
        self.set_handler(name,attrs,content)

        source = source[1:]
        name = "Nature of Addr"
        name = "%s %s" % (address_type,name)
        attrs = source[0]
        content = ord(attrs)
        self.set_handler(name,attrs,content)
        
        source = source[1:]
        name = "Digits"
        name = "%s %s" % (address_type,name)
        attrs = source
        content = PCA_GenLib.getHexBCDString(attrs)
        self.set_handler(name,attrs,content)
        self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
        break

      Msg = "parseAddress Ok "
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "parseAddress error : <%s>,<%s>,name=<%s> " % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,0)
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
      content = "na"
      #Msg = "DEBUG SCCP = *\n%s\n*" % PCA_GenLib.HexDump(source)
      #PCA_GenLib.WriteLog(Msg,0)

      ############################################        
      # Message type code
      # Mandatory fixed part
      # Mandatory variable part
      # Optional part
        
      if (source != None)  : 
        self._cont_handler.startDocument()
        self.StartParsing = 1

        name = "Traffic Type"
        attrs = Traffic_Type
        content = Traffic_Type
        self.set_handler(name,attrs,content)

        name = "Message Type"
        attrs = source[0]
        message_type = ''
        try:
            content = PCA_SCCPParameters.SCCP_message_type[attrs]
        except:
            content = "undef message type =<%s>" % PCA_GenLib.HexDump(attrs)
        message_type = content
        self.set_handler(name,attrs,content)
        
        #################################################
        # Number of Tag depend on message type
        #################################################
        
        if (message_type == "XUDTS_Extended_unitdata") or (message_type == "UDTS_unitdata"):
            source = source[1:]
            name = "Protocol Class"
            attrs = source[0]
            content = ord(attrs)
            self.set_handler(name,attrs,content)

            if (message_type == "XUDTS_Extended_unitdata") :
                source = source[1:]
                name = "Hop Counter"
                attrs = source[0]
                content = ord(attrs)
                self.set_handler(name,attrs,content)
                self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
       
            source = source[1:]
            name = "P called address"
            attrs = source[0]
            content = ord(attrs)
            P_called_address = content
            called_party_address = source[P_called_address+1:]
            self.set_handler(name,attrs,content)        
            #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

            source = source[1:]
            name = "P calling address"
            attrs = source[0]
            content = ord(attrs)
            P_calling_address = content
            calling_party_address = source[content+1:]
            self.set_handler(name,attrs,content)
            #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)        

            source = source[1:]
            name = "P tcap Param"
            attrs = source[0]
            content = ord(attrs)
            P_tcap_parameter = content
            tcap_parameter = source[content+1:]
            self.set_handler(name,attrs,content) 
            #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)
     
            source = source[1:]
            name = "P2_Option_parm"
            attrs = source[0]
            content = ord(attrs)
            self.set_handler(name,attrs,content)
            #self.DebugStr = "%s,<%s>=<%s>" % (self.DebugStr,name,content)

            #source = source[4:]
            #if len(source) != 0:
            #  Msg = "rest data =\n%s" % PCA_GenLib.HexDump(source)
            #  PCA_GenLib.WriteLog(Msg,2)
            Msg = "parsing called_party_address "
            PCA_GenLib.WriteLog(Msg,2)

            self.DebugStr = "%s,Called Party Address Info :" % self.DebugStr
            self.parseAddress(called_party_address,P_calling_address-P_called_address,"called")
            self.DebugStr = "%s,Calling Party Address Info :" % self.DebugStr
            self.parseAddress(calling_party_address,P_tcap_parameter-P_calling_address,"calling")

            ####################################################
            # Parsing TCAP
            ####################################################         
            #Msg = "DEBUG tcap =\n%s" % PCA_GenLib.HexDump(tcap_parameter)
            #PCA_GenLib.WriteLog(Msg,0)
         
            self.set_handler('tcap_parameter',tcap_parameter,"tcap_parameter")
            #self.DebugStr = "%s,TCAP MSG=%s" % (self.DebugStr,TCAP_DebugStr)
     
        else:
            Msg = "SCCP message type = %s not implement yet" % message_type
            PCA_GenLib.WriteLog(Msg,0)
            
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
    