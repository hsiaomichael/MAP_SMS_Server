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
import PCA_MAPParameters
  
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
  Message = ''
  dup_tag = 0
  dll_file_name = ''
  response_DebugStr = ''
  TCAP_Message = {}
  transaction_portion = ''
  tcap_tid = 0
  response_message = ''
  component_portion = ''
  Is_MAP_v1 = 0
  
  def __init__(self,XMLCFG):

    PCA_Parser.ContentHandler.__init__(self)
    self.Message = {}
    self.XMLCFG = XMLCFG
  ########################################################
  ##
  ########################################################

  def startDocument(self):
       self.ExtraSocketData = ''
       self.IsApplicationMessage = 0
       self.Operation = chr(0x00)
       self.TID='na'
       self.Message = ''
       self.dup_tag = 0
       self.TCAP_Message = {}
       self.tcap_tid = self.tcap_tid + 1
       #tag_data = struct.pack("!I",self.tcap_tid)
       #tag = chr(0x49)
       #self.transaction_portion = self.constructTLV(tag,tag_data)
       self.transaction_portion = ""
       self.response_message = ''
       self.component_portion = ''
       self.Is_MAP_v1 = 0
       self.tcap_begin = 0
       self.TCAP_Tag = PCA_TCAPParameters.tcap_end_tag
       self.component_portion_avail = 0
       self.tcap_continue = 0
       self.orig_tid = ''
       self.dest_tid = ''
  
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
      self.TCAP_Message[self.MessageName] = (content,self.attrs)
  
      Msg = "%-20s=<%-25s>,Hex=%s" % (self.MessageName ,content,PCA_GenLib.HexDump(self.attrs))
      PCA_GenLib.WriteLog(Msg,3)
      if self.MessageName != "TCAP map_message":
        Msg = "%s=%s" % (self.MessageName ,content)
        PCA_GenLib.WriteLog(Msg,3)

      if self.MessageName == "TCAP ap_context_name":
        self.dll_file_name = content
        self.Is_MAP_v1 = 1
      elif self.MessageName == "TCAP Originating TID":
        self.orig_tid = self.attrs
       
        self.tcap_begin = 1
        tag_data = self.attrs
        tag = chr(0x49)  # Dest TID Tag
        self.transaction_portion = self.transaction_portion + self.constructTLV(tag,tag_data)
      elif self.MessageName == "TCAP Destination TID":
        self.dest_tid = self.attrs
      elif self.MessageName == "TCAP tcap_begin":
        self.tcap_begin = 1
      elif self.MessageName == "TCAP tcap_continue":
        self.tcap_continue = 1
      elif self.MessageName == "TCAP map_message":
        self.component_portion_avail = 1
            
        try: 
              # Use this to check if map v1 or tcap continue
              self.TCAP_Message["TCAP Application_Context"][1]              
              Msg = "dll_file_name = <%s>" % self.dll_file_name
              PCA_GenLib.WriteLog(Msg,3)
        except:
          if self.tcap_begin == 1 or self.tcap_continue == 1:
            Msg = "MAP v1 or tcap continue message"
            PCA_GenLib.WriteLog(Msg,2)
            try:
              opCode = PCA_MAPParameters.op_code[ord(content[7])]
              if opCode == "mo-ForwardSM":
                opCode = "mt-ForwardSM"
            except:
              opCode = PCA_MAPParameters.op_code[ord(content[8])]
              if opCode == "mo-ForwardSM":
                opCode = "mt-ForwardSM"                
                     
            Msg = "MAP v1 get op code = %s" % opCode
            PCA_GenLib.WriteLog(Msg,2)
            if opCode == "sendRoutingInfoForSM":
               self.dll_file_name = "shortMsgGateway_SRI_v1"
            elif opCode == "mt-ForwardSM":
               self.dll_file_name = "shortMsgMT_Relay_v3"
                
            else:
               self.dll_file_name = "PCA_MAPParser"
          else:
              Msg = "not tcap begin message"
              PCA_GenLib.WriteLog(Msg,2)
              self.dll_file_name = "PCA_MAPParser"
            # Test abort for MAP fallback test
            #if self.dll_file_name == "shortMsgMT_Relay_v3":
            #if self.dll_file_name == "shortMsgGateway_SRI_v3":
            #  Msg = "SRI v3 send TCAP abort"
            # PCA_GenLib.WriteLog(Msg,1)
            #  self.TCAP_Tag = PCA_TCAPParameters.tcap_abort

        Msg = "%s : Parser DLL Name = %s" % (self.MessageName,self.dll_file_name)
        PCA_GenLib.WriteLog(Msg,1)
        Script_File = PCA_DLL.DLL(self.dll_file_name)
        factory_function="Parser"
        factory_component = Script_File.symbol(factory_function)
        parser = factory_component()
        Script_File = PCA_DLL.DLL(self.dll_file_name)
        factory_function="Handler"
        factory_component = Script_File.symbol(factory_function)
        handler = factory_component(self.XMLCFG)
        parser.setContentHandler(handler)
            
        parser.parse(content,self.tcap_begin,self.dll_file_name)
         
        response_message = handler.getHandlerResponse()
        #self.set_handler('map_msg_dict',chr(0x00),response_message)
        response_ServerID = handler.getTID()
        self.response_DebugStr = handler.getDebugStr()
        #self.DebugStr = "%s,<MAP MSG>=%s" % (self.DebugStr,response_DebugStr)
        self.component_portion = response_message

      Msg = "characters OK"
      PCA_GenLib.WriteLog(Msg,9)

    except:
      Msg = "characters Error :<%s>,<%s> , self.MessageName = %s" % (sys.exc_type,sys.exc_value,self.MessageName)
      PCA_GenLib.WriteLog(Msg,0)
      raise


  def endDocument(self,data,debugstr):
    try:    
      #self.DebugStr = debugstr
      self.DebugStr = "%s,<MAP MSG>=%s" % (debugstr,self.response_DebugStr)
    except:
      Msg = "startElement Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise
  

  def getHandlerResponse(self):	
    try:
        Msg = "getHandlerResponse Init "
        PCA_GenLib.WriteLog(Msg,9)
        
        ###############################################
        # Transaction Portion 
        ###############################################
        # No map message , then should be a tcap only for long message
        if self.component_portion_avail == 0 and self.tcap_begin == 1:
          Msg = "TCAP begin message ready for tcap continue"
          PCA_GenLib.WriteLog(Msg,3)
          self.TCAP_Tag = chr(0x65) # tcap continue tag
          tag = chr(0x48)             
          tag_data = struct.pack("!I",self.tcap_tid)
          self.tcap_tid = self.tcap_tid + 1             
          self.transaction_portion =  self.constructTLV(tag,tag_data) + self.transaction_portion

        ###############################################
        # Dialog Portion 
        ###############################################
        if self.TCAP_Tag == PCA_TCAPParameters.tcap_abort:

          # MT-FSM V2
          Application_Context_name = chr(0x04)+chr(0x00)+chr(0x00)+chr(0x01)+chr(0x00)+chr(0x19)+chr(0x02)
          Application_Context_name_Tag = chr(0x06)
          Application_Context = self.constructTLV(Application_Context_name_Tag,Application_Context_name)
          Application_Context_Tag = chr(0xa1)
          Application_Context_TLV = self.constructTLV(Application_Context_Tag,Application_Context)
      
          app_result_tag = chr(0x02)
          app_result_value = chr(0x02)
          app_result = self.constructTLV(app_result_tag,app_result_value)

          app_result_user_diag_tag = chr(0x02)
          app_result_user_diag_value = chr(0x00)
          app_result_user_diag = self.constructTLV(app_result_user_diag_tag,app_result_user_diag_value)
      
          result_user_diag_tag = chr(0xa1)
          result_user_diag_TLV = self.constructTLV(result_user_diag_tag,app_result_user_diag)
        
          app_result_tag = chr(0x02)
          app_result_value = chr(0x01)
          app_result = self.constructTLV(app_result_tag,app_result_value)
          result_tag = chr(0xa2)
          result_TLV = self.constructTLV(result_tag,app_result)
        
          result_source_diag_tag = chr(0xa3)
          result_source_diag_TLV = self.constructTLV(result_source_diag_tag,result_user_diag_TLV)


          dialog_response_tag = chr(0x61)
          dialog_response = Application_Context_TLV+result_TLV+result_source_diag_TLV
          dialog_response_TLV = self.constructTLV(dialog_response_tag,dialog_response)
       
          Single_ASN1_Tag = chr(0xa0)
          Single_ASN1_TLV = self.constructTLV(Single_ASN1_Tag,dialog_response_TLV) 

          oid_tag = chr(0x06)
          oid_data = self.TCAP_Message["TCAP oid"][1]
          oid_tlv = self.constructTLV(oid_tag,oid_data)
          tcap_external = oid_tlv + Single_ASN1_TLV

          tcap_external_tag = chr(0x28)     
          tcap_external_tlv = self.constructTLV(tcap_external_tag,tcap_external)
      
          dialog_portion_tag = chr(0x6b)     
          dialog_portion = self.constructTLV(dialog_portion_tag,tcap_external_tlv)

        # Not MAP v1 and not TCAP continue message 
        elif self.Is_MAP_v1 != 0 and self.tcap_continue == 0:
          
          
          Application_Context_name = self.TCAP_Message["TCAP ap_context_name"][1]
          Application_Context_name_Tag = chr(0x06)
          Application_Context = self.constructTLV(Application_Context_name_Tag,Application_Context_name)
          Application_Context_Tag = chr(0xa1)
          Application_Context_TLV = self.constructTLV(Application_Context_Tag,Application_Context)
      
          app_result_tag = chr(0x02)
          app_result_value = chr(0x00)
          app_result = self.constructTLV(app_result_tag,app_result_value)

          app_result_user_diag_tag = chr(0x02)
          app_result_user_diag_value = chr(0x00)
          app_result_user_diag = self.constructTLV(app_result_user_diag_tag,app_result_user_diag_value)
      
          result_user_diag_tag = chr(0xa1)
          result_user_diag_TLV = self.constructTLV(result_user_diag_tag,app_result_user_diag)
        
          app_result_tag = chr(0x02)
          app_result_value = chr(0x00)
          app_result = self.constructTLV(app_result_tag,app_result_value)
          result_tag = chr(0xa2)
          result_TLV = self.constructTLV(result_tag,app_result)
        
          result_source_diag_tag = chr(0xa3)
          result_source_diag_TLV = self.constructTLV(result_source_diag_tag,result_user_diag_TLV)


          dialog_response_tag = chr(0x61)
          dialog_response = Application_Context_TLV+result_TLV+result_source_diag_TLV
          dialog_response_TLV = self.constructTLV(dialog_response_tag,dialog_response)
       
          Single_ASN1_Tag = chr(0xa0)
          Single_ASN1_TLV = self.constructTLV(Single_ASN1_Tag,dialog_response_TLV) 

          oid_tag = chr(0x06)
          oid_data = self.TCAP_Message["TCAP oid"][1]
          oid_tlv = self.constructTLV(oid_tag,oid_data)
          tcap_external = oid_tlv + Single_ASN1_TLV

          tcap_external_tag = chr(0x28)     
          tcap_external_tlv = self.constructTLV(tcap_external_tag,tcap_external)
      
          dialog_portion_tag = chr(0x6b)     
          dialog_portion = self.constructTLV(dialog_portion_tag,tcap_external_tlv)
        else:
          # MAP v1 or tcap continue message no dialog portion
          dialog_portion = ''
          Msg = "no dialog portion"
          PCA_GenLib.WriteLog(Msg,2)

        
        ###############################################
        # Component Portion 
        ###############################################
        if self.component_portion_avail == 1 and self.TCAP_Tag != PCA_TCAPParameters.tcap_abort:
          tag = chr(0x6c)
          tag_data = self.component_portion
          component_portion_tlv = self.constructTLV(tag,tag_data)
          #Msg = "DEBUG component portion = *\n%s\n*" % PCA_GenLib.HexDump(component_portion_tlv)
          #PCA_GenLib.WriteLog(Msg,1)
        else:
          component_portion_tlv = ''
          Msg = "no component portion"
          PCA_GenLib.WriteLog(Msg,2)
        
        tcap_data = self.transaction_portion  +  dialog_portion + component_portion_tlv
        #tcap_data = self.transaction_portion  +  dialog_portion 
        message_length = len(tcap_data) 
        message_length_hex = struct.pack("!B",message_length)
        tcap_message = self.TCAP_Tag + message_length_hex + tcap_data
        self.Message = tcap_message
          
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
  tcap_hearder_get = 0
  

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
          if self.tcap_hearder_get == 0:
            self.tcap_hearder_get = 1
            tag_desc = PCA_TCAPParameters.Tag_Header_Desc[attrs]
          else:
            tag_desc = PCA_TCAPParameters.Tag_Desc[attrs]
          #tag_desc = PCA_TCAPParameters.Tag_Desc[attrs]
          Msg = "tag_desc = <%s>" % tag_desc
          PCA_GenLib.WriteLog(Msg,3)
          content = tag_desc
        except:
          #content = "undef:%s" % PCA_GenLib.getHexString(attrs)
          content = "undef:%s" % PCA_GenLib.getHexString(attrs)
          #Msg = "PCA DEBUG  error : <%s>,<%s> content = <%s>" % (sys.exc_type,sys.exc_value,content)
          #PCA_GenLib.WriteLog(Msg,0)

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
             Msg = "oid debug =\n%s" % PCA_GenLib.HexDump(attrs)
             PCA_GenLib.WriteLog(Msg,3)
             content = PCA_GenLib.getOctString(attrs)             
             self.app_context = PCA_TCAPParameters.app_context[content]
             Msg = "app_context = %s" % self.app_context
             PCA_GenLib.WriteLog(Msg,3)
             self.DebugStr = "%s,<application>=<%s>" % (self.DebugStr,self.app_context)
             content = self.app_context
             tag = 'ap_context_name'
          except:
            Msg = "id-as-dialog %s" % PCA_GenLib.getOctString(attrs)
            PCA_GenLib.WriteLog(Msg,2)
            content = "id-as-dialog %s" % PCA_GenLib.getOctString(attrs)
            
        elif tag_desc == "tcap_begin":
          self.Is_TCAP_begin = 1
          content = PCA_GenLib.getHexString(attrs)
        elif tag_desc == "tcap_end":
          self.Is_TCAP_begin = 0
          content = PCA_GenLib.getHexString(attrs)
        elif tag_desc == "tcap_continue":
          self.Is_TCAP_begin = 2
          content = PCA_GenLib.getHexString(attrs)
          self.app_context = "shortMsgMT_Relay_v3_continue"
        else:        
          
          content = PCA_GenLib.getHexString(attrs)
        
        if Tag_Type == 'Constructor':
          if tag_desc == "component_portion":
            Msg = "GSM 0340 layer , not parsing now"
            PCA_GenLib.WriteLog(Msg,3)
            self.set_handler("map_message",chr(0x00),attrs)
            ####################################################
            # Parsing MAP
            #################################################### 
            #Msg = "MAP application data =<\n%s\n>" % PCA_GenLib.HexDump(attrs)
            #PCA_GenLib.WriteLog(Msg,3)
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
   
      Msg = "parser OK"
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "parser  :<%s>,<%s>,name=<%s>" % (sys.exc_type,sys.exc_value,name)
      PCA_GenLib.WriteLog(Msg,0)
      Msg = "orig data =\n%s" % PCA_GenLib.HexDump(orig_data)
      PCA_GenLib.WriteLog(Msg,0)
      raise
        

