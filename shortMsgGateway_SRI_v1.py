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
import shortMsgGateway_SRI_v3
import PCA_XMLParser
import PCA_MAPParameters
import PCA_DLL
import smspdu  

###    Message Handler   	
##############################################################################
class Handler(shortMsgGateway_SRI_v3.Handler):	
	
  attrs = None	
  tcap_otid = ''
  tcap_dtid = ''
  Message = ""
  MAP_Message = {}
  dup_tag = 0
  		
  def startDocument(self):
       self.ExtraSocketData = ''
       self.IsApplicationMessage = 0
       self.Operation = chr(0x00)
       self.TID='na'
       self.Message = ''
       self.MAP_Message = {}
       self.dup_tag = 0
	

							
						

#########################################################################
# 
#
#########################################################################
class Parser(shortMsgGateway_SRI_v3.Parser):
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

  



