########################################################################################
#
# Filename:    PCA_Parser.py
#  
# Description
# ===========
# Generic Parser implement SAX spec
#
#
# Author        : Michael Hsiao 
#
# Create Date   : 2004/10/03
# Desc          : Initial

########################################################################################

import sys,string
import PCA_GenLib,struct

class ContentHandler:
    DebugStr = "NA"
    TID = "NA"
    Message = None
    def __init__(self):
        self._locator = None

    def setDocumentLocator(self, locator):
        
        self._locator = locator

    def startDocument(self):
        "Receive notification of the beginning of a document. "

    
    def endDocument(self):
        "Receive notification of the end of a document "

    
    def startPrefixMapping(self, prefix, uri):
        "Begin the scope of a prefix-URI Namespace mapping"

    def endPrefixMapping(self, prefix):
        "End the scope of a prefix-URI mapping."

    
    def startElement(self, name, attrs):
        "Signals the start of an element in non-namespace mode"

    
    def endElement(self, name):
        "Signals the end of an element in non-namespace mode."

    
    def characters(self, content):
        "Receive notification of character data."

    def ignorableWhitespace(self, whitespace):
        "Receive notification of ignorable whitespace in element content."

    
    def processingInstruction(self, target, data):
        "Receive notification of a processing instruction."


    def skippedEntity(self, name):
        "Receive notification of a skipped entity."

    def getDebugStr(self):
        return self.DebugStr
        
    def getTID(self):
        return self.TID
    def getHandlerResponse(self):
        return self.Message

#########################################################################
# 
#
#########################################################################
class Parser:
	
	def __init__(self):
		try:
			Msg = "Parser init"
			PCA_GenLib.WriteLog(Msg,9)
	
			self._cont_handler = ContentHandler()
        		
			Msg = "Parser OK"
			PCA_GenLib.WriteLog(Msg,9)
		except:
 			Msg = "Parser Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
			PCA_GenLib.WriteLog(Msg,0)
			raise
			
	def parse(self, source):
		try:
			Msg = "parser init"
			PCA_GenLib.WriteLog(Msg,9)
			self._cont_handler.startDocument()
			#Msg = "data=<%s>" % source
			#PCA_GenLib.WriteLog(Msg,8)
        		
    
    			#self._cont_handler.startElement(name, attrs):
        		
        		#self._cont_handler.characters(content)
        		#self._cont_handler.endElement(name)
    		
        		self._cont_handler.endDocument()
			Msg = "parser OK"
			PCA_GenLib.WriteLog(Msg,9)
		except:
 			Msg = "parser Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
			PCA_GenLib.WriteLog(Msg,0)
			raise
			
	def getContentHandler(self):
        	"Returns the current ContentHandler."
        	return self._cont_handler

	def setContentHandler(self, handler):
        	"Registers a new object to receive document content events."
        	self._cont_handler = handler


    
if __name__ == '__main__':

  def MainTest(XMLCFG):
	try:
		print 'Start Program ...'
		try:
			PCA_GenLib.DBXMLCFGInit(XMLCFG)	
			Message = "Test"
			handler = ContentHandler()
			parser = Parser()
			parser.setContentHandler(handler)
			parser.parse(Message)
				
		finally:
			PCA_GenLib.CloseLog()

	except:
 	  	print '\n\n uncaught ! < ',sys.exc_type,sys.exc_value,' >'
 	  	import traceback
		traceback.print_exc()  
		raise
     	
  ############################### Main Program ############################################	  
  try:	
  	print "Open cfg file"
	XMLCFG =  open("PCA_RCDProxy.cfg","r").read()
	
	MainTest(XMLCFG)
  except:
  	print "Error or .cfg configuration file not found"
 	print "Msg = : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
 	import traceback
	traceback.print_exc()  	
  	sys.exit()
  	
