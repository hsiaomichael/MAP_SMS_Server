#! c:\python22\python

########################################################################################
#
# Filename:    PCA_XMLParser.py
#
# Description
# ===========
#
#  XML String Parser
#
#
# Author        : Michael Hsiao
#
# Date   	: 2003/06/16
# Desc          : Initial 
########################################################################################


import string
import sys

#############################################################################
# return the Section in the form <StartTag>XXX</EndTag>. 
# of a field given TAG
#############################################################################

def GetTagSection(XMLString,StartTag,EndTag):
	#print "YourXMLString =%s" % XMLString
  	StartPos = string.find(XMLString,StartTag)  
  	if (StartPos == -1 ):
    		Msg = "GetTagSection -- StartTag Not Found !"
    		raise Msg,1
    		
    	#print "StartPos = %s" % StartPos	
        
        EndPos = string.find(XMLString,EndTag)  
  	if (EndPos == -1 ):
    		Msg = "GetTagSection -- EndTag Not Found !"    		
    		raise Msg,2
    		
  	#print "EndPos = %s" % EndPos  	
 	
  	FieldValue = XMLString[StartPos:EndPos+len(EndTag)]    	
  	#return string.strip(FieldValue),XMLString[EndPos+len(EndTag):]
  	return FieldValue,XMLString[EndPos+len(EndTag):]
  	
##########################################################################
# return the value of a field given in the form <TAG>XXX</TAG>. 
# XXX will be returned in this case.
##########################################################################
	
def GetTagValue(XMLString):
	#print "YourXMLString =%s" % XMLString
	
  	StartPos = string.find(XMLString,">")  
  	if (StartPos == -1 ):    		  
    		Msg = "GetTagValue -- StartTag Not Found !"
    		raise Msg,3
    		
    	#print "StartPos = %s" % StartPos    	
        
        EndPos = string.find(XMLString[1:-1],"<")  
  	if (EndPos == -1 ):
    		Msg = "GetTagValue -- EndTag Not Found !"    		
    		raise Msg,4
    		
  	#print "EndPos = %s" % EndPos    	  	
 	
  	FieldValue = XMLString[StartPos+1:EndPos+1]
  	return FieldValue;
  	
##########################################################################
# return the value of a given TAG from a given XML String. 
# 
##########################################################################
	
def GetXMLTagValue(CMD,Tag):
   try:
	StartTag = "<%s>" % Tag
  	EndTag = "</%s>" % Tag
  	MyValue,CMD = GetTagSection(CMD,StartTag,EndTag)
  	
  	#print "Section : %s" % MyValue
  	Field = GetTagValue(MyValue);
   	return string.strip(Field);
   except :
   	#print "GetXMLTagValue : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
   	raise

##########################################################################
# Set XML String Tag value to Python Dictionary  
# 
##########################################################################
def XMLToDict(XMLString):
	XMLDict = {}
	x=1
	
	return {}

##########################################################################
# Set XML String Tag value to Python List  
# 
##########################################################################
def XMLToList(XMLString):
	XMLList = []
	
	
	return []
##############################################################################################################
	
if __name__ == '__main__': 
 
  try :
	#CMD = "<CMD000159>AddServiceProvider<TID>123</TID><USER>snssadmn</USER><PARAMETERS><CODE>MYPROV</CODE><DESC>VERY NICE SERVICE PROVIDER</DESC></PARAMETERS></CMD000159>"
	CMD = "<BMSPOST><MSISDN>0937344313</MSISDN><Tariff>Prepay_L</Tariff><Mode>I</Mode><Barred>N</Barred><SCP>2SCP2</SCP><Action>A</Action><Status>Success</Status></BMSPOST>" 
	
	XMLCFG =  open("cs_XMLProv.cfg","r").read()
	
	
	try:
		
		
		CMD = "<BMSPOST><MSISDN>0999999990</MSISDN></BMSPOST><BMSPOST><MSISDN>0999999991</MSISDN></BMSPOST>"
		#CMD = "<BMSPOST><MSISDN>0999999990</MSISDN></BMSPOST>"
		XMLString = CMD
		
		StartTag="<BMSPOST>"
		EndTag ="</BMSPOST>"
		
		#Tag = "NUMOFTAG"
		#TagValue = GetXMLTagValue(XMLString,Tag)
		#print 'Total Number of Socket Tag <%s> = *%s*' % (Tag,TagValue)
		
		#for i in range(string.atoi(TagValue)):		
		#	Tag = "TAG%s" % i
		#	TagValue = GetXMLTagValue(XMLString,Tag)
		#	print 'The Field for Tag <%s> = *%s*' % (Tag,TagValue)
		
		##while (XMLString != ''):
		#	ReturnSection,XMLString = GetTagSection(XMLString,StartTag,EndTag)
		XMLString = "<BMSPOST><MSISDN>0999999990</MSISDN></BMSPOST><BMSPOST>"
		line=''
		try:
			ReturnSection,line = GetTagSection(XMLString,StartTag,EndTag)
			print "Your Section Return = *%s*" % ReturnSection
		except:
			line=XMLString
		
		NewString="<MSISDN>0999999991</MSISDN></BMSPOST>"
		NewXMLString =line+NewString
		
		print "New String =*%s*" % NewXMLString
		ReturnSection,line = GetTagSection(NewXMLString,StartTag,EndTag)
		print "Your Section Return = *%s*" % ReturnSection
		
			
			
	except :
		#print 'The Field for Tag <%s> Not Found  ' % Tag
		print "Msg = <%s>,<%s>" % (sys.exc_type,sys.exc_value)
		
  except SystemExit:
  	print "",
  except:
  	
   	print "Main Program : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
   	
