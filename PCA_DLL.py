#!/usr/local/bin/python2.3
########################################################################################
#
# Filename:    PCA_DLL.py
#  
# Description
# ===========
# 
#
#
# Author        : Michael Hsiao 
#
# Create Date   : 2004/10/11
# Desc          : Module for Load Python Module synamic
########################################################################################

import sys, string ,os

import PCA_GenLib
import PCA_XMLParser



						
##########################################################		
##  This wrapper facade defines a portable interface to	##
## program various DLL operations. the <OS::*> 
## methods are lower-level wrapper facades that
## encapsulate the variation among explicit dynamic
## linking APIs defined on different operation
## system
##########################################################
	
class DLL:
	handle_ = -1 
	python_file_name_ = -1
	##########################################################		
	## Opens and synamically links the DLL<dll_name>	##
	##							##
	##########################################################
	def __init__(self,dll_name):		
		try:	
			Msg = "DLL Init ..."
			PCA_GenLib.WriteLog(Msg,9)
			
			Msg = "DLL name = <%s>" % dll_name
			PCA_GenLib.WriteLog(Msg,9)
			
			# OS::dlopen (dll_name.c_str())
			#self.handle =  dll_name
			 
			self.python_file_name_ = dll_name
			
			#self.python_file_name_ = __import__(dll_name)
			#reload(self.python_file_name_)
			
			
			Msg = "DLL OK..."
			PCA_GenLib.WriteLog(Msg,9)
    							
		except :
			Msg = "DLL Initial error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
			PCA_GenLib.WriteLog(Msg,0)			
			raise
			
	###################################################################		
	## IF <symbol_name> is in the symbol table of DLL
	## i.e Class in <DLL> module
	## 
	###################################################################
	def symbol(self,symbol_name):
		try:  				
			Msg = "symbol init..."
			PCA_GenLib.WriteLog(Msg,9)
			
			Msg = "synmol name = <%s>" % symbol_name
			PCA_GenLib.WriteLog(Msg,9)
			
			## This will return a handle point to 
			##  symbol_name (class in file ) in self.handle(python file name)
			#return self.importName(self.handle,symbol_name)
			module = __import__(self.python_file_name_)
			reload(module)
			
			self.handle = self.importName(self.python_file_name_,symbol_name)
			
			
			Msg = "symbol OK..."
			PCA_GenLib.WriteLog(Msg,9)	
			
			return self.handle
								
                					
		except :
			Msg = "symbol error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
			PCA_GenLib.WriteLog(Msg,0)			
			raise
			
	def importName(self,modulename,name):
		try:  				
			Msg = "importName init..."
			PCA_GenLib.WriteLog(Msg,9)
		
			try:
			
				module = __import__(modulename,globals(),locals(),[name])
			except ImportError:
				return None
			data = vars(module)[name]
			Msg = "importName OK...<%s>" % data
			PCA_GenLib.WriteLog(Msg,9)
			
			return data
		except :
			Msg = "importName error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
			PCA_GenLib.WriteLog(Msg,0)			
			raise

	#############################################################		
	##							   ##
	#############################################################
	def Destory(self):
		try:  				
			Msg = "Destory init..."
			PCA_GenLib.WriteLog(Msg,9)	
			
			Msg = "Destory OK..."
			PCA_GenLib.WriteLog(Msg,9)			
                					
		except :
			Msg = "Destory error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
			PCA_GenLib.WriteLog(Msg,0)			
			raise


########################################################################


###############################################################################
##	Main Program
###############################################################################
if __name__ == '__main__':

  def MainTest(XMLCFG):
  	try:
		print 'Start MainTest ...'
		try:
			PCA_GenLib.DBXMLCFGInit(XMLCFG)		
			try:				
				Msg = "MainTest StartUp ... 2004/10/11 Version 1.0"
				PCA_GenLib.WriteLog(Msg,0)	
				
				
				
				Tag = "content_parser"
				dll_file_name = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
				Script_File = DLL(dll_file_name)
				factory_function="Parser"
				factory_component = Script_File.symbol(factory_function)
				parser = factory_component()
				
				Tag = "content_handler"
				dll_file_name = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
				Script_File = DLL(dll_file_name)
				factory_function="ContentHandler"
				factory_component = Script_File.symbol(factory_function)
				handler = factory_component()
					
				
			finally:
			
				PCA_GenLib.WriteLog(Msg,0)
			
		finally:
	
			PCA_GenLib.CloseLog()
 	except IOError:        
		print "MainTest IO error"
		print '< ',sys.exc_type,sys.exc_value,' >'

 	except:
   		print 'MainTest uncaught ! < ',sys.exc_type,sys.exc_value,' >'
   		import traceback
		traceback.print_exc()
	
  try:	
  	print "Open cfg file"
	XMLCFG =  open("PCA_CommandFile.cfg","r").read()
	#cfg_file_name = "/usr/aethos/snss/current/bin/%s" % sys.argv[1]
	#XMLCFG =  open(cfg_file_name,"r").read()
	MainTest(XMLCFG)
  except:
  	print "configuration file not found"
 	print "Msg = : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
  	sys.exit()

   	
  print "Bye !"
	
			
