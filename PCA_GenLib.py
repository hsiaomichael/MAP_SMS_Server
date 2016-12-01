#!/home/snadmin/bin/aepython
import sys,traceback
import time,string
import os,stat,signal
import thread
import PCA_XMLParser


ExitFlag = 0

########################################################################################
#
# Filename:    PCA_ThreadGenLib.py
#  
# Description
# ===========
# 
#
#
# Author        : Michael Hsiao 
#
# Date 		: 2004/09/10
# Desc          : Debug Log Module for Multi-Thread programming
########################################################################################

#SignalFlag = 0

Message = { '000' : 'Success',
	    '010' : 'VerifyCommand.py Command Syntax Error',
	    '020' : 'DB_Util.py Database Error',
	    '030' : 'chtsub.py Subscription Error',
	    '040' : 'FTPCommandFile class Error',
	    '050' : 'Main Program Error',
	    '060' : 'Socket Message Format Error',
	    '099' : 'Unknow Error'}

########################################################		
## convert string to bcd	     
######################################################## 
def converStringToBCD(data):
  try:		
    Digits = ""
    length_of_digits = len(data)/2
    j = 0
   
    for i in range(length_of_digits):          
      tmp = int(data[j:j+2],16)
      Digits = Digits + chr(int(tmp))
      j = j + 2
    
    BCDString = Digits	
    return BCDString
  except:
    Msg = "converStringToBCD Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
    raise Msg


########################################################		
## convert string to bcd	     
######################################################## 
def converStringToReverseBCD(data):
  try:		
    Digits = ""
    length_of_digits = len(data)/2
    j = 0
   
    for i in range(length_of_digits):    
      dig = data[j+1] + data[j]      
      tmp = int(dig,16)
      Digits = Digits + chr(int(tmp))
      j = j + 2
    
    BCDString = Digits	
    return BCDString
  except:
    Msg = "converStringToReverseBCD Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
    raise Msg
########################################################		
## convert ascii to hex and character format	      ##
## retur a string (	      ##
######################################################## 
def getHexBCDString(data):
	try:
		ASCIIData = ToASCII(data)
		HexString = ''
   		
       	 	for ascii_value in ASCIIData:
       	 		hex_data = hex(ascii_value)
       	 		if (len(hex_data) == 3):
        			#hex_data = '0x0%s' % hex_data[-1]
        			hex_data = '0%s' % hex_data[-1]
			else:
        			hex_data = '%s' % hex_data[2:]
        		
        		HexString = "%s%s%s" % (HexString,hex_data[1],hex_data[0])    
        		
        	return HexString
	except:
   		Msg = "getHexString Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		#cs_GenLib.WriteLog(Msg,0)	
  		raise	Msg

########################################################		
## convert ascii to hex and character format	      ##
## retur a string (	      ##
######################################################## 
def getOctString(data):
	try:
		ASCIIData = ToASCII(data)
		OctString = ''
   		
       	 	for ascii_value in ASCIIData:
        		OctString = "%s%s" % (OctString,ascii_value)    
        		
        	return OctString
	except:
   		Msg = "getOctString Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		#cs_GenLib.WriteLog(Msg,0)	
  		raise	Msg
########################################################		
## convert ascii to hex and character format	      ##
## retur a string (	      ##
######################################################## 
def getHexString(data):
	try:
		ASCIIData = ToASCII(data)
		HexString = ''
   		
       	 	for ascii_value in ASCIIData:
       	 		hex_data = hex(ascii_value)
       	 		if (len(hex_data) == 3):
        			#hex_data = '0x0%s' % hex_data[-1]
        			hex_data = '0%s' % hex_data[-1]
			else:
        			hex_data = '%s' % hex_data[2:]
        		
        		HexString = "%s%s" % (HexString,hex_data)    
        		
        	return HexString
	except:
   		Msg = "getHexString Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		#cs_GenLib.WriteLog(Msg,0)	
  		raise	Msg

########################################################		
## convert ascii to hex and character format	      ##
## retur a string (	      ##
######################################################## 
def getHexIMSIString(data):
	try:
		ASCIIData = ToASCII(data)
		HexString = ''
   		
       	 	for ascii_value in ASCIIData:
       	 		hex_data = hex(ascii_value)
       	 		if (len(hex_data) == 3):        			
        			hex_data = '%s0' % hex_data[-1]
			else:
        			hex_data = '%s%s' % (hex_data[3],hex_data[2])
        		
        		HexString = "%s%s" % (HexString,hex_data)    
        		
        	return HexString
	except:
   		Msg = "getHexString Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		#cs_GenLib.WriteLog(Msg,0)	
  		raise	Msg
########################################################		
## convert ascii to hex and character format	      ##
## retur a string (just print it for debug )	      ##
######################################################## 
def HexDump(data):
	try:
		ASCIIData = ToASCII(data)
		chr_list = []
		DebugString = []
   		new_line = 8
   		#print "[",
       	 	for ascii_value in ASCIIData:
       	 		if new_line == 8:       	 			
       	 			DebugString.append("[")
				
       	 		hex_data = hex(ascii_value)
       	 		if (len(hex_data) == 3):
        			#hex_data = '0x0%s' % hex_data[-1]
        			hex_data = '0%s' % hex_data[-1]
			else:
        			hex_data = '%s' % hex_data[2:]
				
			
        		
        		DebugString.append(hex_data)    
        		chr_val = chr(ascii_value)    
        		#if ( (ord(chr_val) == 13) or (ord(chr_val) == 10) ):   # prevent '\r' , '\n' character 
        		if not chr_val.isalnum():
        		       		
        			chr_val = ' '
        		chr_list.append(chr_val+"|") 
        		
        		new_line = new_line - 1
        		if new_line == 0:
        			new_line = 8
        			
        			DebugString.append("] ==> ")    
        			
        			DebugString = DebugString + chr_list
        			DebugString.append("\n")
        			chr_list = []
        	
        	
        	if new_line > 0 and new_line < 8:
        		for i in range(new_line):        			
        			DebugString.append("    ")
        		
        		DebugString.append("] ==> ")
		        		
        	DebugString = DebugString + chr_list
        	Data = string.join(DebugString," ")
        	return " "+Data	
	except:
   		Msg = "HexDump Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		#cs_GenLib.WriteLog(Msg,0)	
  		raise	Msg
########################################################		
## Convert String to ascii format		      ##
##						      ##
########################################################
def ToASCII(data):
	try:
   		Result = []
        	ascii_data = map(ord,data)
        	for a in ascii_data:
        		Result.append(a)
        
		return Result
 	except:
   		Msg = "ToASCII Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		#cs_GenLib.WriteLog(Msg,0)	
  		raise Msg
 
  
 

def onSignal(signum,stackframe):
	global PrintDebugLogLevel
	try:
		Msg = '%s : Got signal <%s> ' % (os.path.basename(sys.argv[0]),signum)
		print Msg	
	
		if (signum == signal.SIGUSR1):		
			#print "Increase Debug Log"
			ChangeDebugLevel("+")
			Msg = "Debug level Changed to <%s>" % PrintDebugLogLevel
			WriteLog(Msg,0)
			#print Msg
			
		elif (signum == signal.SIGUSR2):		
			#print "Reduce Debug Log"
			ChangeDebugLevel("-")
			Msg = "Debug level Changed to <%s>" % PrintDebugLogLevel
			WriteLog(Msg,0)
			#print Msg
		else:	
			print "%s Exit" % os.path.basename(sys.argv[0])
	   		sys.exit()
	except:
		Msg = 'cs_GenLib.py uncaught ! < ',sys.exc_type,sys.exc_value,' >'
		print Msg
		sys.exit()
		


def SetProgramSignal():
	
	if (sys.platform != 'win32'):
		signal.signal(signal.SIGINT,onSignal)
		signal.signal(signal.SIGTERM,onSignal)
		signal.signal(signal.SIGQUIT,onSignal)
		signal.signal(signal.SIGHUP,onSignal)
		signal.signal(signal.SIGUSR1,signal.SIG_IGN)
		signal.signal(signal.SIGUSR2,signal.SIG_IGN)
		signal.signal(signal.SIGUSR1,onSignal)
		signal.signal(signal.SIGUSR2,onSignal)
		signal.signal(signal.SIGCHLD,signal.SIG_IGN)
	else:
		signal.signal(signal.SIGINT,onSignal)
		signal.signal(signal.SIGTERM,onSignal)		
	return

def get_time():
	CurrentSeconds = time.time()
	
	CurrentFloatSeconds = "%15.3f" % CurrentSeconds
  	CurrentFloatSeconds = string.split(CurrentFloatSeconds,'.')[1]
	date_tuple =  time.localtime(CurrentSeconds)		
	log_msg_date = "%04d-%02d-%02d %02d:%02d:%02d" % (date_tuple[0:6])
	log_msg_date = "%s.%s" % (log_msg_date,CurrentFloatSeconds) 
	log_name_date = "%04d-%02d-%02d_%02d-%02d-%02d" % (date_tuple[0:6])
	return log_msg_date,log_name_date
		
############################################################
## Debug Log Function , provide level 0~9 debug log
## setup environment variable
## DB_PRINT : Print Debug Message to stdin
## DB_FLUSH : flush file descriptor
## DLVL_ProgramName : Debug Log Level
## DLOG_ProgramName : Debug Log Full File Name
############################################################
def DBXMLCFGInit(XMLCFG):
   try:
   	global RequestMutex
	RequestMutex = thread.allocate_lock()
	
	global FileLineNo	
	global FileNameSeqNo	
	global DebugLogFileName	
	global PrintDebugLogLevel
	global PrintDebug	
	global FlushFile
	
	FileLineNo = 0
	PringDebug = 0
	DebugLogFileName = 'Debug.log'
	FileNameSeqNo = 1
	FileLineNo = 0	
	FlushFile = 0

	ProgramName = os.path.basename(sys.argv[0])		
	################ Get Debug Log File Name ######################### 
	process_id = os.getpid() 	
	try:
		Tag = "DLOG"
		filename = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
		if (filename[-1] == "+"):
					
			DebugLogFileName = "%s.%05d" % (filename[:-1],process_id)
		else:
			DebugLogFileName = filename	
	except :
		DebugLogFileName = "%s.%05d" % (ProgramName,process_id)		
		
	################ Get Debug Log Level ######################### 	
	try:			
		Tag = "DLVL"
		PrintDebugLogLevel = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))
		#print 	"Your Debug Level = <%s>" % PrintDebugLogLevel
	except KeyError:
		PrintDebugLogLevel  = 0
		
	############### Flush Debug Log  ######################### 
	try:	
		Tag = "DB_FLUSH"
		FlushFile = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))
	except KeyError:
		FlushFile = 0
		
	################ Print Message to stdin ######################### 
	try:			
		Tag = "DB_PRINT"
		PrintDebug = string.atoi(PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag))
	except KeyError:		
		PrintDebug = 0	
	OpenLog() 
   except:
   	Msg = "DBXMLCFGInit error <%s>,<%s>" % (sys.exc_type,sys.exc_value)
   	print Msg
   	raise
def DBInit(LogFileName=None):
	global FileLineNo	
	global FileNameSeqNo	
	global DebugLogFileName	
	global PrintDebugLogLevel
	global PrintDebug	
	global FlushFile
	
	FileLineNo = 0
	PringDebug = 0
	DebugLogFileName = 'Debug.log'
	FileNameSeqNo = 1
	FileLineNo = 0	
	FlushFile = 0

	ProgramName = os.path.basename(sys.argv[0])			
	
	################ Get Debug Log File Name ######################### 
	DebugLogFileEnv = "DLOG_%s" % ProgramName	
	process_id = os.getpid() 	
	try:			
		filename = os.environ[DebugLogFileEnv]
		if (filename[-1] == "+"):
					
			DebugLogFileName = "%s.%05d" % (filename,process_id)
		else:
			DebugLogFileName = filename
		
	except KeyError:
		DebugLogFileName = "%s.%05d" % (ProgramName,process_id)	
	
	################ Get Debug Log Level ######################### 	
	DebugLogLevelEnv = "DLVL_%s" % ProgramName	
	try:			
		PrintDebugLogLevel  = "%s" % (os.environ[DebugLogLevelEnv])		
	except KeyError:
		PrintDebugLogLevel  = 0		
	############### Flush Debug Log  ######################### 
	try:					
		FlushFile = "%s" % (os.environ["DB_FLUSH"])			
	except KeyError:
		FlushFile = 0		
	################ Print Message to stdin ######################### 
	try:					
		PringDebug = "%s" % (os.environ["DB_PRINT"])			
	except KeyError:		
		PrintDebug = 0
	
	if (LogFileName):
		DebugLogFileName = LogFileName	
	OpenLog() 
		
def OpenLog():        	
	try:
		global RequestMutex
		#print "RequestMutex.release"
		try:
			RequestMutex.release()  	
		except :
			x=1
		#print "RequestMutex.acquire"
      		RequestMutex.acquire()
      		
		global LOGFILE	
		global FileLineNo
		FileLineNo = 0
		#print "open %s" % DebugLogFileName
		LOGFILE = open(DebugLogFileName,"w+")
		#print "open OK"
		RequestMutex.release()  	
		Msg = "Debug level = <%s>, Debug log = <%s>" % (PrintDebugLogLevel ,DebugLogFileName)
		WriteLog(Msg,0)	
		
		#print "RequestMutex.acquire release"
	except:			
		#print "Open Debug File <%> Error ! ,<%s>,<%s>" % (DebugLogFileName,sys.exc_type,sys.exc_value)	
		#RequestMutex.release()  
		raise	

def WriteLog(msg="None",DebugLevel=9):	
    try:
   	global RequestMutex
      	RequestMutex.acquire()
    	global FileLineNo	
	global FileNameSeqNo	
	global DebugLogFileName	
	global PrintDebugLogLevel
	global PrintDebug	
	global FlushFile
	global LOGFILE
	#print "DebugLevel=<%s> , PrintDebugLogLevel=<%s>" % (DebugLevel,PrintDebugLogLevel )	
	if ( DebugLevel <= PrintDebugLogLevel ):	
		#print "print it"
		#date_tuple =  time.localtime(time.time())	
		log_msg_date = get_time()[0]		
		DebugMsg = traceback.extract_stack()
		MsgFile = os.path.basename(DebugMsg[-2][0])
		MsgLine = DebugMsg[-2][1]
		#print "Debug" ,traceback.extract_stack()
		FileMsg = "%s DB%s %s(%s)==> %s\n" % (log_msg_date,DebugLevel,MsgFile,MsgLine-1,msg)		
		LOGFILE.writelines([FileMsg])
		#### Debug Only ###########
		#print FileMsg		
									
		FileLineNo = FileLineNo + 1		
		MaxRecordInOneDebugLogFile = 10000
		if (FileLineNo > MaxRecordInOneDebugLogFile):				
			Arcihve_DebugFileName = "%s.%s" % (DebugLogFileName,FileNameSeqNo)
			FileNameSeqNo = FileNameSeqNo + 1
			Msg = "Debug Log File more than %s records , rename <%s> to <%s>" % (MaxRecordInOneDebugLogFile,DebugLogFileName,Arcihve_DebugFileName)
			#print Msg
			LOGFILE.writelines([Msg])        			
			LOGFILE.close()	
			try:
				
				os.unlink(Arcihve_DebugFileName)
			except:
				#print "unlink Error ! <%s>,<%s>" % (sys.exc_type,sys.exc_value)	  	
				x=1
			
			os.rename(DebugLogFileName,Arcihve_DebugFileName)			
			
			
			OpenLog()			
			
		
		if(PrintDebug != 0):
			print FileMsg,			
		
		if(FlushFile != 0):	
			try:		
				LOGFILE.flush()
			except:
				x=1
	RequestMutex.release()  

    except:
  	#print "DebugLog WriteLog Error ! <%s>,<%s>" % (sys.exc_type,sys.exc_value)
  	try:
  		RequestMutex.release()  
  	except:
  		x=1	  	
  	return		

def OldWriteLog(msg="None",DebugLevel=9):	
    try:
    	global FileLineNo	
	global FileNameSeqNo	
	global DebugLogFileName	
	global PrintDebugLogLevel
	global PrintDebug	
	global FlushFile
	global LOGFILE
	#print "DebugLevel=<%s> , PrintDebugLogLevel=<%s>" % (DebugLevel,PrintDebugLogLevel )	
	if ( DebugLevel <= PrintDebugLogLevel ):	
		#print "print it"
		#date_tuple =  time.localtime(time.time())	
		log_msg_date = get_time()[0]		
		DebugMsg = traceback.extract_stack()
		MsgFile = os.path.basename(DebugMsg[-2][0])
		MsgLine = DebugMsg[-2][1]
		#print "Debug" ,traceback.extract_stack()
		FileMsg = "%s DB%s %s(%s)==> %s\n" % (log_msg_date,DebugLevel,MsgFile,MsgLine,msg)		
		LOGFILE.writelines([FileMsg])
		#### Debug Only ###########
		#print FileMsg		
									
		FileLineNo = FileLineNo + 1		
		MaxRecordInOneDebugLogFile = 10000
		if (FileLineNo > MaxRecordInOneDebugLogFile):				
			Arcihve_DebugFileName = "%s.%s" % (DebugLogFileName,FileNameSeqNo)
			FileNameSeqNo = FileNameSeqNo + 1
			#Msg = "Debug Log File more than %s records , rename <%s> to <%s>" % (MaxRecordInOneDebugLogFile,DebugLogFileName,Arcihve_DebugFileName)
			#print Msg
			LOGFILE.writelines([Msg])        			
			LOGFILE.close()	
			try:
				os.unlink(Arcihve_DebugFileName)
			except:
				x=1
			os.rename(DebugLogFileName,Arcihve_DebugFileName)			
			OpenLog()			
		
		if(PrintDebug != 0):
			print FileMsg,			
		
		if(FlushFile != 0):		
			try:	
				LOGFILE.flush()
			except:
				x=1
    except:
  	print "DebugLog WriteLog Error ! <%s>,<%s>" % (sys.exc_type,sys.exc_value)	  	
  	raise		
  		  		
def ChangeDebugLevel(Mode):
	global PrintDebugLogLevel
	
	#print "Your Level = <%s> " % PrintDebugLogLevel
	if (Mode == "+"):			
		if ( PrintDebugLogLevel < 9):
			PrintDebugLogLevel = PrintDebugLogLevel + 1					
	else:		
		if (PrintDebugLogLevel > 0 ):
			PrintDebugLogLevel = PrintDebugLogLevel - 1	
		
	#Msg = "Debug level Changed to <%s>" % PrintDebugLogLevel
	#WriteLog(Msg,0)
		
def CloseLog():
	try:
		global LOGFILE
		global PrintDebugLogLevel
		global DebugLogFileName
		Msg = "Close Debug Log , Debug level = <%s>, Debug log = <%s>" % (PrintDebugLogLevel ,DebugLogFileName)
		#Msg = "Close Debug Log "
		WriteLog(Msg,0)
		LOGFILE.close()
	except:
		print "Close Debug Log fail,<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		raise


if __name__ == '__main__':
  SetProgramSignal()
  try:	
  	print "Open cfg file"
	XMLCFG =  open("cs_ModifyPIN.cfg","r").read()
  except:
  	print "cs_ModifyPIN.cfg configuration file not found"
 	print "Msg = : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
  	sys.exit()
  try:
	print 'Start Program ...'
	try:	 
		DBXMLCFGInit(XMLCFG)	
		for i in range(20):
			Msg = "Hello <%s>" % i
			WriteLog(Msg,1)
			
			if i > 10 :
				#time.sleep(200)
				ChangeDebugLevel("+")
			
	finally:
		CloseLog()
  except IOError:        
	print "cs_GenLib.py IO error"
	print '< ',sys.exc_type,sys.exc_value,' >'

  except:
   	print 'cs_GenLib.py uncaught ! < ',sys.exc_type,sys.exc_value,' >'
   	
  print "Finished"
