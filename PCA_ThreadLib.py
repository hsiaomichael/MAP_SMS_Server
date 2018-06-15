
########################################################################################
#
# Filename:    PCA_ThreadLib.py
#  
# Description
# =========== 
#
#
# Author        : Michael Hsiao 
#
# Date   	: 2004/9/13
# Desc          : Thread Lib 
########################################################################################

import thread,threading,sys
import PCA_GenLib


# Global data
terminate_flag = "FALSE"
main_terminate_flag = 'FALSE'
ThreadQueue = []

TerminateMutex = thread.allocate_lock()		
#TerminateMutex.acquire()
#TerminateMutex.release()
#CondMutex = thread.allocate_lock()	
TerminateCondition = threading.Condition()

def SetTerminateFlag( flag ):
	try:
		Msg = "SetTerminateFlag = <%s> " % flag
		PCA_GenLib.WriteLog(Msg,7)
		TerminateMutex.acquire()
		global terminate_flag
		terminate_flag = flag
		TerminateMutex.release()
	
		return
 	except:	
  		Msg = "SetTerminateFlag  Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise
  		
def GetTerminateFlag ():
	try:
		Msg = "GetTerminateFlag "
		PCA_GenLib.WriteLog(Msg,8)
		TerminateMutex.acquire()
		global terminate_flag	
		flag = terminate_flag
		Msg = "GetTerminateFlag = <%s>" % flag
		PCA_GenLib.WriteLog(Msg,7)
		TerminateMutex.release()	
		return flag
 	except:	
  		Msg = "GetTerminateFlag  Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise
  		

def SetMainTerminateFlag ( flag ):
	try:
		Msg = "SetMainTerminateFlag = <%s> " % flag
		PCA_GenLib.WriteLog(Msg,7)
		TerminateMutex.acquire()
		
		global main_terminate_flag
		
		main_terminate_flag = flag
			
		Msg = "TerminateCondition.acquire"
		PCA_GenLib.WriteLog(Msg,7)
		
		TerminateCondition.acquire()
		
		Msg = "TerminateCondition.notify"
		PCA_GenLib.WriteLog(Msg,7)
		
		TerminateCondition.notify() 	
		TerminateCondition.release()
		
		TerminateMutex.release()
	
		return
 	except:	
  		Msg = "SetMainTerminateFlag  Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise
  		
def GetMainTerminateFlag ( ):
	try:
		Msg = "GetMainTerminateFlag "
		PCA_GenLib.WriteLog(Msg,9)
		
		
		TerminateMutex.acquire()
		global main_terminate_flag	
		flag = main_terminate_flag
		Msg = "GetMainTerminateFlag = <%s>" % flag
		
		PCA_GenLib.WriteLog(Msg,7)
		TerminateMutex.release()	
		return flag
		
	
 	except:	
  		Msg = "GetMainTerminateFlag  Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise

def RegisterThread ( ThreadName,ThreadID):
	try:
		Msg = "RegisterThread "
		PCA_GenLib.WriteLog(Msg,5)
		TerminateMutex.acquire()
		ThreadInfo = [ThreadName]  + [ThreadID]
    		ThreadQueue.append(ThreadInfo)
		TerminateMutex.release()
		return
 	except:	
  		Msg = "RegisterThread Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise
  		
def UnregisterThread(ThreadName):
	try:
		TerminateMutex.acquire()
		Msg = "UnregisterThread "
		PCA_GenLib.WriteLog(Msg,5)
		index = 0
		for ThreadInfo in ThreadQueue:
			if ( ThreadInfo[0] == ThreadName ) :
				break;
			index = index + 1
			
		del ThreadQueue[index]
				
		
		TerminateMutex.release()
		return
 	except:	
  		Msg = "UnregisterThread Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise

def FindThreadByThreadID(ThreadID):
	try:
		TerminateMutex.acquire()
		Msg = "FindThreadByThreadID "
		PCA_GenLib.WriteLog(Msg,0)
		for ThreadInfo in ThreadQueue:
			if ( ThreadInfo[1] == ThreadID ) :
				ThreadName = ThreadInfo[0]
				Msg = "ThreadName=<%s>" % ThreadName
				PCA_GenLib.WriteLog(Msg,0)
				break;
		TerminateMutex.release()
		return
 	except:	
  		Msg = "FindThreadByThreadID Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise
	


def FindThreadByName(ThreadName):
	try:
		TerminateMutex.acquire()
		Msg = "FindThreadByName "
		PCA_GenLib.WriteLog(Msg,0)
		for ThreadInfo in ThreadQueue:
			if ( ThreadInfo[0] == ThreadName ) :
				ThreadID = ThreadInfo[1]
				Msg = "ThreadID=<%s>" % ThreadID
				PCA_GenLib.WriteLog(Msg,0)
				break;
		TerminateMutex.release()
		return
 	except:	
  		Msg = "FindThreadByName Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise
	



def PrintList ():
	try:
		TerminateMutex.acquire()
		Msg = "PrintList "
		PCA_GenLib.WriteLog(Msg,0)
		for ThreadInfo in ThreadQueue:
			ThreadName = ThreadInfo[0]
			ThreadID = ThreadInfo[1]
			Msg = "ThreadName=<%s>,ThreadID=<%s>" % (ThreadName,ThreadID)
			PCA_GenLib.WriteLog(Msg,0)
			
		TerminateMutex.release()
		return
 	except:	
  		Msg = "FindThreadByName Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise

def WaitForCondition ():
	try:
		TerminateCondition.acquire()
		
		
		Msg = "WaitForCondition "
		PCA_GenLib.WriteLog(Msg,0)
		
		TerminateCondition.wait()
		TerminateCondition.release()
		return
 	except:	
  		Msg = "WaitForCondition Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
		PCA_GenLib.WriteLog(Msg,0)	
  		raise
	
		
