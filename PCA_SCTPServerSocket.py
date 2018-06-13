
########################################################################################
#
# Filename:    PCA_SCTPServerSocket.py
#  
# Description
# ===========
# SCTP Server Socket 
#
# This program is not to be copied or
# distributed without the express written consent of Author. No part of this
# program may be used for purposes other than those intended by Author.
#
# Author    : Michael Hsiao 
#
# Date      : 2016/09/04
#
# Description
# ===========
# SCTP Server Template
# 

import sys, time,string
import sctp,socket,select
import PCA_GenLib
import PCA_XMLParser


class Acceptor:
 
  ConnectionLoginState = {}
  ########################################################		
  ## Init Socket Environment and set socket option   
  ########################################################
  def __init__(self,XMLCFG):		
    try:	
      Msg = "Prepare SCTP Server ..."
      PCA_GenLib.WriteLog(Msg,9)
      self.XMLCFG = XMLCFG	
      Tag = "LISTEN_HOST"
      host = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
      self.host = host		
			
      Tag = "LISTEN_PORT"
      port = PCA_XMLParser.GetXMLTagValue(XMLCFG,Tag)
      self.port = string.atoi(port)
			
      Msg = "Listen Host=<%s>,Port=<%s>" % (self.host,self.port)
      PCA_GenLib.WriteLog(Msg,1)
      self.SocketConnectionPool, self.ReadSet = [], []

      SocketDescriptor = sctp.sctpsocket_tcp(socket.AF_INET)
      if self.host == "any":
        SocketDescriptor.bind(("", self.port))
      else:
        SocketDescriptor.bind((self.host, self.port))
      SocketDescriptor.listen(5)
      self.SocketConnectionPool.append(SocketDescriptor) # add to main list to identify
      self.ReadSet.append(SocketDescriptor)    
    except :
      Msg = "SelectServer Initial error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)			
      raise
			
  ########################################################		
  ## SCTP dispatcher	 
  ########################################################
  def dispatcher(self,TimeOut):
    try:
      Msg = "dispatcher "
      PCA_GenLib.WriteLog(Msg,9)	

      while 1:			       
        readables, writeables, exceptions = select.select(self.ReadSet,[], [],TimeOut)    				
        for self.SocketConnection in readables:    				 	
          ##################################
          #### for ready input sockets #####
          ##################################
          if self.SocketConnection in self.SocketConnectionPool:  
            ####################################
            ## port socket: accept new client ##
            ## accept should not block	  ##
            ####################################
            connection, address = self.SocketConnection.accept()
            Msg = 'Dispatcher New Connection <%s> from :%s' % (id(connection),address)   # connection is a new socket        	    				
            PCA_GenLib.WriteLog(Msg,1)   
            self.ReadSet.append(connection)                # add to select list, wait
          else:
            try:
              ##################################################
              ##  Check the first request message from client ##
              ##################################################
              if not self.ConnectionLoginState.has_key(id(self.SocketConnection)):
                self.ConnectionLoginState[id(self.SocketConnection)] = 'N'
                Msg = "Set ConnectionLoginState <%s> to N " % id(self.SocketConnection)
                PCA_GenLib.WriteLog(Msg,2)
            						
                ClientMessage = self.SocketConnection.recv(2048)            					
                if not ClientMessage:
                  self.SocketConnection.close()                   # close here and remv from
                  self.ReadSet.remove(self.SocketConnection)      # del list else reselected 
                  Msg = "Del ConnectionLoginState <%s>" % id(self.SocketConnection)
                  PCA_GenLib.WriteLog(Msg,1)
                  del self.ConnectionLoginState[id(self.SocketConnection)]
                  Msg = "Client Close Connection ....address = ('%s',%s)" % (address[0],address[1])
                  PCA_GenLib.WriteLog(Msg,1)
                						 
                else:
                  ClientMessage = "server first echo : %s" % ClientMessage
                  self.sendDataToSocket(self.SocketConnection,ClientMessage)   

              else:
                Message = self.readDataFromSocket(self.SocketConnection,Length=1024,TimeOut = 1.0)
                if Message != None:
                  Message = "server rest echo : %s" % Message
                  self.sendDataToSocket(self.SocketConnection,Message) 
				  
            except socket.error:
              Msg = "Dispatcher error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
              PCA_GenLib.WriteLog(Msg,0)	
              self.SocketConnection.close()                   # close here and remv from
              self.ReadSet.remove(self.SocketConnection)      # del list else reselected 
              del self.ConnectionLoginState[id(self.SocketConnection)]
     
					
      Msg = "dispatcher OK"
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "dispatcher error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      self.close()
      
      raise			
  ########################################################		
  ## SCTP Def Non-Block I/O Send Socket Data		 
  ########################################################
  def sendDataToSocket(self,SocketEventFD,Message):
    try:
      Msg = "sendDataToSocket "
      PCA_GenLib.WriteLog(Msg,9)			

      Msg = "send : id=<%s>,data=<%s>" % (id(SocketEventFD),Message)
      PCA_GenLib.WriteLog(Msg,3)
      #SocketEventFD.send(Message) 
      to=("",0)
      ppid=50331648
      SocketEventFD.sctp_send(Message,to,ppid)


      Msg = "sendDataToSocket OK"
      PCA_GenLib.WriteLog(Msg,9)
      return 1     
    except:
      Msg = "sendDataToSocket error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise
	  
 ########################################################		
  ## SCTP Def Read Socket Data use non-blocking read		
  ########################################################
  def readDataFromSocket(self,SocketFD , Length=1024,TimeOut = 1.0):
    try:
      Msg = "readDataFromSocket "
      PCA_GenLib.WriteLog(Msg,9)
			   				  		
      Message = SocketFD.recv(Length)  
      if not Message:
        Msg = "server close connection"
        PCA_GenLib.WriteLog(Msg,0)
        raise socket.error,"server close connection"

      Msg = "ReadDataFromSocket OK"
      PCA_GenLib.WriteLog(Msg,9)
      return Message
				
			
      #Msg = "ReadDataFromSocket retry time out !"
      #PCA_GenLib.WriteLog(Msg,3)
      #return None
			
    except socket.error:
      Msg = "ReadDataFromSocket socket error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise
	
    except:
      Msg = "ReadDataFromSocket error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      raise	

	  
  ########################################################		
  ## Close Socket					     
  ########################################################					
  def close(self):
    try:
      Msg = "Close Socket Init"
      PCA_GenLib.WriteLog(Msg,9)
    
	
      for SocketFD in self.ReadSet:
        try:
          Msg = "close Socket id=<%s>" % id(SocketFD)
          PCA_GenLib.WriteLog(Msg,1)
          SocketFD.close()
        except:
          Msg = "close Socket error id=<%s>" % id(SocketFD)
          PCA_GenLib.WriteLog(Msg,1)
					
      Msg = "Close connection from Host=<%s>,Port=<%s>" % (self.host,self.port)
      PCA_GenLib.WriteLog(Msg,1)
				
      #self.SocketDescriptor.close()	
			
      Msg = "Close Socket OK"
      PCA_GenLib.WriteLog(Msg,9)			
    except sctp.socket.error:
      Msg = "Connection close"
      PCA_GenLib.WriteLog(Msg,0)			
    except:
      Msg = "Close Socket Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
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
        Server = Acceptor(XMLCFG)
        try:
          Server.dispatcher(TimeOut=1.0)
        finally:				
          Server.close()
      finally:
        PCA_GenLib.CloseLog()

    except KeyboardInterrupt:
        print "\n Bye ! \n"
        return 1
    except:
      print '\n\n uncaught ! < ',sys.exc_type,sys.exc_value,' >'
      import traceback
      traceback.print_exc()  
      raise

#################################################################
  try:	
	XMLCFG =  open("SCTPServer.cfg","r").read()
	MainTest(XMLCFG)
  except:
  	print "Error or .cfg configuration file not found"
 	print "Msg = : <%s>,<%s>" % (sys.exc_type,sys.exc_value)
 	import traceback
	traceback.print_exc()  	
  	sys.exit()
	
		



