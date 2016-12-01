
########################################################################################
#
# Filename:    PCA_M3UAServerSocket.py
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
import PCA_SCTPServerSocket
import PCA_M3UAResponseParser


class Acceptor(PCA_SCTPServerSocket.Acceptor):
 
  ConnectionLoginState = {}  
  M3UAMessage = None
  def __init__(self,XMLCFG):

    try:	
     Msg = "Acceptor init"
     PCA_GenLib.WriteLog(Msg,0)
     
     PCA_SCTPServerSocket.Acceptor.__init__(self,XMLCFG)
    
     self.parser = PCA_M3UAResponseParser.Parser()
     self.handler = PCA_M3UAResponseParser.Handler(XMLCFG)
     self.parser.setContentHandler(self.handler)

     Msg = "Acceptor OK"
     PCA_GenLib.WriteLog(Msg,0)   
    except:
     Msg = "Acceptor Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	  
    

  ########################################################		
  ## M3UA dispatcher	 
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
                PCA_GenLib.WriteLog(Msg,1)
            		
                				
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
                #ClientMessage = "server first echo : %s" % ClientMessage
                #self.sendDataToSocket(self.SocketConnection,ClientMessage) 
                self.handle_event(self.SocketConnection,ClientMessage) 				  

				  
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
  ########################################################################
  # Return Message Error
  #
  #########################################################################
  def handle_event(self,conn,Message):
    try:	
     Msg = "handle_event init"
     PCA_GenLib.WriteLog(Msg,9)
	 
     Msg = "DEBUG con=<%s> msg = *\n%s\n*" % (id(conn),PCA_GenLib.HexDump(Message))
     PCA_GenLib.WriteLog(Msg,0)

     self.parser.parse(Message)
     response_message = self.handler.getHandlerResponse()

     ServerID = self.handler.getTID()
     DebugStr = self.handler.getDebugStr()
     Msg = "send : %s*" % DebugStr
     PCA_GenLib.WriteLog(Msg,1)
     Message = self.handler.getSCTPResponse()
     if Message != None:
       Msg = "send = *\n%s\n*" % PCA_GenLib.HexDump(Message)
       PCA_GenLib.WriteLog(Msg,1)
       self.sendDataToSocket(conn,Message)

     Msg = "handle_event OK"
     PCA_GenLib.WriteLog(Msg,9)   
    except:
     Msg = "handle_event Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	  

