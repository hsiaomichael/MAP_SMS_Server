
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
import PCA_M3UAMessage

def getDetailMessage(message,parameter_list,display_flags):
  try:
        Msg = "-----------------------------------------------------------------"
        PCA_GenLib.WriteLog(Msg,2)
        sccp_msg_dict = {}
        for m3ua_key in sorted(message):
           if m3ua_key == "M3UA sccp_msg_dict":
             sccp_msg_dict = message[m3ua_key][0]            
           else:
             Msg = "<%s>=<%s>,hex=<%s>*" % (m3ua_key,message[m3ua_key][0],PCA_GenLib.getHexString(message[m3ua_key][1]))
             PCA_GenLib.WriteLog(Msg,display_flags)
             parameter_list[m3ua_key] = message[m3ua_key]

        tcap_msg_dict = {}
        for sccp_key in sorted(sccp_msg_dict):
          if sccp_key == "SCCP tcap_msg_dict":
            tcap_msg_dict = sccp_msg_dict[sccp_key][0]                
          else:
            Msg = "<%s>=<%s>,hex=<%s>*" % (sccp_key,sccp_msg_dict[sccp_key][0],PCA_GenLib.getHexString(sccp_msg_dict[sccp_key][1]))
            PCA_GenLib.WriteLog(Msg,display_flags)
            parameter_list[sccp_key] = sccp_msg_dict[sccp_key]


        map_msg_dict = {}
        for tcap_key in sorted(tcap_msg_dict):
          if tcap_key == "TCAP map_msg_dict":
            map_msg_dict = tcap_msg_dict[tcap_key][0]                
          else:
            Msg = "<%s>=<%s>,hex=<%s>*" % (tcap_key,tcap_msg_dict[tcap_key][0],PCA_GenLib.getHexString(tcap_msg_dict[tcap_key][1]))
            PCA_GenLib.WriteLog(Msg,display_flags)
            parameter_list[tcap_key] = tcap_msg_dict[tcap_key]

        for map_key in sorted(map_msg_dict):
          Msg = "<%s>=<%s>,hex=<%s>*" % (map_key,map_msg_dict[map_key][0],PCA_GenLib.getHexString(map_msg_dict[map_key][1]))
          PCA_GenLib.WriteLog(Msg,display_flags)
          parameter_list[map_key] = map_msg_dict[map_key]

        Msg = "-----------------------------------------------------------------"
        PCA_GenLib.WriteLog(Msg,2)
        #return parameter_list
  except:
    Msg = "getDetailMessage error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
    PCA_GenLib.WriteLog(Msg,0)
    raise

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
     self.M3UAMessage = PCA_M3UAMessage.Writer(XMLCFG)


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
	 
     #Msg = "DEBUG con=<%s> msg = *\n%s\n*" % (id(conn),PCA_GenLib.HexDump(Message))
     #PCA_GenLib.WriteLog(Msg,0)

     self.parser.parse(Message)
     response_message = self.handler.getHandlerResponse()

     ServerID = self.handler.getTID()
     DebugStr = self.handler.getDebugStr()
     if string.find(DebugStr,"BEAT") == -1:
       Msg = "----------------------------------------------------------------------------------"
       PCA_GenLib.WriteLog(Msg,1)
       Msg = "recv : %s*" % DebugStr
       PCA_GenLib.WriteLog(Msg,1)
     
     #Message = self.handler.getSCTPResponse()

     if response_message['M3UA Message Class'][0] == "Transfer Messages":
       request_parameter_list = {}
       getDetailMessage(response_message,request_parameter_list,3)
      
       map_type = "SRI-SM-Ack"
       if string.find(DebugStr,"shortMsgMO") != -1:
         Message = None # MO-FSM ACK not response anything
         Msg = "MO-FSM ACK not response anything"
         PCA_GenLib.WriteLog(Msg,1)

       else:
         if string.find(DebugStr,"SRI") != -1:
           map_type = "SRI-SM-Ack"      
         else:
           map_type = "MT-FSM-Ack"
         
         Message = self.M3UAMessage.getPayloadData(map_type,request_parameter_list,request_parameter_list)
         self.parser.parse(Message)
         response_message = self.handler.getHandlerResponse()

         ServerID = self.handler.getTID()
         DebugStr = self.handler.getDebugStr()
         Msg = "send : %s*" % DebugStr
         PCA_GenLib.WriteLog(Msg,1)
     else:
       #ASP Up (ASPUP) or "ASP Active (ASPAC) or "Heartbeat (BEAT)" or Heartbeat Acknowledgement (BEAT ACK)"
       Message = self.handler.getSCTPResponse()
     

     if Message != None:
       Msg = "send = *\n%s\n*" % PCA_GenLib.HexDump(Message)
       PCA_GenLib.WriteLog(Msg,2)
       

       self.sendDataToSocket(conn,Message)


       if string.find(DebugStr,"ASPAC") != -1:
         Msg = "send : %s*" % DebugStr
         PCA_GenLib.WriteLog(Msg,1)
         time.sleep(3)
         Msg = "send MO-FSM "
         PCA_GenLib.WriteLog(Msg,1)
         self.sendMO(conn)
            	
       
#Message = self.M3UAMessage.getPayloadData("SRI-Ack",mo_fsm_message_request,mo_fsm_message_request)


     Msg = "handle_event OK"
     PCA_GenLib.WriteLog(Msg,9)   
    except:
     Msg = "handle_event Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	  

  ########################################################################
  # 
  #
  #########################################################################
  def sendMO(self,conn):
    try:	
     Msg = "sendMO"
     PCA_GenLib.WriteLog(Msg,9)
	
     request_parameter_list = {}
     #getDetailMessage(response_message,request_parameter_list,3)
         
     Message = self.M3UAMessage.getPayloadData("MO-FSM",request_parameter_list,request_parameter_list)
     self.parser.parse(Message)
     response_message = self.handler.getHandlerResponse()

     ServerID = self.handler.getTID()
     DebugStr = self.handler.getDebugStr()
     Msg = "send : %s*" % DebugStr
     PCA_GenLib.WriteLog(Msg,1)


     if Message != None:
       Msg = "send = *\n%s\n*" % PCA_GenLib.HexDump(Message)
       PCA_GenLib.WriteLog(Msg,2)

       self.sendDataToSocket(conn,Message)
      
     Msg = "sendMO OK"
     PCA_GenLib.WriteLog(Msg,9)   
    except:
     Msg = "sendMO Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise	  

