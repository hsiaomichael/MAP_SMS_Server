
########################################################################################
#
# Filename:    PCA_M3UAServerSocket.py
#
# Description
# ===========
# SCTP Server Socket
#
#
# Author    : Michael Hsiao#
# Date      : 2016/09/04
#
# Description
# ===========
# SCTP Server Template
#
# Modify    : Michael Hsiao#
# Date      : 2018/06/14
# Desc      : add FSG support

import sys, time,string,os
import sctp,socket,select,smspdu
import PCA_GenLib
import PCA_XMLParser
import PCA_SCTPServerSocket
import PCA_M3UAResponseParser
import PCA_M3UAMessage

g_originator = None
g_recipient = None
g_imsi = None
g_text = None
g_total_segment = 0
g_current_segment = 0
g_sca = None
#######################################################################
#
#######################################################################

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

#######################################################################
#
#######################################################################
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
            ## accept should not block    ##
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
                self.handle_event(self.SocketConnection,ClientMessage)

            except socket.error:
              Msg = "Dispatcher error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
              PCA_GenLib.WriteLog(Msg,0)
              self.SocketConnection.close()                   # close here and remv from
              self.ReadSet.remove(self.SocketConnection)      # del list else reselected
              del self.ConnectionLoginState[id(self.SocketConnection)]

        Msg = "check external command"
        PCA_GenLib.WriteLog(Msg,9)
        try:
            self.handle_cmd(self.SocketConnection,"/tmp/pca.cmd")
        except AttributeError:
            Msg = "association not established yet"
            PCA_GenLib.WriteLog(Msg,1)

      Msg = "dispatcher OK"
      PCA_GenLib.WriteLog(Msg,9)
    except:
      Msg = "dispatcher error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)
      self.close()
      raise


  def handle_cmd(self,conn,file):
    global g_originator
    global g_recipient
    global g_imsi
    global g_text
    global g_total_segment
    global g_current_segment
    global g_sca
    try:
      data =  open(file).read()[0:-1]
      Msg = "data = <%s>" % data
      PCA_GenLib.WriteLog(Msg,1)
      os.unlink(file)
      if string.find(data,"MO") != -1:
        (cmd,originator,recipient,imsi,text) = string.split(data,",")
        Msg = "send mo originator=<%s>, recipient=<%s>, imsi=<%s>,text=<%s>" % (originator,recipient,imsi,text)
        PCA_GenLib.WriteLog(Msg,0)
        self.MO(conn,originator,recipient,imsi,text)
      elif string.find(data,"segment") != -1:
        g_total_segment = 2
        g_current_segment = 0
        (cmd,originator,recipient,imsi,text) = string.split(data,",")
        Msg = "send mo segment originator=<%s>, recipient=<%s>, imsi=<%s>,text=<%s>" % (originator,recipient,imsi,text)
        PCA_GenLib.WriteLog(Msg,0)
        (g_originator,g_recipient,g_imsi,g_text) = (originator,recipient,imsi,text)
        self.sendMO_tcap_begin(conn)
      elif string.find(data,"Alert") != -1:
        (cmd,msisdn) = string.split(data,",")
        Msg = "send sc-alert msisdn=<%s>" % (msisdn)
        PCA_GenLib.WriteLog(Msg,0)
        self.alertServiceCentre(conn,msisdn)
      elif string.find(data,"HR") != -1:
        (cmd,msisdn,fsg_sca,originator,text) = string.split(data,",")
        Msg = "HR request msisdn=<%s>,fsg_sca=<%s>,originator=<%s>,text=<%s>" % (msisdn,fsg_sca,originator,text)
        PCA_GenLib.WriteLog(Msg,0)
        g_text = text
        g_originator = originator
        g_sca = fsg_sca
        self.SendRoutingInfo(conn,msisdn,fsg_sca)
      else:
        Msg = "unknow command data = <%s>" % data
        PCA_GenLib.WriteLog(Msg,0)

    except IOError:
      x=1
    except:
      Msg = "handle_cmd error : <%s>,<%s> " % (sys.exc_type,sys.exc_value)
      PCA_GenLib.WriteLog(Msg,0)

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
     
     self.parser.parse(Message,"IN")
     response_message = self.handler.getHandlerResponse()         
     ServerID = self.handler.getTID()
     DebugStr = self.handler.getDebugStr()

     ################################################
     # will not display M3UA heartbeat message
     ################################################
     if string.find(DebugStr,"BEAT") == -1:
       Msg = "----------------------------------------------------------------------------------"
       PCA_GenLib.WriteLog(Msg,1)
       Msg = "recv : %s*" % DebugStr
       PCA_GenLib.WriteLog(Msg,1)

     
     #ASP Up (ASPUP) or "ASP Active (ASPAC) or "Heartbeat (BEAT)" or Heartbeat Acknowledgement (BEAT ACK)"

     #if response_message != None and string.find(DebugStr,"tcap_end") == -1 and string.find(DebugStr,"tcap_continue") == -1:
     if string.find(DebugStr,"tcap_continue") != -1 and string.find(DebugStr,"shortMsgMO_Relay_v3") != -1:
       Msg = "tcap tcap_continue , ready send MO-segment message"
       PCA_GenLib.WriteLog(Msg,1)
       request_parameter_list = {}
       (orig_tid,dest_tid) = self.handler.getTCAP_ID()
       request_parameter_list["TCAP Originating TID"] = (orig_tid,orig_tid)
       request_parameter_list["TCAP Destination TID"] = (dest_tid,dest_tid)
       self.sendMO_segment(conn,request_parameter_list)
     elif response_message != None and string.find(DebugStr,"tcap_end") == -1 :
       Msg = "send = *\n%s\n*" % PCA_GenLib.HexDump(response_message)
       PCA_GenLib.WriteLog(Msg,2)

       self.parser.parse(response_message,"IN")
       #response_message_ = self.handler.getHandlerResponse()
       ServerID = self.handler.getTID()
       DebugStr = self.handler.getDebugStr()
       if string.find(DebugStr,"BEAT") == -1:
         Msg = "send : %s*" % DebugStr
         PCA_GenLib.WriteLog(Msg,1)
       self.sendDataToSocket(conn,response_message)
     elif g_current_segment < g_total_segment :
       Msg = "segment info current=<%s>,total=<%s> we may need to send segment msg" % (g_current_segment, g_total_segment)
       PCA_GenLib.WriteLog(Msg,1)
       request_parameter_list = {}
       (orig_tid,dest_tid) = self.handler.getTCAP_ID()
       request_parameter_list["TCAP Originating TID"] = (orig_tid,orig_tid)
       request_parameter_list["TCAP Destination TID"] = (dest_tid,dest_tid)
       self.sendMO_segment(conn,request_parameter_list)

       ################################################
       # Send MO-FSM once link active
       ################################################
       #if string.find(DebugStr,"ASPAC") != -1:
         #Msg = "send : %s*" % DebugStr
         #PCA_GenLib.WriteLog(Msg,1)
        
         #Msg = "send SSNM DUNA"
         #PCA_GenLib.WriteLog(Msg,1)
         #self.sendSSNM(conn,"DUNA")         
            
         #Msg = "send SSNM "
         #PCA_GenLib.WriteLog(Msg,2)
         #self.sendSSNM(conn,"DAVA")

         #Msg = "send alertSC "
         #PCA_GenLib.WriteLog(Msg,1)
         #self.send_alertServiceCentre(conn)

     else:
         if string.find(DebugStr,"sendRoutingInfoForSM") != -1:
            Msg = "sri-sm response , ready send MT-FSM"
            PCA_GenLib.WriteLog(Msg,1)      
            
            (imsi,NNN) = self.handler.getSRI_SM_resp()
            Msg = "sri-sm response ,imsi=<%s>,NNN=<%s>, ready send MT-FSM" % (imsi,NNN)
            PCA_GenLib.WriteLog(Msg,1)    
            self.MT(conn,NNN,imsi)
            
         else:
            Msg = "tcap end or no response message , not response back ...."
            PCA_GenLib.WriteLog(Msg,1)

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
  def MO(self,conn,originator_address,recipient_address,imsi,sms_text_data):
    try:
     Msg = "MO"
     PCA_GenLib.WriteLog(Msg,9)

     request_parameter_list = {}
     request_parameter_list['originator'] = (originator_address,originator_address)
     request_parameter_list['recipient'] = (recipient_address,recipient_address)
     request_parameter_list['imsi'] = (imsi,imsi)
     (sms_text_length,sms_text) = smspdu.pdu.pack7bit(sms_text_data)

     Msg = "---------------------------------------"
     PCA_GenLib.WriteLog(Msg,2)

     Msg = "len=<%s> ascii   = *\n%s\n*" % (len(sms_text_data),PCA_GenLib.HexDump(sms_text_data))
     PCA_GenLib.WriteLog(Msg,2)

     Msg = "len=<%s> gsm7bit = *\n%s\n*" % (sms_text_length,PCA_GenLib.HexDump(sms_text))
     PCA_GenLib.WriteLog(Msg,2)

     Msg = "---------------------------------------"
     PCA_GenLib.WriteLog(Msg,2)

     request_parameter_list['sms_text'] = (sms_text,sms_text)
     request_parameter_list['sms_text_length'] = (sms_text_length,sms_text_length)
     Message = self.M3UAMessage.getPayloadData("MO-FSM",request_parameter_list,request_parameter_list)
     self.sendDataToSocket(conn,Message)
     Msg = "MO OK"
     PCA_GenLib.WriteLog(Msg,9)
    except:
     Msg = "MO Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
  
  ########################################################################
  #
  #
  #########################################################################
  def sendMO_tcap_begin(self,conn):
    try:
     Msg = "sendMO_tcap_begin"
     PCA_GenLib.WriteLog(Msg,9)

     request_parameter_list = {}

     Message = self.M3UAMessage.getPayloadData("MO-FSM-Begin",request_parameter_list,request_parameter_list)

     self.sendDataToSocket(conn,Message)

     Msg = "sendMO_tcap_begin OK"
     PCA_GenLib.WriteLog(Msg,9)
    except:
     Msg = "sendMO_tcap_begin Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise

  ########################################################################
  #
  #
  #########################################################################
  def sendMO_segment(self,conn,request_parameter_list):
    global g_originator
    global g_recipient
    global g_imsi
    global g_text
    global g_total_segment 
    global g_current_segment 
    try:
     (originator_address,recipient_address,imsi,sms_text) =   (g_originator,g_recipient,g_imsi,g_text)

     Msg = "sendMO_segment data = %s %s %s %s" % (originator_address,recipient_address,imsi,sms_text)
     PCA_GenLib.WriteLog(Msg,1)

     g_current_segment = g_current_segment + 1
     
     request_parameter_list['originator'] = (originator_address,originator_address)
     request_parameter_list['recipient'] = (recipient_address,recipient_address)
     request_parameter_list['imsi'] = (imsi,imsi)
     try:
       text  = sms_text[0:153]
       g_text  = sms_text[153:]
     except:
       text  = sms_text

     if len(text) == 0:
      text = "ab"
    
     (sms_text7bit_length,sms_text7bit) = (len(text),text)
     request_parameter_list['sms_text'] = (sms_text7bit,sms_text7bit)
     request_parameter_list['sms_text_length'] = (sms_text7bit_length,sms_text7bit_length)

     request_parameter_list['total_segment'] = (g_total_segment,g_total_segment)
     request_parameter_list['current_segment'] = (g_current_segment,g_current_segment)

     Message = self.M3UAMessage.getPayloadData("MO-FSM-segment",request_parameter_list,request_parameter_list)

     Msg = "--- parsing segment outgoing message ----------------------------------------------"
     PCA_GenLib.WriteLog(Msg,1)
     self.parser.parse(Message,"IN")
     response_message = self.handler.getHandlerResponse()

     ServerID = self.handler.getTID()
     DebugStr = self.handler.getDebugStr()

     Msg = "send : %s*" % DebugStr
     PCA_GenLib.WriteLog(Msg,1)

     Msg = "----------------------------------------------------------------------------------"
     PCA_GenLib.WriteLog(Msg,3)

     self.sendDataToSocket(conn,Message)

     Msg = "sendMO_segment OK"
     PCA_GenLib.WriteLog(Msg,9)
    except:
     Msg = "sendMO_segment Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
  ########################################################################
  #
  #
  #########################################################################
  def alertServiceCentre(self,conn,msisdn):
    try:
        Msg = "alertServiceCentre"
        PCA_GenLib.WriteLog(Msg,9)

        request_parameter_list = {}
      
        request_parameter_list['alert_MSISDN'] = (msisdn,msisdn)
        Message = self.M3UAMessage.getPayloadData("alertSC",request_parameter_list,request_parameter_list)
        self.sendDataToSocket(conn,Message)

        Msg = "alertServiceCentre OK"
        PCA_GenLib.WriteLog(Msg,9)
    except:
        Msg = "alertServiceCentre Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
        PCA_GenLib.WriteLog(Msg,0)
        raise
  ########################################################################
  #
  #
  #########################################################################
  def SendRoutingInfo(self,conn,msisdn,fsg_sca):
    try:
        Msg = "SendRoutingInfo"
        PCA_GenLib.WriteLog(Msg,9)

        request_parameter_list = {}
      
        request_parameter_list['recipient'] = (msisdn,msisdn)
        request_parameter_list['fsg_sca'] = (fsg_sca,fsg_sca)
        
        
        Message = self.M3UAMessage.getPayloadData("SRI-SM",request_parameter_list,request_parameter_list)
        self.sendDataToSocket(conn,Message)

        Msg = "SendRoutingInfo OK"
        PCA_GenLib.WriteLog(Msg,9)
    except:
        Msg = "SendRoutingInfo Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
        PCA_GenLib.WriteLog(Msg,0)
        raise
        
  ########################################################################
  #
  #
  #########################################################################
  def MT(self,conn,NNN,imsi):
    global g_originator
    global g_text
    global g_sca
    try:
     Msg = "MT"
     PCA_GenLib.WriteLog(Msg,9)
     (originator_address,sca,sms_text_data) =   (g_originator,g_sca,g_text)
     imsi = "%sf" % imsi
     request_parameter_list = {}
     request_parameter_list['originator'] = (originator_address,originator_address)    
     request_parameter_list['imsi'] = (imsi,imsi)
     request_parameter_list['NNN'] = (NNN,NNN)
     request_parameter_list['sca'] = (sca,sca)
   
     (sms_text_length,sms_text) = smspdu.pdu.pack7bit(sms_text_data)

     request_parameter_list['sms_text'] = (sms_text,sms_text)
     request_parameter_list['sms_text_length'] = (sms_text_length,sms_text_length)

     Message = self.M3UAMessage.getPayloadData("MT-FSM",request_parameter_list,request_parameter_list)
     self.sendDataToSocket(conn,Message)
    
     Msg = "MT OK"
     PCA_GenLib.WriteLog(Msg,9)
    except:
     Msg = "MT Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise
  ########################################################################
  #
  #
  #########################################################################
  def sendSSNM(self,conn,SSNM_TYPE):
    try:
     Msg = "sendSSNM"
     PCA_GenLib.WriteLog(Msg,9)


     Message = self.M3UAMessage.getSSNM(SSNM_TYPE)


     if Message != None:
       Msg = "send = *\n%s\n*" % PCA_GenLib.HexDump(Message)
       PCA_GenLib.WriteLog(Msg,2)

       self.sendDataToSocket(conn,Message)

     Msg = "sendSSNM OK"
     PCA_GenLib.WriteLog(Msg,9)
    except:
     Msg = "sendSSNM Error :<%s>,<%s>" % (sys.exc_type,sys.exc_value)
     PCA_GenLib.WriteLog(Msg,0)
     raise

