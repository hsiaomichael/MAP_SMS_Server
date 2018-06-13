MAP Server Simulator
========================
Native SS7 stack
Sigtran Support :  encode/decode (M3UA|SCCP|TCAP|MAP|GSM 0340) protocol

Send MO-FSM , send SRI-ack and MT-ack to SMSC
Receive MO-FSM-ack , SRI-SM , MT-FSM 



Pre-Request
========================
pre-request : Python SCTP -> https://github.com/philpraxis/pysctp
              Python SMSPDU -> https://pypi.python.org/pypi/smspdu

Test Procedure 
=================

   * Get SMSC IP,Port,Point Code
   * chmod +x run.sh
   * vi MAPServer.cfg update sctp server ip port , M3UA Point Code and MAP SC_Address
   * ./run.sh
  
   * use cmd.sh send MO-FSM or MO-long message to SMSC
   * once Simulator receiver SRI-SM , will send SRI-SM-act back to SMSC (with NNN and IMSI)
   * once Simulator receiver MT-FSM , will send MT-FSM-act back to SMSC 
 


