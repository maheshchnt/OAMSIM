import os
import sys

class oamsim_cmd_tx ():
   def __init__(self, msg_fifo_name, rsp_fifo_name):
      self.msg_fifo = msg_fifo_name
      self.rsp_fifo = rsp_fifo_name
      ''' 
          Create 2 fifos; one for transmitting the cmd
          and the other one is to receive the response
      '''
      try:
         os.mkfifo(self.msg_fifo)
      except OSError as e:
         if e.errno != os.errno.EEXIST:
            raise
         
      try:
         os.mkfifo(self.rsp_fifo)
      except OSError as e:
         if e.errno != os.errno.EEXIST:
            raise

   def send_cmd(self, cmd):
      msg = str.encode(cmd)
      wr_fd = os.open(self.msg_fifo, os.O_WRONLY)
      os.write(wr_fd, msg)
      os.close(wr_fd)
      rd_fd = os.open(self.rsp_fifo, os.O_RDONLY)
      rsp = os.read(rd_fd, 2)
      os.close(rd_fd)
      if cmd == "exit":
         quit()


# Create OAMSIM CMD TX thread
tx = oamsim_cmd_tx("oamsim_msg", "oamsim_resp")

