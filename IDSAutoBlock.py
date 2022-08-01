from subprocess import Popen, PIPE
import subprocess
import sys
from time import sleep
import logging
from os.path import exists
import re
from unittest import runner

#################################s
#                               #
# @author: Pradeep CH           #
#                               #
#################################

#Constant variables
NEW_LINE = '\n'
IDS_LOG_FILE = "idsLogFile"
LOG_FILE = "IDSAutoBlocker.log"

class IDSLogMonitor(object):
    def __init__(self, logFilePath):
        self.logFile = open(logFilePath,'r');

    # This code is derived from Stack overflow answer at
    # https://stackoverflow.com/a/5420116/1926283
    def getIPS(self):
        self.logFile .seek(0,2)
        while True:
            line = self.logFile .readline()
            if not line:
                sleep(0.1)
                continue
            #Extarct only the source IP
            match= re.search(r"([.0-9]+):[0-9]+ -> [.0-9]+:[0-9]", line)
            ip = ""
            if match:
                ip = match.group(1)
            yield ip

class IPBlocker(object):
    def __init__(self):
        pass

    def blockIP(self, ip):
        try:
            cmd = ["csf", "-d", ip]
            logging.debug(f"Executing command : {cmd}" )   
            op = subprocess.run(cmd,stdout=subprocess.PIPE)
            response = op.stdout.decode('utf-8')
            logging.info(f"Blocked ip :{ip} with command response {response}")
            return True
        except:
            logging.error(f"Could not block ip: {ip}")
        return False

class Runner(object):
    def __init__(self,idsMonitor, ipBlocker) :
        self.idsMonitor = idsMonitor
        self.ipBlocker =  ipBlocker
        self.blockedIps = []
        self.blockIPListFileName='IDSBlockedIPs'
        self._init()

    def start(self):
        logging.info("Scheduler started....")
        try: 
            ipsToBlock = self.idsMonitor.getIPS();
            for ip in ipsToBlock:
                if not ip : 
                    continue;
                blocked = self.ipBlocker.blockIP(ip)
                if not blocked:
                    continue
                self._addToBlockList(ip) 
        except Exception as ex:
            logging.error(f"The scheduler stopped with cause {ex}")
            logging.exception(ex)

    def _ignoreBlockedIPs(self,ips):
        return [ip for ip in ips if ip not in self.blockedIps] 

    def _addToBlockList(self, ip):
        self.blockedIps.append(ip)
        with open(self.blockIPListFileName, 'a' ) as fp:
            fp.writelines(f"{ip}{NEW_LINE}")

    def _init(self):
        logging.debug("Looking for previously blocked entries...")
        if not exists(self.blockIPListFileName):
            logging.debug("Creating the blocked list file...")
            with open(self.blockIPListFileName,'w') as fp:
                pass
        with open(self.blockIPListFileName, 'r') as fp:
            lines = [line.rstrip() for line in fp]
            for line in lines:
                self.blockedIps.append(line)
        logging.info(f"Number of IPs identfiied as blocked : {len(self.blockedIps)}")


#This class contains basic utility functions
class CommonUtils(object):
    @staticmethod
    def initLogging():
        loggingLevel = logging.INFO; 
        logging.basicConfig(filename=LOG_FILE, level=loggingLevel,format='%(asctime)s %(levelname)s %(message)s');

    @staticmethod
    def processArgs(argv):
        if not argv or len(argv)<2:
            raise Exception("Firewall log file should be specified") 
        args = {}
        args[IDS_LOG_FILE] = argv[1]
        return args
    
if __name__=='__main__':
    CommonUtils.initLogging()
    args = CommonUtils.processArgs(sys.argv)
    idsLogMonitor = IDSLogMonitor(args[IDS_LOG_FILE])
    ipBlocker = IPBlocker()
    runner =  Runner(idsLogMonitor, ipBlocker )
    runner.start()