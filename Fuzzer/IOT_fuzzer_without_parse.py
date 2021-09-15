from imports import *
from boofuzz_modify import *
from IOT_logging import *
import subprocess


class vmcontrol:
    def __init__(self):
        self.restart = 0
    def restart_target(self):
        if self.restart > 3:
            logger.debug("Restarting emulation")
            self.restart = 0
            logger.info("Restarting the firmware")
            os.system("./restart.sh")
            time.sleep(30)
            os.system("./snapshot.sh")
        else:
            logger.debug("Rolling back")
            self.restart += 1
            rc = subprocess.call("./rollback.sh", shell= True)
            time.sleep(5) 

def check_stable(session, conn):
    conn.close()
    session._open_connection_keep_trying(conn)
    conn.send(session.nodes[1].render())
    response = conn.recv(10000)
    if len(response) == 0:
        logger.error("Server connection error\n Restarting!")
        return False
    else:
        while True:
            banner = conn.recv(100000)
            if len(banner) == 0:
                break
        return True




def check_log(target, fuzz_data_logger, session, *args, **kwargs):
    time.sleep(target.interval)
    node = session.fuzz_node
    payload = node._name + "-" + str(node._element_mutant_index)
    match_1 = r"\$[\s]*\d+[\s]*: [\d\w]+[\s][\d\w]+[\s][\d\w]+[\s][\d\w]+"
    match_2 = r"ci_file"
    match_3 = r"XSS"
    response = ""
    while(1):
        banner = target.recv(10000)
        response += str(banner)
        if(len(banner)==0):
            break
    if re.search(match_3, response):
        logger.debug("Found XSS vulnerbility")
        logger.debug("The transmitied pcap is \n%s" %str(node.render()))
        if payload not in target.XSS_payloads:
            target.XSS_payloads.append(payload)
            logger.critical("Found XSS vulnerbility")
            logger.critical("The transmitied pcap is \n%s" %str(node.render()))
    log_read = target.firmware_log.read()
    if re.search(match_1, log_read):
        logger.debug("Found BO vulnerbility")
        logger.debug("The transmitied pcap is \n%s" %str(node.render()))
        if "A"*10 in str(node.render()) or len(node.mutant.render()) == 0:
            if payload not in target.BO_payloads:
                target.BO_payloads.append(payload)
                if not check_stable(session, target):
                    logger.critical("Found BO vulnerbility")
                    logger.critical("The transmitied pcap is \n%s" %str(node.render()))
    if re.search(match_2, log_read):
        logger.debug("Found CI vulnerbility")
        logger.debug("The transmitied pcap is \n%s" %str(node.render()))
        if payload not in target.CI_payloads:
            target.CI_payloads.append(payload)
            logger.critical("Found CI vulnerbility")
            logger.critical("The transmitied pcap is \n%s" %str(node.render()))

    



def check_connection(target, fuzz_data_logger, session, *args, **kwargs): 
    target.send(session.nodes[1].render())
    banner = target.recv(10000)
    # if len(banner) == 0:
    #     logger.debug("Sleep for connection")
    #     target.close()
    #     time.sleep(2)
    #     session._open_connection_keep_trying(target)
    #     banner = target.recv(10000)
    #     target.send(session.nodes[1].render())
    #     if len(banner) == 0:
    #         logger.debug("sleep for longer connection")
    #         os.system("./rollback.sh")
    #         time.sleep(4)
    #         # restart_firm()
    # elif re.match(b"HTTP/1.1 5", banner):
    #     logger.debug("Bad response")
    #     os.system("./rollback.sh")
    #     time.sleep(4)
    
    if len(banner) == 0 or re.match(b"HTTP/1.1 5", banner):
        logger.debug("Connection restart")
        os.system("./rollback.sh")
        time.sleep(4)

        
    target.close()
    session._open_connection_keep_trying(target)
    # target.open()


class Main_fuzzer:
    def __init__(self, firm_dir, pcap_dir):
        self.restart = 0
        self.restart_flag = 0
        self.log_fp = open("output.log", "w")
        with open("debug.log", "w") as f:
            pass
        self.firm_dir = firm_dir
        self.firm_log = open(os.path.join(firm_dir, "qemu.final.serial.log"), "r")
        self.pcap_dir = pcap_dir
        self.cf_read = myparser()
        self.content = os.listdir(os.path.join(pcap_dir, "PCAPS"))
        self.content.remove("index.config")
        with open(os.path.join(pcap_dir, "PCAPS", self.content[0]), "r") as f:
            self.host = json.loads(f.read())["Header"]["Host"]
        self.cf_read.read(os.path.join(self.pcap_dir, "PCAPS", "index.config"))
        sections = self.cf_read.sections()
        logger.info("There is %d GET pcaps" %len(self.cf_read.options("GET")))
        logger.info("There is %d POST pcaps" %len(self.cf_read.options("POST")))

        self.conn = New_target(
            connection = TCPSocketConnection(self.host, 80, send_timeout=0.5, recv_timeout=0.02),
            firmware_log = self.firm_log,
            )
        self.conn.vmcontrol = vmcontrol()
        self.session = Session(
            target = self.conn, 
            receive_data_after_each_request = False, 
            keep_web_open = False,
            # pre_send_callbacks = [check_connection],
            post_test_case_callbacks = [check_log],
            # crash_threshold_element = 1000,
            # crash_threshold_request = 1000,
            fuzz_loggers = [FuzzLoggerText(file_handle=self.log_fp)],
        )
        self.firm_log.read()
        s_initialize("HTTP")
        self.session.connect(s_get("HTTP"))
        logger.info("Mainfuzzer plugin initialized")
    
    def __del__(self):
        self.firm_log.close()
        self.log_fp.close()
    
    def cleanup_node(self, node):
        for item in node.stack:
            del item
        self.conn.XSS_payloads.clear()
        self.conn.BO_payloads.clear()
        self.conn.CI_payloads.clear()
        node.stack.clear()
        node.names.clear()
        node.reset()

        

    def fuzz_https(self):
        logger.info("Loading http files")

        for item in self.content:
            if re.match("GET", item):
                logger.info("Fuzzing node: %s" %item)
                if re.search("-0$", item) or "-1-_&" in item:
                    pass
                else:
                    with open(os.path.join(self.pcap_dir, "PCAPS", item), "r") as f:
                        content = json.loads(f.read())
                    s_switch("HTTP")
                    s_static(content["Header"]["method"] + " " + content["Header"]["path"].split("?")[0] + "?")
                    num = 0
                    for key, value in content["Param"].items():
                        if num != 0:
                            s_static("&")
                        s_static(key)
                        s_static("=")
                        s_attack(value)
                        num += 1
                    s_static(" " + content["Header"]["version"] + "\r\n")
                    s_static("Host: %s\r\n" %content["Header"]["Host"])
                    for key, value in content["Header"].items():
                        if key not in ["method", "path", "version", "Host"]:
                            s_static(key)
                            s_static(":")
                            s_static(" ")
                            s_static(value)
                            s_static("\r\n")
                    s_static("\r\n")
                    
            elif re.match("POST", item): 
                logger.info("Fuzzing node: %s" %item)
                with open(os.path.join(self.pcap_dir, "PCAPS", item), "r") as f:
                    content = json.loads(f.read())
                s_switch("HTTP")
                s_static(content["Header"]["method"] + " " + content["Header"]["path"] + " " + content["Header"]["version"] + "\r\n")
                s_static("Host: %s\r\n" %content["Header"]["Host"])
                for key, value in content["Header"].items():
                    if key not in ["method", "path", "version", "Host"]:
                        s_static(key)
                        s_static(":")
                        s_static(" ")
                        s_static(value)
                        s_static("\r\n")
                s_static("\r\n")
                num = 0
                for key, value in content["Param"].items():
                    if num != 0:
                        s_static("&")
                    s_static(key)
                    s_static("=")
                    if re.search("sessionKey", key):
                        s_static(value, name="depend")
                    else:
                        s_attack(value)
                    num += 1
                # if self.has_depend:
                #     s_static("&sessionKey=")
                #     s_static("depend", name="depend")
            self.session.fuzz()
            logger.info("Fuzzed %d of %d test cases" %(self.session.total_mutant_index, self.session.total_num_mutations))
            if self.session.total_mutant_index > 0:
                logger.info("Restarting the target!")
                # os.system("./rollback.sh")
                # time.sleep(10)
                # os.system("./restart.sh")
                # time.sleep(35)
                # os.system("./snapshot.sh")
            logger.info("Cleaning up node: %s" %item)
            self.cleanup_node(s_get("HTTP"))
            if self.restart:
                logger.info("Restarting the firmware")
                os.system("./restart.sh")
                time.sleep(30)
                os.system("./snapshot.sh")

    
    


    def fuzz(self):
        self.fuzz_https()


        
    