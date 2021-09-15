import mitmproxy
from imports import *

BLACKLISTS = ["\.gif", "\.png", "\.css",  "\.ico", "\.otf", "\.jpg"]
# BLACKLISTS = ["\.gif", "\.png", "\.css", "\.js", "\.ico", "\.otf", "\.jpg"]
PCAP_DIR = "PCAPS"
HTML_DIR = "HTML"

def real_path(path):
    #filter the useless requests
    for blacklist in BLACKLISTS:
        if re.search(blacklist, path):
            return False
    return True

def log_request(request):
    output = {}
    header = {}
    header["method"] = request.method
    header["path"] = request.path
    header["version"] = request.http_version
    for k,v in request.headers.items():
        header[k] = v
    output["Header"] = header
    if(request.method == "GET"):
        param = request.path.split("/")[-1].split("?")
        if(len(param) == 1):
            output["Param"] = ""
        else:
            get_params = {}
            params = []
            for item in param[1].split("&"):
                tmp = item.split("=")
                if(len(tmp) == 1):
                    get_params[tmp[0]] = ""
                else:
                    get_params[tmp[0]] = tmp[1]
            output["Param"] = get_params
    else:
        post_params = {}
        param = request.get_text(strict=True).split("&")
        for item in param:
            tmp = item.split("=")
            if(len(tmp) == 1):
                post_params[tmp[0]] = ""
            else:
                post_params[tmp[0]] = tmp[1]
        output["Param"] = post_params
    return json.dumps(output)

class ProxyLogger:

    def __init__(self, cf_read, cf_write):
        self.cf_read = cf_read
        self.cf_write = cf_write


    def response(self,flow):
        if real_path(flow.request.path):
            if (flow.request.method == "GET"):
                path = flow.request.path
                page_url = path.split("/")[-1].split("?")
                if(len(page_url) == 1):
                    param = None
                    page_url = page_url[0]
                else:
                    params = []
                    param = page_url[1]
                    page_url = page_url[0]
                    for item in param.split("&"):
                        params.append(item.split("=")[0])
                        params.sort()
                if param:
                    pcap_name = "GET-" + page_url + "-" + str(len(params)) + "-"
                    for item in params:
                        pcap_name += (item + "&")
                else:
                    pcap_name = "GET-" + page_url + "-0"
                    
                if pcap_name not in self.cf_read.options("GET"):
                    # Save the responding pcap
                    # Save the GET request
                    with open(PCAP_DIR + "/" + pcap_name, "w") as f:
                        f.write(log_request(flow.request))
                    with open(PCAP_DIR + "/index.config", "r+") as f:
                        self.cf_write.set("GET", pcap_name, "1")
                        self.cf_write.write(f)
                    with open(HTML_DIR + "/" + pcap_name, "w") as f:
                        f.write(str(flow.response.get_text()))
                # else:
                #     num = self.cf_read.getint("GET", pcap_name) + 1
                #     with open(PCAP_DIR + "/index.config", "w+") as f:
                #         self.cf_read.remove_option("GET", pcap_name)
                #         self.cf_read.write(f)
                #         self.cf_write.set("GET", pcap_name, str(num))
                #         self.cf_write.write(f)

            if (flow.request.method == "POST"):
                path = flow.request.path
                page_url = path.split("/")[-1]
                content = flow.request.get_text(strict=True)
                params = []
                for item in content.split("&"):
                    params.append(item.split("=")[0])
                    params.sort()
                pcap_name = "POST-" + page_url + "-" + str(len(params)) + "-"
                for item in params:
                    pcap_name += (item + "&")
                
                if pcap_name not in self.cf_read.options("POST"):
                    hash_name = "POST" + str(hash(pcap_name))
                    # Save the POST request
                    with open(PCAP_DIR + "/" + hash_name, "w") as f:
                        f.write(log_request(flow.request))
                    with open(PCAP_DIR + "/index.config", "r+") as f:
                        self.cf_write.set("POST", pcap_name, hash_name)
                        self.cf_write.write(f)




            #     if(path not in self.htmls):
            #         self.htmls.append(path)
            #         with open("urls", "a+") as f:
            #             f.write(path + " ")
            #         with open("./HTML/html-"+ str(hash(path)), "w") as f:
            #             f.write(flow.response.get_text())
            #     # with open(RESPONSE_FILE, "a+") as f:
            #     #     f.write(path + str(chat[path]) + "\n")
            #         # f.write(flow.request.method)
            #         # f.writow.response.status_code))
            # if (flow.request.method == "POST"):
            #     path = flow.request.path
            #     page_url = path.split("/")[-1]


    # def response(self,flow):
    #     if real_path(flow.request.path):
    #         if (flow.request.method == "GET"):
    #             path = flow.request.path
    #             page_url = path.split("/")[-1]
    #             print(path)
    #             print(page_url)


def start():
    cf_read = myparser()
    cf_write = myparser()
    if "index.config" not in os.listdir(PCAP_DIR):
        with open(PCAP_DIR + "/index.config", "w") as f:
            cf_write.add_section("POST")
            cf_write.add_section("GET")
            cf_write.write(f)
    cf_read.read(PCAP_DIR + "/index.config")
    return ProxyLogger(cf_read, cf_write) 
