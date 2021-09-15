#!/usr/bin/python3
import subprocess, binascii, pickle
from imports import *

NOT_INTRERESTED = ['.gif', '.png', '.css', '.js']
BLACKLISTS = ["\.gif", "\.png", "\.css", "\.js", "\.ico", "\.otf", "\.jpg"]
# tshark  -r 4.pcapng -T fields -e tcp.stream

def get_stream_num(file_name):
    output = subprocess.getoutput("tshark  -r %s -T fields -e tcp.stream" % file_name)
    max_num = 0
    nums = output.split('\n')
    for num in nums:
        if len(num) > 0:
            if max_num < int(num):
                max_num = int(num)
    print("[+]Stream_numL:\t%s"% max_num)
    return max_num

def get_tcp_stream(file_name, num):
    print("---------------------%d---------------------"%num)
    # print('\n')
    cmd = "tshark -r %s -2 -R \"tcp.stream eq %d\"  -T fields -e \"http.request\" -e \"tcp.payload\"  -e \"http.file_data\" -e \"http\""%(file_name, num)
    output = subprocess.getoutput(cmd).split("\n")
    while('\t\t\t' in output):
        output.remove('\t\t\t')
    result = []
    # print(output)
    for i in range(len(output)):
        try:
            text = output[i].replace(":", "")
            if text[0:2] == '1\t':
                print(text)
                if(text[0:10] == '1\t504f5354'):
                    my_request = text.lstrip('1\t').split('\t')[0]
                else:
                    if text[-4:] != "http":
                        continue
                    my_request = text.lstrip('1\t').rstrip('\thttp')
                my_request = binascii.unhexlify(my_request).decode()
                # print(my_request)
                # go_down = 1
                # for tag in NOT_INTRERESTED:
                #     if (tag in my_request):
                # # if('.js' in my_request or '.css' in my_request or '.png' in my_request):
                #         go_down = 0
                # if(go_down == 0):
                #     continue
                # j = i+1
                # while(output[j][-5:] != '\thttp'):
                #     j = j+1
                # mid = output[j]
                # print(mid)
                # if(mid[1] == '\t'):
                #     my_response = mid.rstrip('\thttp').lstrip('\t')
                # else:
                #     my_response = binascii.unhexlify(mid.lstrip('\t').split('\t')[0]).decode()
                # print("my_response:\n", my_response)
                result.append(my_request)
            # result.append(my_response)
        except:
            pass
    return result

def real_path(path):
    #filter the useless requests
    for blacklist in BLACKLISTS:
        if re.search(blacklist, path):
            return False
    return True

def analyze(requests):
    ids = []
    PCAP_DIR = "./PCAPS"
    cf_write = myparser()
    cf_write.add_section("GET")
    cf_write.add_section("POST")
    for item in requests:
        if "POST" in item:
            print(item)
        if len(item.split("\r\n\r\n")) != 2:
            continue
        header, body = item.split("\r\n\r\n")
        headers = header.split("\r\n")
        method, path, version = headers[0].split()
        if not real_path(path):
            continue
        output = {}
        header = {}
        header["method"] = method
        header["path"] = path
        header["version"] = version
        for line in headers[1:]:
            k, v = line.split(": ")
            header[k] = v
        output["Header"] = header
        if(method == "GET"):
            param = path.split("/")[-1].split("?")
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
            param = body.split("&")
            for item in param:
                tmp = item.split("=")
                if(len(tmp) == 1):
                    post_params[tmp[0]] = ""
                else:
                    post_params[tmp[0]] = tmp[1]
            output["Param"] = post_params

        dump_file = json.dumps(output)
        if method == "GET":
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
            if pcap_name not in ids:
                # Save the responding pcap
                # Save the GET request
                ids.append(pcap_name)
                with open(PCAP_DIR + "/" + pcap_name, "w") as f:
                    f.write(dump_file)
                cf_write.set("GET", pcap_name, "1")
        else:
            page_url = path.split("/")[-1]
            params = []
            for item in body.split("&"):
                params.append(item.split("=")[0])
                params.sort()
            pcap_name = "POST-" + page_url + "-" + str(len(params)) + "-"
            for item in params:
                pcap_name += (item + "&")
            
            if pcap_name not in ids:
                ids.append(pcap_name)
                hash_name = "POST" + str(hash(pcap_name))
                # Save the POST request
                with open(PCAP_DIR + "/" + hash_name, "w") as f:
                    f.write(dump_file)
                cf_write.set("POST", pcap_name, hash_name)
        # os._exit(0)
    with open("index.config", "w+") as f:
        cf_write.write(f)
        print("!!!!!!!!!!!!!!")
        

if __name__ == '__main__':
    if(len(sys.argv)!=2):
        # print("Error\n Usage: python handle_stream.py FILENAME")
        # os._exit(0)
        with open("request.pk", "rb") as f:
            requests = pickle.load(f)
        analyze(requests)
    else:
        pcap_name = sys.argv[1]
        stream_num = get_stream_num(pcap_name)
        http_chat=[]
        for i in range(stream_num+1):
            http_chat.extend(get_tcp_stream(pcap_name, i))
            # for chat in get_tcp_stream(pcap_name, i):
            #     http_chat.append(chat)
        chat_num = len(http_chat)
        print ("[+]There are %d http chats"%chat_num)
        with open("request.pk", "wb") as f:
            pickle.dump(http_chat, f)
        # for i in range(int(chat_num/2)):
        #     print (http_chat[2*i + 1])