#!/usr/bin/python3
import os, sys, json, re



def main():
    if (len(sys.argv) == 1):
        print("[+]Usage: get_url.py PCAPS_DIR")
    else:
        path = sys.argv[1]
    PCAP_DIR = path + "/PCAPS"
    with open("url.log", "w") as fp:
        for item in os.listdir(PCAP_DIR):
            if(re.match("GET", item)):
                with open(PCAP_DIR + "/" + item, "r") as f:
                    content = json.loads(f.read())
                path = content["Header"]["path"]
                host = content["Header"]["Host"]
                url = "http://0.0.0.0:8080" + path.split("?")[0] + "\n"
                fp.write(url)
            



if __name__ == '__main__':
  main()
