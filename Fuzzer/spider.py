#!/usr/bin/python3
import argparse, os, time
from selenium import webdriver
LOGIN_NAME = 'admin'
LOGIN_PASSWORD = '#'


def perform_auth(webPage):
    time.sleep(1)
    print(webPage.page_source)
    frame_list = webPage.find_elements_by_xpath("//frame")
    if (len(frame_list) != 0):
        init_url = webPage.current_url
        name_list = []
        for frame in frame_list:
            name_list.append(frame.get_attribute("name"))
        for name in name_list:
            webPage.get(init_url)
            try:
                webPage.switch_to.frame(name)
                text_elements = webPage.find_elements_by_xpath("//input[@type='text']")
                password = webPage.find_element_by_xpath("//input[@type='password']")
                try:
                    submit = webPage.find_element_by_xpath("//input[@type='submit']")
                except:
                    try:
                        submit = webPage.find_element_by_xpath("//input[@type='button']")
                    except:
                        submit = webPage.find_element_by_xpath("//button[@type='button']")
                if(len(text_elements) != 0):
                    for element in text_elements:
                        if (element.is_displayed()):
                            login = element
                    login.clear()
                    if(LOGIN_NAME != '#'):
                        login.send_keys(LOGIN_NAME)
                password.clear()
                if(LOGIN_PASSWORD != '#'):
                    password.send_keys(LOGIN_PASSWORD)
                submit.click()
                time.sleep(1)
                return True
            except:
                print("Doesn't exit in %s" %name)
        webPage.get(init_url)
        return False
    else:
        try:
            print(webPage.page_source)
            text_elements = webPage.find_elements_by_xpath("//input[@type='text']")
            password = webPage.find_element_by_xpath("//input[@type='password']")
            try:
                submit = webPage.find_element_by_xpath("//input[@type='submit']")
            except:
                try:
                    submit = webPage.find_element_by_xpath("//input[@type='button']")
                except:
                    submit = webPage.find_element_by_xpath("//button[@type='button']")
            if(len(text_elements) != 0):
                for element in text_elements:
                    if (element.is_displayed()):
                        login = element
                login.clear()
                password.clear()
                if(LOGIN_NAME != '#'):
                    login.send_keys(LOGIN_NAME)
            if(LOGIN_PASSWORD != '#'):
                password.send_keys(LOGIN_PASSWORD)
            submit.click()
            time.sleep(1)
            return True

        except:
            auth_url = ('http://%s:%s@0.0.0.0:8080') % (LOGIN_PASSWORD, LOGIN_PASSWORD)
            try:
                webPage.get(auth_url)
                return True
            except:
                return False



def main():
    parser = argparse.ArgumentParser(description = 'Spider v1.0')
    parser.add_argument('-u', '--url' , \
      help = 'The tareted url of IOT device', \
      default = 'http://192.168.0.50')
    args = parser.parse_args()
    url  = args.url

    webPage = webdriver.Chrome(executable_path="./chromedriver")
    # webPage = webdriver.Remote(desired_capabilities = webdriver.DesiredCapabilities.HTMLUNITWITHJS)
    try:
        webPage.get(url)
    except:
        print("Error getting webPage")
    
    result = perform_auth(webPage)
    print(result)
    # print(webPage.page_source)
    # while(1):
    #     text = input()
    #     if(text == 'q'):
    #         os._exit(0)
    #     text_elements = webPage.find_elements_by_xpath("//input[@type='text']")
    #     # password = webPage.find_element_by_xpath("//input[@type='password']")
    #     submit = webPage.find_element_by_xpath("//input[@type='submi']")
    #     print(text_elements)
    #     # print(password)
    #     print(submit)

if __name__ == '__main__':
  main()
