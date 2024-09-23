# -*- coding: utf-8 -*-

import requests
import requests_html 
import xmltodict 
import re
from bs4 import BeautifulSoup
import urllib

def check_urls_active_by_head(urls):
    result = set()
    for url in urls:
        try:
            if requests.head("http://" + url, allow_redirects=True, timeout=1.00).status_code < 400:
                result.add(url)
        except:
            pass
    return result

def read_crawler_config(config_path="./config.xml"):
    with open(config_path,mode="rb") as fp:
        config_dict = xmltodict.parse(fp,encoding="utf-8")
    return config_dict

def read_urls_by_file(file_path):
    with open(file_path,mode="r",encoding="utf-8") as fp:
        result =  [url.strip() for url in fp.readlines() if len(url)!= 0]
    return result

def init_webdriver(config):
    pass

def filter_rule_match(info,rules):
    if type(rules) == dict:
        return info[rules["filter_type"]].find(rules["content"]) != -1
    else:
        return all([info[filter_rule["filter_type"]].find(filter_rule["content"])!= -1 for filter_rule in rules])



def engine_crawler_callback(url,param):
    pass
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36'
}

import time
def bing_crawler(keyboard,rule):

    search_url = "https://www.bing.com/search?q={}".format(urllib.parse.quote(keyboard))
    domain_pattern = r'https?://([a-zA-Z0-9.-]+)'
    session = requests_html.HTMLSession()
    urls = set()

    while search_url:

        response = session.get(search_url,headers=headers,timeout=(10,15))
        response.html.render(scrolldown = 4,sleep = 2)

        soup = BeautifulSoup(response.text, 'lxml',from_encoding=response.encoding)

        for item in soup.find_all('li', class_='b_algo'):
            title = item.find('h2').text
            link = item.find('h2').a['href']
            summary = item.find('p').text if item.find('p') else 'No summary'

            if filter_rule_match({"title":title,"link":link,"summary":summary},rule["filter_rule_set"]["filter_rule"])==True:
                urls.add(re.findall(domain_pattern, link)[0])

        next_page = soup.find('a', class_='sb_pagN')
        search_url = "https://www.bing.com" + next_page['href'] if next_page else None

    return crawler_loop(urls,rule)

def crawler_loop_webdrive(webdriver,urls,config):
    pass

def crawler_loop(urls,rules):
    result = dict()

    for url in urls:
        try:
            response = requests.get("http://{}".format(url),allow_redirects=True,timeout=(10,15))
            response.encoding = "utf-8"
            if response.status_code == 200:
                result[url] = "match_result:" + str(rule_match_warp(response.content,rules))
            else:
                result[url] = "connect_failed:" + str(response.status_code)
        except Exception as errpr:
            print(errpr)
    return result

def rule_match(soup,rule):
    def beautifulsoup_select_warp(soup,location):
        result = soup.select(location)
        if result != None:
            return result
        return []
    
    result = []

    if type(rule["rule_unit"]) == dict:
        for match in beautifulsoup_select_warp(soup,rule["rule_unit"]["location"]):
            result.append(match.get_text().find(rule["rule_unit"]["content"]) != -1)
        if len(result) == 0:
            result.append(False)
    else:
        for rule_unit in rule["rule_unit"]:
            for match in beautifulsoup_select_warp(soup,rule_unit["location"]):
                result.append(match.get_text().find(rule_unit["content"]) != -1)
        if len(result) != len(rule["rule_unit"]):
            result.append(False)

    if rule.get("rule_set",None) != None:
        if type(rule["rule_set"]) == dict:
            result.append(rule_match(soup,rule))
        else:
            for item in rule["rule_set"]:
                result.append(rule_match(soup,item))

    if rule["@relationship"] == "OR":
        return any(result)
    else:
        return all(result)


def rule_match_warp(content,rules):
    soup = BeautifulSoup(content,"lxml")

    if type(rules) == dict:
        if rule_match(soup,rules["rule_set"]) != False:
            return rules["@name"]
    else:
        for rule in rules:
            if rule_match(soup,rule["rule_set"]) != False:
                return rule["@name"]
    return None

engine_crawler = {
    "bing" : bing_crawler
}


def rule_walker(rules,config):
    if type(rules) == dict:
        return engine_crawler[rules["@engine_name"]](rules["@keyboard"],rules)
    else:
        for rule in rules:
            return engine_crawler[rule["@engine_name"]](rule["@keyboard"],rule)

#爬虫主入口
def crawler_mian(config_path):
    config = read_crawler_config(config_path)["config"]
    result = None

    if config["urls_file"] != None:
        urls = check_urls_active_by_head(read_urls_by_file(config["urls_file"]))
        
        if config["webdriver"] == "True":
            webdriver = init_webdriver(config)
            result = crawler_loop_webdrive(webdriver,urls,config)
        else:
            result = crawler_loop(urls,config["rule_container"]["rule"])
    else:
        result = rule_walker(config["rule_container"]["rule"],config)
    return result


crawler_mian(r"C:\Users\26538\Desktop\src\src\config.xml")