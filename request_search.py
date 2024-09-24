# -*- coding: utf-8 -*-
import re
import requests
import requests_html 
import xmltodict 
from bs4 import BeautifulSoup
import urllib

def check_urls_active_by_head(urls):
    result = set()
    for url in urls:
        try:
            if requests.head("http://" + url, allow_redirects=True, timeout = 2).status_code < 400:
                result.add(url)
        except:
            pass
    return result

def read_crawler_config(config_path="./config.xml"):
    with open(config_path,mode="rb") as fp:
        config_dict = xmltodict.parse(fp,encoding="utf-8")
    return config_dict


def read_urls_by_file(file_path):
    result = None
    with open(file_path,mode="r",encoding="utf-8") as fp:
        result =  [url.strip() for url in fp.readlines() if len(url)!= 0]
    return result

def filter_rule_match(info,rules):
    if type(rules) == dict:
        return info[rules["filter_type"]].find(rules["content"]) != -1
    else:
        return all([info[filter_rule["filter_type"]].find(filter_rule["content"])!= -1 for filter_rule in rules])


def rule_match_lower(soup,location,content):
    node = soup.select_one(location)
    if node != None:
        for string in node.stripped_strings: 
            if string != None and re.search(content,string) != None:
                return True
    return False
    
def rule_match(soup,rule):
    result = []

    if type(rule["rule_unit"]) == dict:
        result.append(rule_match_lower(soup,rule["rule_unit"]["location"],rule["rule_unit"]["content"]))
    else:
        for rule_unit in rule["rule_unit"]:
            result.append(rule_match_lower(soup,rule_unit["location"],rule_unit["content"]))

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



def engine_crawler_callback(url,param):
    pass
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36'
}

def request_warper(url):
    response = None
    try:
        session = requests_html.HTMLSession()
        response = session.get(url,headers=headers,timeout=(10,15))

        if response.status_code == 200:
            response.html.render(scrolldown = 4,sleep = 2)
            response.encoding = "utf-8"
        else:
            print("连接失败:{}    错误代码:{}\n".format(url,response.status_code))
            response = None
    except Exception as error:
        print("连接失败:{}    异常:{}\n".format(url,str(error)))
        response = None

    return response

    
def bing_crawler(keyboard,rule):

    search_url = "https://www.bing.com/search?q={}".format(urllib.parse.quote(keyboard))
    domain_pattern = r'https?://([a-zA-Z0-9.-]+)'
    urls = set()

    while search_url:
        response = request_warper(search_url)
        if response == None:
            break

        soup = BeautifulSoup(response.text)
        for item in soup.find_all('li', class_='b_algo'):
            link = ""
            title = ""
            summary = ""

            if item.find('h2') != None:
                link = item.find('h2').a['href']
                title = "".join([string for string in item.find('h2').stripped_strings if string])
            if item.find('p2') != None:
                summary = "".join([string for string in item.find('p2').stripped_strings if string]) if item.find('p') else 'No summary'

            if filter_rule_match({"title":title,"link":link,"summary":summary},rule["filter_rule_set"]["filter_rule"])==True:
                urls.add(re.findall(domain_pattern, link)[0])

        next_page = soup.find('a', class_='sb_pagN')
        search_url = "https://www.bing.com" + next_page['href'] if next_page else None

    return crawler_loop(urls,rule)

def crawler_loop(urls,rules):
    result = dict()

    for url in urls:
        response = request_warper("http://" + url)
        if response != None:
            result[url] = rule_match_warp(response.text,rules)
    return result

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
    result = None
    config = read_crawler_config(config_path)["config"]

    if config["urls_file"] != None:
        urls = check_urls_active_by_head(read_urls_by_file(config["urls_file"]))
        result = crawler_loop(urls,config["rule_container"]["rule"])
    else:
        result = rule_walker(config["rule_container"]["rule"],config)
    return result


crawler_mian(r"C:\Users\26538\Desktop\src\src\config.xml")
