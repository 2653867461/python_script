# pip install bs4 requests_html telethon cryptg pillow aiohttp hachoir twint lxml[html_clean] shodan

import re
import logging
import requests_html

from shodan import Shodan
from bs4 import BeautifulSoup
from urllib.parse import quote
from util import request_warper_with_render

from util import default_proxy
from util import default_headers

logging.basicConfig(
    level=logging.INFO,
    format="%(name)s - %(levelname)s - %(funcName)s - %(lineno)d - %(message)s",
)
logger = logging.getLogger(__name__)

default_quake_token = "f81d294b-7a1a-40a9-861d-f0990c13b5e5"
default_telegram_token = "7766598547:AAEL58ZZ27d3eIYUjKxuBzwNliEWs4UG5Ng"
default_shodan_token = "FwYffREcrkxi2etdqpiife0OnzDJwdEq"


def bing_spider(keyword, header=default_headers, proxies=default_proxy, limit=100):
    url = "https://www.bing.com/search?q={}".format(quote(keyword))
    result = dict()
    page = 0

    while url and limit:
        response = request_warper_with_render(url, header, None, proxies)
        if response == None:
            break

        soup = BeautifulSoup(response, features="lxml")
        for item in soup.find_all("li", class_="b_algo"):
            node = item.find("h2")
            link = node.a["href"] if node else None

            if link != None:
                result[link] = "".join([string for string in node.stripped_strings])

        header["Referer"] = url
        next_page = soup.find("a", class_="sb_pagN")
        url = "https://www.bing.com" + next_page["href"] if next_page else None
        limit -= 1
        page += 1

    logger.info(
        "搜索结束 搜索内容：{}\t翻页次数：{}\t结果数量：{}".format(
            keyword, page, len(result)
        )
    )
    return result


def google_spider(keyword, header=default_headers, proxies=default_proxy, limit=100):
    url = "https://www.google.com/search?q={}".format(quote(keyword))
    result = dict()
    link_pattern = "&url=([^&]+)"
    page = 0

    while url and limit:
        response = request_warper_with_render(url, header, None, proxies)
        if response == None:
            break

        soup = BeautifulSoup(response, features="lxml")

        for item in soup.find_all("div", class_="egMi0"):
            node = item.find("a")
            link = (
                re.search(link_pattern, node["href"]).group(0) if node != None else None
            )
            if link != None:
                result[link] = "".join(
                    [
                        string
                        for string in item.find("div", class_="BNeawe").stripped_strings
                    ]
                )

        header["Referer"] = url
        next_page = soup.find("a", class_="nBDE1b")
        url = "https://www.google.com" + next_page["href"] if next_page else None
        limit -= 1
        page += 1

    logger.info(
        "搜索结束 搜索内容：{}\t翻页次数：{}\t结果数量：{}".format(
            keyword, page, len(result)
        )
    )
    return result


class quake_engine:
    """
    字段	            类型	    必填	默认值	    备注
    pagination_id	    str	        否	    无	        分页id，指定分页id能够获取更多分页数据，分页id过期时间为5分钟
    query	            str	        是	    *	        查询语句
    rule	            str	        否	    无	        类型为IP列表的服务数据收藏名称
    ip_list	            List[str]	否	    无	        IP列表
    size	            int	        否	    10	        单次分页大小，分页大小越大，请求时间越长
    ignore_cache	    bool	    否	    false	    是否忽略缓存
    start_time	        str	        否	    无	        查询起始时间，接受2020-10-14 00:00:00格式的数据，时区为UTC
    end_time	        str	        否	    无	        查询截止时间，接受2020-10-14 00:00:00格式的数据，时区为UTC
    include	            List(str)	否	    无	        包含字段
    exclude	            List(str)	否	    无	        排除字段
    latest	            bool	    否	    false	    是否使用最新数据
    """

    def __init__(self, quake_token=default_quake_token) -> None:
        self.quake_header = {
            "X-QuakeToken": quake_token,
            "Content-Type": "application/json",
        }
        self.quake_token = quake_token
        self.status = "Successful"
        self.quake_url = {
            "service_spider": "https://quake.360.net/api/v3/scroll/quake_service",
            "host_spider": "https://quake.360.net/api/v3/scroll/quake_host",
        }

    def _quake_request_scroll(self, quake_url, quake_header, quake_param, **kwargs):
        result = None
        try:
            while True:
                result = requests_html.requests.post(
                    quake_url, headers=quake_header, json=dict(**quake_param, **kwargs)
                ).json()

                self.status = result["message"]
                pagination_id = result["meta"].get("pagination_id", None)

                yield result["data"]
                if pagination_id == None:
                    break

                quake_param["pagination_id"] = pagination_id
        except Exception as error:
            logger.error("错误信息:{}\n".format(str(error)))

    def quake_service_spider(self, keyword, **kwargs):
        for item in self._quake_request_scroll(
            self.quake_url["service_spider"],
            self.quake_header,
            quake_param={"query": keyword, "latest": True},
            **kwargs
        ):
            yield item

    def quake_host_spider(self, keyword, **kwargs):
        for item in self._quake_request_scroll(
            self.quake_url["host_spider"],
            self.quake_header,
            quake_param={"query": keyword, "latest": True},
            **kwargs
        ):
            yield item


class shodan_engine:
    """
    {
        "matches": [
            {
                "product": "nginx",
                "hash": -1609083510,
                "ip": 1616761883,
                "org": "Comcast Business",
                "isp": "Comcast Business",
                "transport": "tcp",
                "cpe": [
                    "cpe:/a:igor_sysoev:nginx"
                ],
                "data": "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nDate: Mon, 25 Jan 2021 21:33:48 GMT\r\nContent-Type: text/html\r\nContent-Length: 650\r\nConnection: close\r\n\r\n",
                "asn": "AS7922",
                "port": 443,
                "hostnames": [
                    "three.webapplify.net"
                ],
                "location": {
                    "city": "Denver",
                    "region_code": "CO",
                    "area_code": null,
                    "longitude": -104.9078,
                    "country_code3": null,
                    "latitude": 39.7301,
                    "postal_code": null,
                    "dma_code": 751,
                    "country_code": "US",
                    "country_name": "United States"
                },
                "timestamp": "2021-01-25T21:33:49.154513",
                "domains": [
                    "webapplify.net"
                ],
                "http": {
                    "robots_hash": null,
                    "redirects": [],
                    "securitytxt": null,
                    "title": "400 The plain HTTP request was sent to HTTPS port",
                    "sitemap_hash": null,
                    "robots": null,
                    "server": "nginx",
                    "host": "96.93.212.27",
                    "html": "\r\n400 The plain HTTP request was sent to HTTPS port\r\n\r\n400 Bad Request\r\nThe plain HTTP request was sent to HTTPS port\r\nnginx\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n",
                    "location": "/",
                    "components": {},
                    "securitytxt_hash": null,
                    "sitemap": null,
                    "html_hash": 199333125
                },
                "os": null,
                "_shodan": {
                    "crawler": "c9b639b99e5410a46f656e1508a68f1e6e5d6f99",
                    "ptr": true,
                    "id": "534cc127-e734-44bc-be88-2e219a56a099",
                    "module": "auto",
                    "options": {}
                },
                "ip_str": "96.93.212.27"
            },
            {
                "product": "nginx",
                "hostnames": [
                    "kolobok.us"
                ],
                "hash": 1940048442,
                "ip": 3104568883,
                "org": "RuWeb",
                "isp": "RuWeb",
                "transport": "tcp",
                "cpe": [
                    "cpe:/a:igor_sysoev:nginx:1.4.2"
                ],
                "data": "HTTP/1.1 410 Gone\r\nServer: nginx/1.4.2\r\nDate: Mon, 25 Jan 2021 21:33:50 GMT\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-Length: 295\r\nConnection: keep-alive\r\n\r\n",
                "asn": "AS49189",
                "port": 80,
                "version": "1.4.2",
                "location": {
                    "city": null,
                    "region_code": null,
                    "area_code": null,
                    "longitude": 37.6068,
                    "country_code3": null,
                    "latitude": 55.7386,
                    "postal_code": null,
                    "dma_code": null,
                    "country_code": "RU",
                    "country_name": "Russia"
                },
                "timestamp": "2021-01-25T21:33:51.172037",
                "domains": [
                    "kolobok.us"
                ],
                "http": {
                    "robots_hash": null,
                    "redirects": [],
                    "securitytxt": null,
                    "title": "410 Gone",
                    "sitemap_hash": null,
                    "robots": null,
                    "server": "nginx/1.4.2",
                    "host": "185.11.246.51",
                    "html": "\n\n410 Gone\n\nGone\nThe requested resource/\nis no longer available on this server and there is no forwarding address.\nPlease remove all references to this resource.\n\n",
                    "location": "/",
                    "components": {},
                    "securitytxt_hash": null,
                    "sitemap": null,
                    "html_hash": 922034037
                },
                "os": null,
                "_shodan": {
                    "crawler": "c9b639b99e5410a46f656e1508a68f1e6e5d6f99",
                    "ptr": true,
                    "id": "118b7360-01d0-4edb-8ee9-01e411c23e60",
                    "module": "auto",
                    "options": {}
                },
                "ip_str": "185.11.246.51"
            },
            ...
        ],
        "facets": {
            "country": [
                {
                    "count": 7883733,
                    "value": "US"
                },
                {
                    "count": 2964965,
                    "value": "CN"
                },
                {
                    "count": 1945369,
                    "value": "DE"
                },
                {
                    "count": 1717359,
                    "value": "HK"
                },
                {
                    "count": 940900,
                    "value": "FR"
                }
            ]
        },
        "total": 23047224
    }
    """

    def __init__(
        self, shodan_token=default_shodan_token, proxies=default_proxy
    ) -> None:
        self.shodan_token = shodan_token
        self.shodan_client = Shodan(shodan_token)

    def shodan_spider(self, keyword):
        for item in self.shodan_client.search_cursor(keyword):
            yield item


print(bing_spider("百度知道"))
