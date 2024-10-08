# pip install stem


import re
import logging
import requests_html

from stem import Signal
from stem.control import Controller
from pyppeteer import launcher

launcher.DEFAULT_ARGS.remove("--enable-automation")

logging.basicConfig(
    level=logging.INFO,
    format="%(name)s - %(levelname)s - %(funcName)s - %(lineno)d - %(message)s",
)
logger = logging.getLogger(__name__)


default_proxy = None
default_headers = {"User-Agent": requests_html.user_agent(), "Accept-Charset": "utf-8"}


def read_lines(file_path):
    result = None
    with open(file_path, mode="r", encoding="utf-8") as fp:
        result = [url.strip() for url in fp.readlines() if len(url) != 0]
    return result


def extract_domain(urls):
    domain_pattern = r"https?://([a-zA-Z0-9.-]+)"

    if type(urls) == str:
        return re.find(domain_pattern, urls)
    else:
        return [re.find(domain_pattern, url) for url in urls]


def check_active_by_head(url):
    if (
        requests_html.requests.head(
            "http://" + url, allow_redirects=True, timeout=2
        ).status_code
        < 400
    ):
        return False
    return True


def request_warper_with_render(
    url, headers=None, cookies=None, proxies=default_proxy, **kwargs
):
    webpage = None
    result = None

    try:
        with requests_html.HTMLSession() as session:
            webpage = session.get(
                url=url, headers=headers, cookies=cookies, proxies=proxies
            )
            if webpage.status_code == 200:
                webpage.html.render(retries=2, sleep=1, scrolldown=4, **kwargs)
                webpage.encoding = "utf-8"
                result = webpage.text

                with open("main.html", mode="w", encoding="utf-8") as fp:
                    fp.write(webpage.text)

                webpage.close()
            else:
                logger.error("错误信息:{}\n".format(webpage.status_code))
    except Exception as error:
        logger.error("错误信息:{}\n".format(str(error)))

    return result


import socket, socks


def enable_v2ray_proxy():
    global default_proxy
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 10808)
    socket.socket = socks.socksocket
    default_proxy = {
        "socks5": "socks5://127.0.0.1:10808",
        "http": "http://127.0.0.1:10809",
    }


def enable_tor_proxy():
    global default_proxy
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket
    default_proxy = {
        "socks5": "socks5://127.0.0.1:9050",
        "http": "socks5://127.0.0.1:9050",
    }


def tor_switch_proxy():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
