---
title: "两个crypto题解"
date: 2023-07-31T14:08:14+08:00
draft: false
---

这两个题目都不是数学题，是与python相关的题目。

## Bruce Schneier's Password

本题来源CryptoHack的Misc部分，分值100pt，属于简单题。题目代码如下：

```python
import numpy as np
import random
import re
from Crypto.Util.number import isPrime
from utils import listener


FLAG = "crypto{????????????????????????????????????????}"
SCHNEIER_FACTS = [
    "If Bruce Schneier had designed the Caesar cipher, Caesar would still be alive today.",
    "It is impossible to hide information from Bruce Schneier. Not even by destroying it.",
    "Bruce Schneier can fill a knapsack in constant time without exceeding the weight.",
    "Bruce Schneier writes his books and essays by generating random alphanumeric text of an appropriate length and then decrypting it.",
    "When Bruce Schneier observes a quantum particle, it remains in the same state until he has finished observing it.",
    "Bruce Schneier knows Alice and Bob's shared secret.",
    "The last cryptologist who questioned Bruce Schneier was found floating face down in his own entropy pool.",
    "Bruce Schneier's house is in a Galois Field.",
    "Bruce Schneier is in the middle of the man-in-the-middle.",
    "When Bruce Schneier wears a security badge, he's authenticating the badge.",
]


def check(password):
    if not re.fullmatch(r"\w*", password, flags=re.ASCII):
        return "Password contains invalid characters."
    if not re.search(r"\d", password):
        return "Password should have at least one digit."
    if not re.search(r"[A-Z]", password):
        return "Password should have at least one upper case letter."
    if not re.search(r"[a-z]", password):
        return "Password should have at least one lower case letter."

    array = np.array(list(map(ord, password)))
    if isPrime(int(array.sum())) and isPrime(int(array.prod())):
        return FLAG
    else:
        return f"Wrong password, sum was {array.sum()} and product was {array.prod()}"


class Challenge():
    def __init__(self):
        self.before_input = f"{random.choice(SCHNEIER_FACTS)}\n"

    def challenge(self, message):
        if not "password" in message:
            self.exit = True
            return {"error": "Please send Bruce's password to the server."}

        password = message["password"]
        return {"msg": check(password)}


listener.start_server(port=13400)
```

题目要求你输入一个字符串，满足以下条件：

- 至少包含一个数字、一个小写字母和一个大写字母，

- 只包含数字、小写字母、大写字母和下划线，

- 所有的字符的ascii值之和为质数，之积也为质数。

显然一堆整数的积并不可能是质数，这里用到的是numpy array的溢出机制。numpy array存储数据是根据内部的元素类型自动决定的，比如array([1, 2, 3])的数据类型是int32，array([2^32])是int64，array([2^64])的数据类型就是object。这里就是要找一些整数，使得和为质数，同时乘积在int64下自然溢出得到的值也为质数。

算了一下大概11到12个字符的ord乘积就可以刚好大于2^64，越大的值质数分布越稀疏，还是搞小一点好。然后暴力跑一下，大约8分钟就得到了一个密码。解答如下：

```python
from Crypto.Util.number import isPrime
import random
import numpy as np
from tqdm import tqdm

L = 10
r = [i for i in range(48, 58)] + [i for i in range(65, 91)] + [i for i in range(97, 123)]
r.append(ord('_'))
zero = pow(2, 64)

for i in range(48, 58):
    for j in tqdm(range(65, 91)):
        for k in range(97, 123):
            for _ in range(100000):
                ciphers = np.array(random.choices(r, k = L) + [i, j, k])
                if isPrime(int(ciphers.sum())) and isPrime(int(ciphers.prod())):
                    print(ciphers)
                    exit(0)

# 9eg3c3Wey91Aa 
```

## gcccd

本题来源于\*ctf 2023，打的时候并没有做出来，看了题解才知道这题很厉害orz

题目如下：

```python
#!/usr/bin/env python3

from secret import flag
import socketserver
import hashlib
import signal
import random
import string
import os

p=20973268502876719886012765513713011996343752519737224550553652605696573094756255499211333096502971357908939298357512380813773140436677393056575164230564778609423872301899323721040416852230597466288892977839300189625522429038289083381035647126860128821615664730513694930502000903655609105029016636999073477487851081722316115785141
enc=lambda x:pow(17,x,p)
m=int(flag.encode().hex(),16)

def gcd(a,b,f=enc):
    if b:
        return gcd(b,a%b,f)
    else:
        return f(a)

class Task(socketserver.BaseRequestHandler):
    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)

    def timeout_handler(self, signum, frame):
        self.request.close()

    def proof_of_work(self):
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        _hexdigest = hashlib.sha256(proof.encode()).hexdigest()
        self.request.send(f"sha256(XXXX+{proof[4:]}) == {_hexdigest}\n".encode()+b'Give me XXXX: ')
        x = self.request.recv(1024).strip(b'\n')
        if len(x) != 4 or hashlib.sha256(x+proof[4:].encode()).hexdigest() != _hexdigest:
            return False
        return True

    def handle(self):
        signal.alarm(60)

        if not self.proof_of_work():
            return

        while True:
            try:
                self.request.send(b'type:')
                t=int(self.request.recv(1024).strip(b'\n'))
                self.request.send(b'a:')
                a=int(self.request.recv(1024).strip(b'\n'))
                self.request.send(b'b:')
                b=int(self.request.recv(1024).strip(b'\n'))
                assert a>0 and b>0
                if t==1:#enc test
                    self.request.send(b'%d\n'%gcd(a,b))
                elif t==2:#leak try1
                    self.request.send(b'%d\n'%gcd(a,m))
                elif t==3:#leak try2
                    self.request.send(b'%d\n'%gcd(a,b,f=lambda x:gcd(x,m)))
                elif t==4:#leak try3
                    self.request.send(b'%d\n'%gcd(a,m,f=lambda x:gcd(x,b)))
                else:
                    self.request.close()
                    break
            except BrokenPipeError:
                break
            except:
                self.request.send(b'Bad input!\n')


class ThreadedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 23333
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
```

这题一开始的想法是让a=0，gcd(a, m)就能得到$17^m \ mod \ p$ ，然后求解离散对数就可以了，可惜a不能等于0。看了题解才知道python的递归次数有1000次左右的限制，考虑利用t=3的代码，控制gcd(a, b)的递归次数可以知道gcd(x, m)的递归次数。

那么知道递归次数有什么用呢？根据递归次数可以知道m % x的值。例如gcd(5, m)，m %  5 =2或者4的时候是4次递归，m % 5 = 3则需要5次递归。这样给出一些x（可以是质数可以是合数），获得递归次数，就可以用crt求解m了。

第一步是知道具体的递归次数限制，可以用gcd(a, b)去求。斐波那契数列是让gcd递归次数显著升高的方法，显然数列相邻两项的gcd递归次数就是项在数列中的下标。所以第一步传入gcd(fb(i), fb(i+1))试探次数，i >= 950。

第二步是构造一个gcd(a, b)使得结果为指定的m，同时递归深度又是指定的。可以根据下面的方法来构造：

```python
def gen(m, depth):
    a, b = m, m
    for _ in range(depth):
        a, b = a + b, a
    return a, b
```

第三步就是遍历m求解，似乎从2遍历到1000就可以拿到足够的方程去解crt。
