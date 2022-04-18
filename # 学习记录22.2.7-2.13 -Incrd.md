# 学习记录22.2.7-2.13 -Incrd

## Salsa20 算法

算法介绍参考：
<https://cr.yp.to/salsa20.html>  
<https://cr.yp.to/snuffle/salsafamily-20071225.pdf>

Salsa20是一种流式对称加密算法，类似于Chacha20，算法性能相比AES能够快3倍以上。
Salsa20算法通过将 32 Byte 的key和 8 Byte 的随机数nonce扩展为 2^70 Byte 的随机字节流，通过随机字节流和异或操作实现加解密，因此 Salsa20 算法中随机字节流的生成为关键所在。  

加解密操作
得到随机字节流之后，Salsa算法的加解密操作极其简单。  

- 加密操作：  
当加密长度为b字节的明文数据时，通过将明文数据和随机字节流的前b个字节进行异或运算得到密文。  
- 解密操作：  
当解密长度为b字节的数据时，通过将密文和b字节的字节流进行异或运算得到明文。  

## picoCTF Compress and Attack

compress_and_attack.py

```python
#!/usr/bin/python3 -u

import zlib
from random import randint
import os
from Crypto.Cipher import Salsa20

flag = open("./flag").read()


def compress(text):
    return zlib.compress(bytes(text.encode("utf-8")))

def encrypt(plaintext):
    secret = os.urandom(32)
    cipher = Salsa20.new(key=secret)
    return cipher.nonce + cipher.encrypt(plaintext)

def main():
    while True:
        usr_input = input("Enter your text to be encrypted: ")
        compressed_text = compress(flag + usr_input)
        encrypted = encrypt(compressed_text)
        
        nonce = encrypted[:8]
        encrypted_text =  encrypted[8:]
        print(nonce)
        print(encrypted_text)
        print(len(encrypted_text))

if __name__ == '__main__':
    main() 

```

使用了 Salsa20 加密算法，目前并没有公认对其有效的攻击方式，且题目也仅给出nonce，没有泄露随机生成的密钥。  
注意到题目标题提到了 compress，而且在题目加密过程中，在 `encrypt` 函数前，先执行了 `compress(flag + usr_input)`，同时我们可以构造明文的一部分，参考 [CRIME](https://en.wikipedia.org/wiki/CRIME)，即当压缩结果长度缩小时，可以推断注入内容的某些部分可能与源的某些部分匹配，从而一步步推断出明文内容。  

so the crack is:

```python
from pwn import *
import string

def get_min_args(zlib_oracle):
    sorted_oracle = sorted(zlib_oracle.keys(), key = lambda i: zlib_oracle[i])
    min_value = zlib_oracle[sorted_oracle[0]]
    min_args = []
    for arg in sorted_oracle:
        if zlib_oracle[arg] == min_value:
            min_args.append(arg)
        else:
            break
    return min_args

def main():
    r = remote("mercury.picoctf.net", 29675)
    attempt_list = string.ascii_letters + string.digits + "_}"
    base_list = ["picoCTF{"]
    found = False
    while not found:
        zlib_oracle = {}
        for base in base_list:
            for char in attempt_list:
                payload = base + char
                try:
                    r.sendline(payload)
                    r.recvlines(2)
                    print("attempt: ", end = "")
                    print(payload)
                    val = int(r.recvline(keepends=False).decode())
                    zlib_oracle[payload] = val
                except:
                    r = remote("mercury.picoctf.net", 29675)
        base_list = get_min_args(zlib_oracle)
        if len(base_list) == 1 and base_list[0][-1] == '}':
            found = True
            r.close()
    print("Flag found: {}".format(base_list[0]))

if __name__ == "__main__":
    main()
```

## picoCTF Scrambled: RSA

Description:  
Hmmm I wonder if you have learned your lesson... Let's see if you understand RSA and how the encryption works.  
Connect with nc mercury.picoctf.net 47987.  

nc mercury.picoctf.net 47987.  

```text
flag: 1113251507597950021531592612978156945108835531286327173728153476895912816291029754437208842062605055538745213054720031020830128996819844516704521902837451497360259035029598382297774675382632343715764980576718507548354716352034674140201733057963972697518339445838442305458550686051069659504965440505351493031631264053459009271925226002248712745830342247130624996659909143519639939159279401165524950739322568287879590564196678397702375113326183793854658181570273610595902243200484974839614484180793592753868921174605419864781554373091371265422682361113452618729309420639184148165705914322553347189275207796050062964414825595758977259237617034538812828037365762957057252138688707397332690334492502215793702085270923592464296453313890557420042298723583896144802291189337277979319573813427484240269599036369653410636235067165740637234232401425104902606660819352362073931132214937502806318713300938768175863256467468624862351047863799851582961131519960067858317512346623360462389854293863733063913107646527246872136487651616332393951337247621143319440629182848295701872021949036220711675931669628369479978310742659372321123127379196217685538935970702056726695511834683067766178276198306650286195724779016114398458815612136246407918712716028109610633660388808923748791205248107010541420846550973931380694703938826811472103724093814804762853089598514484506195222505153847684386976430949084188631268556763864479518047296075197527984668725857100882570093559537468852548676081266601448840924764671909922816023536763180460474290061989346142107941832830226113572935940938663422922759157474791705986064906828231667747226112280154748980636968013379970332581044959311939329890105420602651908835864387697127176702274696358158931803071117633348856625773343358132301043023532927232169739169851145788019909754742667064622580357713232480559837919131048675715111169216353057777528409755287225709063877681649120257518187942732073201964606851778960859795354271838853828322323305135768456675885056703882262575653741844612996497459568056137529520931808801356721657626082165778140173475381818699376395923889962369499639088592058174602893191882877660217661141859011401976638027611021991558563177456521389838380000949860740742284563164699552853342106308087734757698346774693813710564130017863531325404180217298450947589959414783249533448298203785677211212555585179028319447141603330217552008414436599305586269739022753535060877872727483490083827186440205419641989097587582831360836478719492386053366792072716084802252279465163968807664857228463436984621399244291419565099658339835498027441619830082161599309416677576918713952602887704014462625485864837305096114389990659932588469208805599632574937504364495193993882668825493376180203596099353890008193986038916721442960241314691195916159345492318339638797701301161351309681742705402260040123760181374814779054280267243946121408341013812575317748363139115486363354415534638180790587029328880656943724280930950434195866033840646457653224534136732237788606558692343091044608209929150000285766907641618435192670541594868790701248338445510980797863777893858745214389502271188333732971740199936491079377885558822398481585971498685783670729172749770659110917918070497577172369805913778023520769558702771012446674425394433654484415290838314573336783619252558705059649227955268843908541696208151748323429051337834675931613522176984925084010930669144324062450868002131581891204948012884490997094529489117938965721316122564673309669065676507513072888537971953718916258363701347467749260321862017510129611810479935321414624121746569657301853248379101020979167044739257216885358423417993479047748952367803717269487962735079527689282714239154033095209194729867731859747055640934913215633610423018651125580272890208882226993301352016201092568200621666336413854784026885615578523234566109609209136528300966574053328132184272566034636488051942025883042207143032801224807260713983298797656996999978071587421819794299988157370167618236911914433503946229595687577633154413073578104120586081403888393622103374112154348820325453269174926422542003390778376330716091991294891314197117307617076542762166190479075553161672344678552454513745001576780823869837829692958507160913205989872735804255305750531663033101143686110925599484066454389353420341520322262551132470558940162824737043177975634556748314075569722231903335097140007220615497578686325976554302590952404310391795413924147612043684218599378123823683004187702137654031597277827730907209980505905142396750226514590218161842109102520803272202499938015678975271422714061034214681341827699248142458985149601428658051749445253573180503782118226438577246718680624550608125367596135239696994123950333753115548227618399202446129217542365341523194280697531630791514827159564443075272599941139003891676980736330786679836206223319090377284979204192377689849391906128774663726988370698020463436458591054218008540758821822186694448148303386803827699063950693627068955759894463589602682232944311624671770337642809968964364980826559351347931212981414622483872919578854093728636437365229035433124416893820566792347114402058570501440926444970229288981516592483545001461338355992576814648564114843888390286776087875767156705392336958308148260217317238819393970506349811277141745861309177952686540377266728837389207956053490274485273743914413338689788001807175739102711972485056414615404329119573210840379552323634545232248675969563527900898865278271618737500856657089084322462304583892613322588771842729683964443336479125493160818168203580509249074833738315067122778868140829173566476889871705824327577990860278431701833063232515225256860761095990401794547515644383223567835955888822333178137893911414615358753165349307739629056904108896986777433235441852734657377214401518398999999610254771854861155786951593185680025363946837801541897952772640887033148992354983649746837457502763439608537306774651089800825314910813817562582130572122607755991015777717403772821775747161658250512064609858497688764209724473997330228559177204036831854389987663204655208484958752012196450515135058519751654249832044550106447214420200309700851853626754795190265480166950474822524702538520887627708036958122768655816209987124277263841541873930254498410226700626147347163904922973092194305549461407800993855144620627878847238782816450202309583799499650283102134452452470941568303309759856836019201214754833720148634917283400635116248785941057247827300789756636333834416287287185549133500146480924631300707066580428314611540456356301737810037391854329126494625334697338723714835022287566995794956051145630520090090546771615225825050383809265664228160013250208231057761048460194950627836949863114046344659562384044058603518504062094644623940283910522812451767837021162344410971764895861525068252655195915448564632167489645338415661167006216046687055701126723564719433017960539298377208806244968956789304686824246455127375533119824174341095447714633953580523942715665305309534897540669710430247527408706137111120137847919431220271939277389879211974367767726276427116623298508166127652326237517702327551571136741340480692901771005133497904814422606096598475693541650315872397941243094486782692075815970120986012100689638455575204381922880898794814517478909003960321071677721318043686635196067601939616123828311131245836420354706974232650731791038727186357364915010329166164158098697302877878786934462861427508529893887396069553149832404061672365599162466522731276562049719752017804158864362400249989837062059169465664120633585480728302613743174556649335954645010685772132689987148581073836317635549723767308048602018328869450885282177182670895606493263538386609000579654940719547355826814232348838392828667476579893482397258212561870836658548778229614290581143665850268554827327674119525517407094111002672867378604819178755200464432397356149037881370858498231236563378566741668964113773143502178857124356361480282381475294478182239397733690032788639885538141645295496162421154786729652460003531207268559200584092458595946741596371083578121121067087181408986281769466279741467448876843906664352976472304785
n: 131568250215399433645887008336311984097592160012738275802809667994813320254186467319065456582766686012957498566663245348650221686696318706488774781909810757827100278352136851250336980527208949300792702751981171942594854585489309697543928047109220862383491602155052016350160559563097526040273993931968061582653
e: 65537
I will encrypt whatever you give me:
```

连接后发现加密后的 flag 长得离谱，尝试随便输入一些信息比如 `1` 加密后发现结果也是不同寻常的，与本地计算 $p^emod\ n$ 的结果也没什么联系，说明题目其实并不是 RSA 算法，尝试加密 `a`, `ab`，发现加密 `ab` 会得到两种结果，而 `a` 加密的结果总在其中，`ab` 的加密结果貌似是由两部分结合再经过排列得到的，加密 `b` 发现其结果并不在 `ab` 的加密结果中，而是以某种其他形式出现的，假设加密函数为 `enc()`, `unk()` 为一未知函数，结论基本就是 `enc(a)` 总会出现在 `enc(axxxx)` 的某个位置,而 `enc(x)` 会以 `unk(enc(x))` 的形式出现在整体的加密结果中，因此我们只需要记录每一个 `unk(enc(x))` 就能对结果进行逐位枚举。

now the crack is:

```python
import string

from pwn import *

char_list = string.printable[:-5]
r = connect("mercury.picoctf.net", 47987)
r.recvuntil(b"flag: ")
encrypted_flag = r.recvuntil(b"\nn: ", drop=True).decode()

def encrypt(p):
    global r
    while True:
        try:
            print("Sending", p)
            r.sendlineafter("I will encrypt whatever you give me: ".encode("utf-8"), p.encode("utf-8"))
            c = r.recvline(keepends=False).decode().replace("Here you go: ", "")
            break
        except:
            print("Reconnectting")
            r = remote("mercury.picoctf.net", 47987)
            print("Updating!")
            update_encrypted_flag()
            update_segments()
    return c

def update_encrypted_flag():
    global encrypted_flag, r
    r.recvuntil(b"flag: ")
    encrypted_flag = r.recvuntil(b"\nn: ", drop=True).decode()

def update_segments():
    global known_segments, result
    known_segments = []
    for i in range(len(result)):
        current_test = result[:i+1]
        current_encrypt_test = encrypt(current_test)
        current_encrypt_char = remove_segments(current_encrypt_test, known_segments)
        known_segments.append(current_encrypt_char)

def remove_segments(result, segments):
    # Remove all previously seen segments.
    for segment in segments:
        result = result.replace(segment, "")
    return result

result = ""
known_segments = []
while not "}" in result:
    for char in char_list:
        current_test = result + char
        current_encrypt_test = encrypt(current_test)
        current_encrypt_char = remove_segments(current_encrypt_test, known_segments)

        if current_encrypt_char in encrypted_flag:
            print("New Letter Found: %s+[%s]" % (result, char))
            result += char
            known_segments.append(current_encrypt_char)
            break

print("Complete Flag: %s" % result)

```

写的时候被一个点卡了很久，就是 nc 连接一段时间后，服务端会主动切断连接，而且重新连接后的加密密钥会重新设置，就导致了每次不仅要检查重连，还要在重连的时候更新记录的 `unk(enc(x))` 列表，改 bug 改了挺久的，编程技术有待提高，得多注意细节，细节！！！

## picoCTF XtraORdinary

Description:  
Check out my new, never-before-seen method of encryption! I totally invented it myself. I added so many for loops that I don't even know what it does. It's extraordinarily secure!  

encrypt.py

```python
#!/usr/bin/env python3

from random import randint

with open('flag.txt', 'rb') as f:
    flag = f.read()

with open('secret-key.txt', 'rb') as f:
    key = f.read()

def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt

ctxt = encrypt(flag, key)
    
random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'break it'
]

for random_str in random_strs:
    for i in range(randint(0, pow(2, 8))):
        for j in range(randint(0, pow(2, 6))):
            for k in range(randint(0, pow(2, 4))):
                for l in range(randint(0, pow(2, 2))):
                    for m in range(randint(0, pow(2, 0))):
                        ctxt = encrypt(ctxt, random_str)

with open('output.txt', 'w') as f:
    f.write(ctxt.hex())
```

output.txt

```text
57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637
```

`encrypt()` 函数只是进行了一步异或操作，再看下面的加密流程，先是 `ctxt = encrypt(flag, key)` 用 `key` 作为密钥，再进入下面的循环。  
我们知道  
$N⊕A⊕A=N$  
所以循环中如果用同样的密钥异或偶数次即相当于无操作，因此重复的 `ever` 可以缩减成一个，`for random_str in random_strs:` 中的循环嵌套便可以都看成 `for m in range(randint(0, pow(2, 0))):`，根据排列组合共有 $2^5=32$ 种可能，可以进行穷举，但是本题的难点应该是第一次加密使用的 `key` 是未知的，因此只能假设 `flag` 的前缀为 "picoCTF{"，并且只有 `key` 长度小于 `len("picoCTF{")` 时才有可能解出 `key`。

```python
import itertools

def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt


ciphey = "57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637"
random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]

flag_prefix = b'picoCTF{'
for i in range(0,6):
    c = bytes.fromhex(ciphey)
    new_string = list(itertools.combinations(random_strs, i))
    for sub_new_string in new_string:
        for word in sub_new_string:
            c = encrypt(c, word)

        key = encrypt(c, flag_prefix)
        key = key[:len(flag_prefix)].decode()
        if key.isprintable():
            print(key)
            
```

这里还用了 `isprintable()` 函数缩减可能结果。  

```text
Bhr~a'0R
Elrmoq<T
Bhr~a'0R
Elrmoq<T
Bhr~a'0R
Africa!A
Elrmoq<T
```

其中 `Africa!A` 最为可疑，出现了 Africa 有意义单词，且结尾的 A 说明可能已经进入密钥循环了，因此可以假定 `key` 即为 `Africa!`。  

因此解密脚本即为：

```python
import itertools

def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt


ciphey = "57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637"
random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]

key = b'Africa!'
flag_prefix = b'picoCTF{'
flag = ""
for i in range(0,6):
    c = bytes.fromhex(ciphey)
    new_string = list(itertools.combinations(random_strs, i))
    for sub_new_string in new_string:
        for word in sub_new_string:
            c = encrypt(c, word)

        flag = encrypt(c, key).decode()
        if flag.isprintable():
            print(flag)
            
```

output:

```text
tcckOD[nr4=wHs4W5Re0}e5X3hm9>aTd1>'..y
tcckOD[nr4=wHs4W5Re0}e5X3hm9>aTd1>'..y
picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}
tcckOD[nr4=wHs4W5Re0}e5X3hm9>aTd1>'..y
```

## VNCTF2022 CRYPTO ezmath

Description:  
只是一个简单的数学问题，不过后面的题目可能需要他才能开启喔。  
  
\*flag's format: flag{ \*}  

server.py:

```python
from Crypto.Util.number import*
import random
from secret import flag,check
from hashlib import sha256
import socketserver
import signal
import string 

table = string.ascii_letters+string.digits
class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b''):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        proof = (''.join([random.choice(table)for _ in range(20)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return True

    def handle(self):
        proof = self.proof_of_work()
        if not proof:
            self.request.close()
        counts = 0
        signal.alarm(60)
        for i in range(777):
            times = getPrime(32)
            self.send(b'plz give me the ' + str(times).encode() + b'th (n) that satisfying (2^n-1) % 15 == 0:')
            n = int(self.recv())
            a , ret = check(times,n)
            if a == True:
                self.send(ret.encode())
                counts += 1
            else:
                self.send(ret.encode())
        if counts == 777:
            self.send(b'You get flag!')
            self.send(flag)
        else:
            self.send(b'something wrong?')
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever() 

```

```text
[+] sha256(XXXX+AUU33i61TjfSXNwy) == 98c9bfa54725a41e347ecab10f0fa57fbcb0723fd40f7eb3bb3d8f6f9ec89581
[+] Plz Tell Me XXXX :lpDL
plz give me the 3903583727th (n) that satisfying (2^n-1) % 15 == 0   (the 1st 2^n-1 is 15):
```

第一个问题是 sha256 爆破，只要求缺失的前四位，可以直接穷举。  
第二个问题是求第 x 个满足 $(2^n-1) mod\ 15 == 0$ 的 n。  
过程：  
$(2^n-1) mod\ 15 == 0$  
$2^n ≡ 1 (mod\ 15)$  
$2*2^{n-1} ≡ 1 (mod\ 15)$  
根据 $ab≡1(mod\ 15)$ 中 b 为 a 关于模 15 的模反元素，且显然如果 b 是 a 的模反元素，则 $b+k*15(k∈N^*)$ 都是 a 的模反元素。  
a = 2, b = 8  
即有 $2*(8+k*15) ≡ 1 (mod\ 15)$  
$2^{n-1}=8+k*15$    两边同除以 8  
$2^{n-4}=1+k*15/8$  
因此有 $2^{n-4}≡1(mod\ 15)$  
即满足 $2^n ≡ 1 (mod\ 15)$ 的 n 亦满足 $2^{n-4}≡1(mod\ 15)$  
而第一个满足 $2^n ≡ 1 (mod\ 15)$ 的 n = 4  
由递归可得 $n_x=4+(x-1)*4$  
now the crack is

```python
from hashlib import sha256
import string
import itertools as it
from pwn import *
import tqdm

def crack_sha256(part2, sha_result):
    table = string.ascii_letters+string.digits

    part1 = ""

    for e in it.product(table, repeat=4):
        part1 = "".join(e)
        if sha256((part1+part2).encode()).hexdigest().encode() == sha_result:
            break
    return part1

def cal(n):
    return (n-1)*4+4

r = remote("node4.buuoj.cn", 28074)
r.recvuntil("XXXX+".encode())
part2 = r.recvuntil(")".encode(), drop=True).decode()
r.recvuntil(" == ".encode())
sha_result = r.recvline(keepends=False)
r.sendafter("Plz Tell Me XXXX".encode(), crack_sha256(part2, sha_result).encode())

for i in tqdm.tqdm(range(777)):
    r.recvuntil("plz give me the ".encode())
    payload = cal(int(r.recvuntil("th (n) that".encode(), drop=True).decode()))
    r.sendline(str(payload).encode())
print(r.recvall())
```
