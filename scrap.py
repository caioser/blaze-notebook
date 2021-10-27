#!/usr/bin/env python
# coding: utf-8

# In[91]:


import pandas as pd
import numpy as np
import hmac
import hashlib
from datetime import datetime, timedelta
from math import pow, floor

from selenium import webdriver
from selenium.webdriver.common.keys import Keys # send keys like: Keys.ENTER

from selenium.webdriver.common.by import By # find_element_by_xpath == find_element(By.XPATH, "//div[@class='entries']/*")
from selenium.webdriver.support.ui import WebDriverWait # Explicit waits
from selenium.webdriver.support import expected_conditions as EC #conditionits for explicit waits

pd.set_option('max_colwidth', 70)

print('do')


# In[2]:


def divisible(hash_hmac, mod):

#    print(f">>> divisible({hash_hmac}, {mod})")

    val_i = 0
    val_f = 0
    # print(f"estanciando val = {val_i}")
    o = len(hash_hmac) % 4
    # print(f"estanciando o = len(hash_hmac) % 4 = {o}")

    if o > 0:
        o -= 4
        print(f"WARNING: [ o > 0 = True ]   value of 'o' is '{o}'")

#    print(f">>> for x in range(0,{len(hash_hmac)},4):")

    df1 = pd.DataFrame(data={}, columns=["x", "val_i", "bitwised", "hex_hash", "int_hash", "val_f", "== 0"])
    for x in range(0,len(hash_hmac),4):
        # print(f"x = {x}     val = {val_i}")
        # print(f"val_f = ((val_i << 16) + int({hash_hmac[x:x+4]},16)) % mod")
        # print(f"val_f = ({val_i << 16} + {int(hash_hmac[x:x+4],16)}) % {mod}")

        val_f = ((val_i << 16) + int(hash_hmac[x:x+4],16)) % mod

        df1 = df1.append(
                pd.Series([
                    x,
                    val_i,
                    val_i<<16,
                    hash_hmac[x:x+4],
                    int(hash_hmac[x:x+4],16),
                    val_f,
                    val_f==0
                    ],
                    index=df1.columns),
                ignore_index=True)

        val_i = val_f
    #print(df1)
    return [val_i == 0, df1["== 0"]]


# In[3]:


def getPoint(hash_hmac):
#    print("Inicio GETPOINT()")

#    print(f"{hash_hmac} é divisível por 15?")
    test = divisible(hash_hmac, 15)
    if test[0]:
#        print("Sim, então:")
#        print(f"""CRASH: 0\
#
#
#        """)
        return 0
#    print("Não então:")
    h = int(hash_hmac[0:int(52/4)], 16)
    e = int(pow(2, 52))
#    print(f"proporção h/e: {(h/e)*100:.3f}%")
#    print(f"estanciando h = int({hash_hmac[0:int(52/4)]}) = {h:,} ({(h/e)*100:.3f}%)")
#    print(f"estanciando e = int(pow(2, 52)) = {e:,} (100%)")


    # print(f'point = float(format((floor((100 * {e:,} - {h:,}) / ({e:,} - {h:,})) / 100), ".2f"))')

    # print(f'((100 * {e:,} - {h:,}) / ({e:,} - {h:,})) / 100')
    # print(f'(({100*e:,} - {h:,}) / ({e-h:,})) / 100')
    # print(f'({100*e-h:,} / {e-h:,}) / 100')
    # print(f'floor({(100*e-h) / (e-h):,}) / 100')
    # print(f'{floor((100*e-h) / (e-h))} / 100')

#    print(f'((100 * 1 - {h/e:.3f}) / (1 - {h/e:.3f})) / 100')
#    print(f'((100 - {h/e:.3f}) / {1 - (h/e):.3f}) / 100')
#    print(f'({100 - (h/e):.3f} / {1 - (h/e):.3f}) / 100')
#    print(f'floor({(100 - (h/e)) / (1 - (h/e)):.3f}) / 100')

    point = float(format((floor((100 * e - h) / (e - h)) / 100), ".2f"))
#    print(f"""CRASH: {point}\
#
#
#    """)
    return [point,
            int(''.join(str(e) for e in [int(not(e)) for e in list(map(int, test[1].to_numpy()))]), 2),
            ''.join(str(e) for e in [int(not(e)) for e in list(map(int, test[1].to_numpy()))]),
            (h/e)*100]


# In[4]:


def seed(hash, amount=9):
    chain = [hash]
    for x in range(amount):
        chain.append(hashlib.sha256(str.encode(chain[x])).hexdigest())
        #print(len(chain),chain[len(chain)-1])
    return pd.Series(chain)
        
seeds = seed('5f5f9da7af0feedcb21a3cf96917df0788b895b09499977e1d23e4710d71bb05')
seeds[0]


# In[5]:


def hashes(seed_series):
    client_seed = "0000000000000000000415ebb64b0d51ccee0bb55826e43846e5bea777d91966"
    hmacs = []
    crashes = []
    inIntFromBin = []
    inBin = []
    scale = []
    
    for seed in seed_series:
        #print(f'hash_hmac = hmac.new(str.encode(seed), str.encode(client_seed), hashlib.sha256).hexdigest()')
        #print(f'hash_hmac = hmac.new({str.encode(seed)}, {str.encode(client_seed)}, hashlib.sha256).hexdigest()')
        hash_hmac = hmac.new(str.encode(seed), str.encode(client_seed), hashlib.sha256).hexdigest()
        hmacs.append(hash_hmac)

        point = getPoint(hash_hmac)
        crashes.append(point[0])
        inIntFromBin.append(point[1])
        inBin.append(point[2])
        scale.append(point[3])
        
    return pd.DataFrame({
                         'crashes':crashes,
                         'seeds':seed_series,
                         'hmacs':hmacs,
                         'dec':inIntFromBin,
                         'bin':inBin,
                         'scale':scale
                        })

z = hashes(seeds)
print(z)


# In[6]:


f"{(int('25fb', 16)/int('ffff', 16)) - (int('25fa', 16)/int('ffff', 16)):.18f}"


# In[7]:


((int('25fb', 16)/int('ffff', 16)) - (int('25fa', 16)/int('ffff', 16)))*15


# In[8]:


for x in range(15):
    print(f"{9735+x} --> {f'{hex(9735+x)}'[2:]} --> {(9735+x)/int('ffff', 16)} --> {(9735+x)%15} --> {((9735+x)%15)<<16}")


# In[9]:


int('ffff', 16)


# In[10]:


(14<<16) + int('ffff', 16)


# In[11]:


int(b'1111111110111110', 2)


# In[12]:


s = pd.Series(
    [
    False,
    False,
    False,
    False,
    False,
    False,
    False,
    False,
    True,
    False,
    False,
    False,
    False,
    False,
    False,
    False,
    ]
)


int(''.join(str(e) for e in [int(not(e)) for e in list(map(int, s.to_numpy()))]), 2)


# In[13]:


[int(not(e)) for e in list(map(int, s.to_numpy()))]


# In[14]:


''.join(str(e) for e in [int(not(e)) for e in list(map(int, s.to_numpy()))])


# In[15]:


aleatory_captured_hashes = [
    '9e3548f370097ea623ddc9b22b338fb26878c5fba7244eb464f55af2a9656dc5', #13.56 KV16dnWXlB jogada em 13/10/2021 4:03 pm
    'abe6ad5995d75c77aab270d3a1efca1aad4ada36e09a6a632fc0ed547ab9a6a7', # 1.00 8Lkn32Mbl3 jogada em 13/10/2021 4:19 pm
    'c43ed26d1c1f60f31ab5888b5c290c2dbda6c293c160bfeadee6f4569a276c4d', # 4.25            jogada em 10/10/2021 5:39 pm
]

rexi = hmac.new(
        str.encode(aleatory_captured_hashes[0]), 
        str.encode("0000000000000000000415ebb64b0d51ccee0bb55826e43846e5bea777d91966"), 
        hashlib.sha256
        ).hexdigest()
    
print(rexi)


# In[16]:


class Divisible:
    def __init__(self, hashHmac=None, mod=15):
        self.hash = hashHmac
        self.mod = mod
        self.df = pd.DataFrame(
                data={},
                columns=[
                    "x",
                    "val_i",
                    "bitwised",
                    "hex_hash",
                    "int_hash",
                    "bit+int",
                    "val_f",
                    "!= 0"
                ])
        self.check_divisible()

    def check_divisible(self):
        vali, valf, o = (0, 0, len(self.hash)%4)
        o -= 4 if o > 0 else o

        for x in range(0, len(self.hash), 4):
            valf = ((vali << 16) + int(self.hash[x:x+4], 16)) % self.mod
            self.df = self.df.append(
                    pd.Series(
                        data=[
                            x,
                            vali,
                            vali << 16,
                            self.hash[x:x+4],
                            int(self.hash[x:x+4], 16),
                            (vali << 16) + int(self.hash[x:x+4], 16),
                            valf,
                            int(valf != 0)
                        ],
                        index=self.df.columns
                    ),
                    ignore_index=True)
            vali = valf
        
        self.divisible = vali == 0
        self.bined = ''.join(str(e) for e in self.df['!= 0'])
        self.hexed = ''.join([hex(e)[2:] for e in self.df['val_f']])


# In[17]:


u = Divisible(rexi)

print(u.df)
print(u.divisible)
print(u.bined)
print(u.hexed)


# In[18]:


u.df.iat[-2, 3]


# In[19]:


print(''.join(str(e) for e in u.df['!= 0']))

myHex = ''.join([hex(e)[2:] for e in u.df['val_f']])
myHexInt = int(myHex, 16)
myTotal = int("eeeeeeeeeeeeeeee", 16)
print(myHex)
print(f'{myHexInt:,}')
print(f'{myTotal:,}')
print((myHexInt/myTotal)*100)


# In[114]:


class Crash():
    def __init__(self, hashHmac):
        self.hash = hashHmac
        self.d = Divisible(self.hash, 15)
        self.h = int(self.hash[0:int(52/4)], 16)
        self.e = int(pow(2, 52))
        self.point = float(format((floor((100 * self.e - self.h) / (self.e - self.h)) / 100), ".2f"))
        self.scale = (self.h/self.e) * 100
        self.decbin = (int(self.d.bined, 2) / int(''.join('1' for item in range(16)), 2)) * 100
        self.dechex = (int(self.d.hexed, 16)/ int(''.join('e' for item in range(16)), 16)) * 100
        self.zero = 0
        self.good = 0
        if self.d.divisible:
            self.zero = self.point
            self.point = 0
        if self.point >= 2:
            self.good = 1


# In[21]:


class Crexi(Divisible):
    pass


# In[22]:


r = Crexi(rexi)
r.hash


# In[115]:


w = Crash(rexi)

wkeys = ['bina', 'd', 'deci', 'e', 'h', 'hash', 'point', 'scale', 'zero', 'good']

print(w.d.bined)
print(w.d.divisible)
print(w.decbin)
print(w.dechex)
print(w.e)
print(w.h)
print(w.hash)
print(w.point)
print(w.zero)
print(w.scale)
txt = 'good' if w.good else 'bad'
print(txt)
print(w.d.df)


# In[24]:


class Blaze:
    def __init__(self, list=[]):
        
        opt = webdriver.ChromeOptions()
        opt.add_experimental_option('excludeSwitches', ['enable-logging']) # disable "Devtools listening on..."
        #opt.headless = True
        
        self.driver = webdriver.Chrome(options=opt)
        self.wait = WebDriverWait(self.driver, 10)
        self.driver.get("https://blaze.com/pt/games/crash")
        self.driver.execute_script("document.body.style.zoom='0.7'")
        print("Ok, ready to go now!")

        self.list = list
        self.nlist = len(self.list)
        self.listCrashes()

        self.openModal()
        self.hash = self.setHash()
        self.factor = self.setFactor()
        self.closeModal()

    def listCrashes(self):
        self.wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "div.entries")))
        lista = self.driver.find_elements_by_css_selector("div.entries span")
        lista.reverse()
        for x in range(len(lista)):
            lista[x] = float(lista[x].get_attribute("innerHTML")[:-1])
            #print(lista[x])
        self.list = lista
        self.nlist = len(self.list)

    def openModal(self):
        print("wait until <div.entries> visibility")
        self.wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "div.entries")))
        print("<div.entries> located, execute js click script")
        self.driver.execute_script("document.querySelector('div.entries span').click()") #open modal of last crash
        print("wait until <div.server-roll div> visibility")
        self.wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "div.server-roll div")))
        print("modal open completed, hash located:")

    def setHash(self):
        return self.driver.find_element_by_css_selector("div.server-roll div").text #get hash on modal of last crash
    
    def setFactor(self):
        return float(self.driver.find_element_by_css_selector("div.entries span").get_attribute("innerHTML")[:-1]) #get str of crash, like 1.23X
    
    def closeModal(self):
        self.driver.execute_script("document.querySelector('div.close').click()")

    def listen(self, ntimes=5):
        ntimes += self.nlist
        self.stamps = pd.DataFrame(data={}, columns=['crash', 'reg', 'duration'])
        while self.nlist < ntimes:
            newList = self.driver.find_elements_by_css_selector("div.entries span")
            newList.reverse()
            current = len(newList)
            
            if current > self.nlist:
                for y in range(current-self.nlist):
                    self.list.append(float(newList[y-(current-self.nlist)].get_attribute("innerHTML")[:-1]))
                    self.tstamps.append(datetime.now())
                    print(self.tstamps[-1:])
                    print(self.list[y-(current-self.nlist)])
                self.nlist = current

    def listen2(self):
        print('Press Ctrl-C to quit.')
        try:
            while True:
                newList = self.driver.find_elements_by_css_selector("div.entries span")
                print(newList[0].get_attribute("innerHTML"),' ', end='\r')
                
                
        except KeyboardInterrupt:
            print('\n')


# In[117]:


class LearnBlaze:
    def __init__(self, hashFromCrashPoint):
        self.client_seed = "0000000000000000000415ebb64b0d51ccee0bb55826e43846e5bea777d91966"
        self.maxHash = int(''.join('f' for item in range(64)), 16)
        #self.maxHmac = int(''.join('e' for item in range(64)), 16)
        self.seed = hashFromCrashPoint
        self.data = {
            "good":[],
            "point":[],
            "zeros":[],
            "seeds":[self.seed],
            "hmacs":[],
            "divbin":[],
            "divhex":[],
        }
        
        self.genSeeds(n=10)
        self.genHmacs()
        self.genPoints()
        self.numerize()
        
    def genSeeds(self, n=10000):
        # first, n seeds are needed
        for x in range(n):
            (
                self.data["seeds"]
                .append(hashlib
                        .sha256(str.encode(self.data["seeds"][x]))
                        .hexdigest())
            )
        self.data["seeds"].reverse()
        
    def genHmacs(self):
        #hmacs for each seed
        for seed in self.data["seeds"]:
            (
                self.data["hmacs"]
                .append(
                    hmac.new(
                        str.encode(seed),
                        str.encode(self.client_seed),
                        hashlib.sha256
                    ).hexdigest()
                )
            )
    
    def genPoints(self):
        for eachmac in self.data["hmacs"]:
            crash = Crash(eachmac)
            self.data["point"].append(crash.point)
            self.data["good"].append(crash.good)
            self.data["zeros"].append(crash.zero)
            self.data["divbin"].append(crash.decbin)
            self.data["divhex"].append(crash.dechex)
                
    def numerize(self):
        seeds = self.data["seeds"]
        hmacs = self.data["hmacs"]
        for x in range(len(seeds)):
            seeds[x] = (int(seeds[x], 16) / self.maxHash) * 100
            
        for y in range(len(hmacs)):
            hmacs[y] = (int(hmacs[y], 16) / self.maxHash) * 100
            
j = LearnBlaze(aleatory_captured_hashes[0])
hf = pd.DataFrame(j.data)
print(hf)


# In[45]:


gist = [i*2 for i in range(10)]
gist.reverse()
gist


# In[47]:


my = {'hm':gist}
my['hm'].reverse()
print(my['hm'])


# In[64]:


aleSeed = int(aleatory_captured_hashes[2], 16)
maxSeed = int(''.join('f' for item in range(64)), 16)

print(maxSeed)
print(aleSeed)
print((aleSeed/maxSeed)*100)


# In[134]:


aa = 9.5
distancias = [14.9, 14.9+14.1]
gas = 7
retorno = 2.3


for x in distancias:
    print(((x / aa) * gas) * retorno)

