## SCADA - LightTheWay

Script: light_the_way.py

Connecting to the IP address via a browser and observing the network traffic, we can see regularly scheduled GET requests to /api. 

![](https://i.imgur.com/T7fQZee.jpg)


The JSON response from the server contains 6 numbered objects of this form

"1": { "EG": 0, "ER": 1, "EY": 0, "NG": 1, "NR": 0, "NY": 0, "SG": 0, "SR": 1, "SY": 0, "WG": 0, "WR": 1, "WY": 0}

and a dummy flag: 
"flag": "University CTF 2021"

Each of the objects represents one of the 6 junctions pictured on the website and we can confirm that the flashing lights in the HMI correspond to 1s in the JSON in the natural encoding **E**ast/**N**orth/**S**outh/**W**est  **G**reen/**R**ed/**Y**ellow. E.g. the above entry specifies for junction 1 that the lights at the street coming from North are green, while they are red for all other streets at this junction.

The challenge description indicates that we need to set the lights, so that the path displayed in the HMI is cleared, however there seems to be no way to directly interact with the API other than to query its state (POST requests are not an allowed method).

So we need to find another way to interact with the state of the lights. A nmap scan reveals that the standard Modbus port 502 is open on the target machine. The Modbus protocol does not incooperate any authentication, so anyone can communicate with the target machine. 

![](https://i.imgur.com/oSMyGms.jpg)


Modbus servers provide 1bit coils and 16bit registers to a Modbus client device, but there is no standard of how objects are encoded in coils and registers. So first let's try to read the current state and reverse engineer how  the data is structured.

The pyModbusTCP package provides a ModbusClient with functionality to read and write coils and registers. First up, read some registers from the first couple of unit ids:

```python3
for uid in range(0,10):
	c = ModbusClient(host=ip, port=502, unit_id=uid, auto_open=True)
	holding_regs = c.read_holding_registers(0, 20)
```

The returned values are all 0 except for the first few values of unit ids 1-6:

![](https://i.imgur.com/EI6o7jk.jpg)


These numbers are all in ASCII range, let's see if it is a sensible message. Converting to characters:

![](https://i.imgur.com/MjZxxfx.jpg)


The challenge description mentioned *reverting the system to manual*, so we loop over unit ids 1-6 and set `auto_mode` to `False` by overwriting from register 10 onwards:

```python3
manual_mode = list(map(lambda x : ord(x),['f','a','l','s','e']))
c.write_multiple_registers(10, manual_mode)
```

But where do we change the values of the lights? We can take a look at the values of the coils with the `read_coils(bit_addr, bit_nb)` function. What we get back is a massive array of `False` with a few `True` in between. 

![](https://i.imgur.com/kWXs99C.jpg)


Clearly, we need a more readable representation. So instead, we print the indices at which `True` occurs. 

```python3
coils = c.read_coils(1,2000)
for (i,value) in enumerate(coils,1):	
	if value == True:
		print(i)
```

![](https://i.imgur.com/CvDxiMP.jpg)


The fact that for each unit id exactly 4 values are set to `True` is promising since at each junction exactly one of (Red, Yellow, Green) is switched on for each of the 4 streets. However, if we compare the first JSON entry that the API returned for junction 1 with the first entry of the table, we can see that the order of the coils clearly differs. But it turns out that we have enough information to figure out the order of the 12 coils of one junction.

We make a lucky guess that the lights at a junction corresponding to the same street are specified next to each other and hence consider 4 triplets of coils. We need to determine the order of the triplets for North, East, South and West as well as the order of the colours Red, Yellow and Green within the triplet.

Note that we don't know whether the first index that is True is actually the first number in the triplet. The encoding might start up to two places before the first index we recorded. 

Going back to junction 1, the only way to get an offset of 4 zeros between the indices 571 and 576 is having triplets (100)(001). Hence, in this case the sequence does start at index 571:

| 571  | 572  | 573  | 574  | 575  | 576  | 577  | 578  | 579  | 580  | 581  | 582  |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| (1   | 0    | 0)   | (0   | 0    | 1)   | (0   | 0    | 1)   | (0   | 0    | 1)   |

Since there is only a green light for North at junction 1, while other lights are red, we can infer the order within the triplet as (Green, Yellow, Red) and we know that North is the first triplet. Then it is easy to determine the starting index for the remaining junctions (we omit junction 3 and 5 since they are not along the desired path): 

At junction 2 the North light is Yellow (reading off values from full initial JSON response that is not included for brevity), so the first triplet is (010), implying a starting index of 1921-1=1920. 

| 1920 | 1921 | 1922 | 1923 | 1924 | 1925 | 1926 | 1927 | 1928 | 1929 | 1930 | 1931 |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| (0   | 1    | 0)   | (0   | 1    | 0)   | (0   | 0    | 1)   | (0   | 0    | 1)   |

This tells us that the second triplet indicating Yellow corresponds to East.

Junction 4 has also a Yellow North light, so the starting index is 1266.

| 1266 | 1267 | 1268 | 1269 | 1270 | 1271 | 1272 | 1273 | 1274 | 1275 | 1276 | 1277 |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| (0   | 1    | 0)   | (0   | 0    | 1)   | (0   | 0    | 1)   | (0   | 1    | 0)   |

Junction 4 has a Red South light and a yellow west light and hence the order of streets is (North, East, South, West).

Junction 6 has a Red North light and therefore a starting index of 886. The order of streets and colours is consistent across all states, so this is all we need to know where and in which order we can overwrite the light signals.

To clear the path we need to set the following street lights to green: 1 West, 2 North, 4 West, 6 West while setting all other street lights at that junction to 0. So, our overwrites are

| Starting index |      |      |      |      |      |      |      |      |      |      |      |      |
| -------------- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 571            | 0    | 0    | 1    | 0    | 0    | 1    | 0    | 0    | 1    | 1    | 0    | 0    |
| 1920           | 1    | 0    | 0    | 0    | 0    | 1    | 0    | 0    | 1    | 0    | 0    | 1    |
| 1266           | 0    | 0    | 1    | 0    | 0    | 1    | 0    | 0    | 1    | 1    | 0    | 0    |
| 886            | 0    | 0    | 1    | 0    | 0    | 1    | 0    | 0    | 1    | 1    | 0    | 0    |

We send these with the `write_multiple_coils(bits_addr, bits_value)` function. By querying the API manually or revisiting the website we get the flag.

![](https://i.imgur.com/1K02zZX.jpg)

![](https://i.imgur.com/CWIPVuw.jpg)

