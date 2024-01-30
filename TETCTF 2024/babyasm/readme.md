## 

Reverse[](#reverse)

### 

BabyASM (92 solves)[](#babyasm-92-solves)

#### 

Description:[](#description)

-   Author: zx
    

-   Can you unlock it?
    

-   Server: `http://103.3.61.46/TetCTF2024-babyasm/babyasm.html`
    

#### 

Solution:[](#solution)

The babyasm.html file checks if the input is a total of 27 characters and fits the flag format TetCTF{...}, then passes the last 20 characters Including '}' into the wasm function.

When looking at the console log, it can be seen that there is an error when trying to run the file in firefox. Same when trying to use command line tools to decompile it. The solution is to use a chrome-based browser.

![](https://158212888-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2Fpfs5GbEFUvNmvw1Ekwmu%2Fuploads%2FVSOB0r20ize9WKsVaH4i%2Fimage.png?alt=media&token=92f45030-b02b-4303-b9d8-4b5ba7d00eb2)

Wasm debugger in Chrome

The picture above shows how debugging web assembly looks like. The main file and wasm can be seen by clicking babyasm.html and 8fa74aba. A breakpoint can be added by clicking the address to the left of the code, and when the breakpoint is hit, it can either be passed by clicking the blue play button in the top left or clicking the step button to run the following lines. The Scope section to the left allows the user to see all declared variables and the stack, which is useful to follow what's going on in the code.

With the above knowledge, the goal is to simply follow along and reverse engineer what's happening to the input. I started with aaaa... as an input and then abcd... as an input to come up with the following:
```
g = [96, 101, 20, 177, 155, 116, 108, 69, 84, 109, 103, 110, 111, 95, 116, 103, 97, 72, 20, 59]

t = [38793, 584, 738, 38594, 63809, 647, 833, 63602, 47526, 494, 663, 47333, 67041, 641, 791, 66734, 35553, 561, 673, 35306]

# Plugging in abcd... (97-100 + 83 = 180-183)

2: ((181 + (180 + 96)) ^ 32) + 83 = 572

3: ((182 + (572 - 101)) ^ 36) + 83 = 764

4: ((183 + (764 * 20)) ^ 19) + 83 = 15559

1: ((180 + (15559 ^ 177)) ^ 55) + 83 = 15728

-----

6: ((185 + (180 + 155)) ^ 32) + 83 = 630

...

# Resulting equations

((b+(a+g[0])^32)+83 = t[1]

((c+(t[1]-g[1])^36)+83 = t[2]

((d+(t[2]*g[2])^19)+83 = t[3]

((a+(t[3]^g[3])^55)+83 = t[0]

((f+(e+g[4])^32)+83 = t[5]

((g+(t[5]-g[5])^36)+83 = t[6]

((h+(t[6]*g[6])^19)+83 = t[7]

((e+(t[7]^g[7])^55)+83 = t[4]

...
```
There is a global set of constants (g), a target (t), and 20 character inputs. 83 is added to every input and the results are calculated in the order 2, 3, 4, 1. We get a system of equations, four unknowns and four equations and just need to solve five sets of four equations to get the flag.

I briefly tried a math solver approach before running into issues with the way xor is handled, before I gave up and just went with a brute force approach which is fine since the search space is very limited (instant).
```Python
#g = [96, 101, 20, 177, 155, 116, 108, 69, 84, 109, 103, 110, 111, 95, 116, 103, 97, 72, 20, 59]

g =  [115,  82,  52,  149,  136,  67,  76,  97,  71,  90,  71,  74,  124,  104,  84,  67,  114,  127,  52,  31]

t =  [38793,  584,  738,  38594,  63809,  647,  833,  63602,  47526,  494,  663,  47333,  67041,  641,  791,  66734,  35553,  561,  673,  35306]

def  brute_force_solve(g, t, o):

	for a in  range(32+83,  127+83):

		for b in  range(32+83,  127+83):

			eq1 =  ((b +  (a + g[0+4*o]))  ^  32)  +  83

			if eq1 == t[1+4*o]:

				for c in  range(32+83,  127+83):

					eq2 =  ((c +  (eq1 - g[1+4*o]))  ^  36)  +  83

						if eq2 == t[2+4*o]:

							for d in  range(32+83,  127+83):

								eq3 =  ((d +  (eq2 * g[2+4*o]))  ^  19)  +  83

								eq4 =  ((a +  (eq3 ^ g[3+4*o]))  ^  55)  +  83

								if eq3 == t[3+4*o]  and eq4 == t[0+4*o]:

									return a, b, c, d

	return  None,  None,  None,  None

for o in  range(0,5):

	a, b, c, d = brute_force_solve(g, t, o)

	print(chr(a-83),  chr(b-83),  chr(c-83),  chr(d-83), sep="", end="")
```
At first I used the global array from the decompiled wasm, but couldn't find a solution. I didn't go through to see what the mechanism is, but it seems the global array alternates between two different sets which is why the first line is commented. I initially thought the global array was being "corrupted" mistakenly, and would just run a dummy submission after every test to "fix" it, so I did get stuck before realizing. Running the above code gives us the flag: `TetCTF{WebAss3mblyMystique}`