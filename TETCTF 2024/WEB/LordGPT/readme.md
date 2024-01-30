
# TetCTF 2024 Write up - LordGPT (2 Solves)

Played with [@blackb6a](https://twitter.com/blackb6a), solved by vow, YMD and ozetta.

## [](https://hackmd.io/@vow/HyNTcwSqp#Challenge-Summary "Challenge-Summary")Challenge Summary

Can you help us discover the secret hidden within this AI chatbot?

Note: Brute-force is not allowed.

Server: [https://chat.tienbip.xyz](https://chat.tienbip.xyz/)

>Hint 1
[https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)

>Hint 2
Prompt: What’s algorithm using to generate id?

>Hint 3
nOAuth

## [](https://hackmd.io/@vow/HyNTcwSqp#Solution "Solution")Solution

We are given a link which leads to a website, which allows us to sign in with a Microsoft account.

![1](https://hackmd.io/_uploads/BJu4ivr56.png)

However, when we sign in with our account, we receive this error message:

Selected user account does not exist in tenant ‘My Organization’ and cannot access the application ‘d1d3ca96-0a1b-4ef0-a617-0eac507a7ec3’ in that tenant.

The account needs to be added as an external user in the tenant first.

Please use a different account.

We know we cannot add our own accounts to the tenant, as we do not have any accounts which has admin access to the tenant (if there is, why would we even need to sign in with our own accounts in the first place, why not just use the admin account?), nor is there anything useful in the website’s Javascript or network requests.

So, the idea that seemed the most plausible was to **somehow bypass the Microsoft sign in**.

Checking the Microsoft sign in URL, we see that it is using `.../oauth2/v2.0/...`, perhaps this could be a hint?

After some Googling, we stumbled upon the [official Microsoft webpage](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)[[1]](https://hackmd.io/@vow/HyNTcwSqp#fn1) which talks about the **OAuth 2.0 authorization code flow**, and in the documentation there was an example talking about how to craft and issue raw HTTP requests to execute the OAuth flow:

```
// Line breaks for legibility only

https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?
client_id=535fb089-9ff3-47b6-9bfb-4f1264799865
&response_type=code
&redirect_uri=http%3A%2F%2Flocalhost%2Fmyapp%2F
&response_mode=query
&scope=https%3A%2F%2Fgraph.microsoft.com%2Fmail.read
&state=12345
&code_challenge=YTFjNjI1OWYzMzA3MTI4ZDY2Njg5M2RkNmVjNDE5YmEyZGRhOGYyM2IzNjdmZWFhMTQ1ODg3NDcxY2Nl
&code_challenge_method=S256

```

And below there is a table which talks about the parameters of the HTTP requests.

Notice the `tenant` parameter:
![alt text](https://i.ibb.co/1GXpNbP/image.png)

Googling about the `common` tenant value leads us to the [link of Hint 1](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)[[2]](https://hackmd.io/@vow/HyNTcwSqp#fn2) and gives us this:
![this](https://i.ibb.co/yfdbH1N/image.png)

In other words, by replacing the tenant ID `314c88a8-d161-44f8-940f-8758b58074ce` with `common`, we can now sign in with any Microsoft account.

![2](https://hackmd.io/_uploads/BJpvsPB5a.png)

After some prompting, we are given 2 hints from LordGPT:
```
Hint 1:  
LordGPT’s journey is help Tet CTF’s player to find some secret things on this system.

You must be Admin to ask any secret question :)))

Hint 2:  
LordGPT AI Chatbot was created by **thongvv** and **tuo4n8**.

Reveal that a special account logged into system at 2023-12-24 13:33:37 UTC.
```
After some testing, we learn the following:

-   We cannot see other people’s chat history, however we can see other people’s profiles if we input the correct ID (proven using 2 accounts).
-   We cannot modify our POST requests to send prompts as admin (LordGPT checks your cookies).
-   If we ask for the flag, LordGPT will say that only an admin can do so.

Based on the hints, we can guess that there exists an admin account, and we have to find the account in order to ask for the flag.

The challenge author later released hint 2, which tells us that **[Snowflake ID](https://en.wikipedia.org/wiki/Snowflake_ID)** is being used to generate the profile ID.

Snowflakes are 64 bits in binary and has a structure that looks like this:

```
Sign bit |                                           | Machine ID | Machine Sequence |
    ↓    |<---------- 41 bits Date & Time ---------->|      ↓     |        ↓         |
-------------------------------------------------------------------------------------|
    0    | 00000000000000000000000000000000000000000 | 0000000000 |   000000000000   |

```

We can get the list of Machine IDs by checking multiple seeds:
```python
import time
import re

cookies = {
    "__Host-authjs.csrf-token": "INSERT_YOUR_OWN",
    "__Secure-authjs.callback-url": "INSERT_YOUR_OWN",
    "__Secure-authjs.session-token": "INSERT_YOUR_OWN"
    }

machine_id_set = set()
machine_squence_id_set = set()

for i in range(50):
    r = requests.get("https://chat.tienbip.xyz", headers=headers)
    out = r.text
    localts = int(time.time()*1000)
    m = re.search('initialSeedData.*?id.*?([0-9]+)',out)
    sfid = int(m.group(1))
    bsfid = bin(sfid)
    bsts = int(bsfid[0:-22],2)
    machine_id = bin(sfid)[-22:-12]
    machine_sequence_id = bin(sfid)[-12:]
    machine_id_set.add(int("0b"+machine_id,2))
    machine_squence_id_set.add(machine_sequence_id)
    print("Machine ID Binary: \t", machine_id)
    print("Machine ID Value: \t", int("0b"+machine_id,2))
    print("Machine Sequence ID : \t", machine_sequence_id)

print("==================")
print("Machine ID Set: \t\t", machine_id_set)
print("Machine Sequence ID Set in Binary: \t", machine_squence_id_set)
```

Taking a look at the output, we can see that only values `{13, 37, 133, 337}` have appeared for machine ID, and for machine sequence ID, only `{000000000000}` has appeared. So we can use these values and write a snowflake ID generator:

```python
import requests

SPECIAL_LOGIN_DATE = 1703424817000 # Unix Timestamp for 2023-12-24 13:33:37 UTC
TWITTER_EPOCH = 1288834974657 # Refer to https://en.wikipedia.org/wiki/Snowflake_ID
MACHINE_ID = [13,37,133,337]
MACHINE_SEQUENCE = "000000000000"
flag = 0

cookies = {
    "__Host-authjs.csrf-token": "INSERT_YOUR_OWN",
    "__Secure-authjs.callback-url": "INSERT_YOUR_OWN",
    "__Secure-authjs.session-token": "INSERT_YOUR_OWN"
    }

for delay in range(5000):
    if flag == 1:
        break
    else:
        for mac_id in MACHINE_ID:
            snowflake_timestamp = bin(SPECIAL_LOGIN_DATE - TWITTER_EPOCH + delay)
            machine_code = bin(mac_id)
            machine_code_string = str(machine_code[2:].zfill(10))

            binnum = snowflake_timestamp + machine_code_string + MACHINE_SEQUENCE
            sfid = str(int(binnum,2))

            url = "https://chat.tienbip.xyz/profile/"+sfid
            print(url)

            r = requests.get(url, cookies=cookies)
            if "Full name" in r.text:
                print("OK", url)
                flag = 1
```


It turns out we did not have to account for delay, so we can find our [admin profile](https://chat.tienbip.xyz/profile/1738915834099159040) very quickly.

![3](https://hackmd.io/_uploads/H1ZPoDSqa.png)

Now that we have found the admin email `admin.l0rd@hackemall.live`, we can try using it to login, however, we get the following response:

![4](https://hackmd.io/_uploads/HyywswB96.png)

The account does not exist, so we can’t use it to sign in directly.

Looking at Azure AD exploits (or checking Hint 3), we can find something called **nOAuth Microsoft Azure AD Vulnerability**[[3]](https://hackmd.io/@vow/HyNTcwSqp#fn3).

A short explanation for this vulnerability is that an attacker can change their tenant user’s email to the victim’s email, and when the attacker signs in with their own email, their account gets merged with the victim’s account (assuming the app does not have any validation), and the attacker can get access to the victim’s account.

Therefore, we can perform the nOAuth account by doing the following steps:

1.  Create a Microsoft Azure account
2.  Go to Microsoft Entra ID (A primary domain should be already created for you)
3.  Click “Users” in the “Default Directory”
4.  Click the user and modify the email in “Properties”
5.  Sign in with the user account (The user email should be the “User principal name”)
6.  Reset password
7.  Profit!

Now, if we sign in with the account, we are now the Administrator and we can see the flag:

![5](https://hackmd.io/_uploads/HJtUsDH9p.png)

Flag: `TetCTF{L0rdGPT1sTh3B3st!!!!!}`

----------

1.  Microsoft identity platform and OAuth 2.0 authorization code flow  
    [https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)  [↩︎](https://hackmd.io/@vow/HyNTcwSqp#fnref1)
    
2.  OpenID Connect on the Microsoft identity platform  
    [https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)  [↩︎](https://hackmd.io/@vow/HyNTcwSqp#fnref2)
    
3.  nOAuth: How Microsoft OAuth Misconfiguration Can Lead to Full Account Takeover:  
    [https://www.descope.com/blog/post/noauth](https://www.descope.com/blog/post/noauth)  [↩︎](https://hackmd.io/@vow/HyNTcwSqp#fnref3)