# CRIME-poc

CRIME attack PoC : compression oracle attacks

> In a compression oracle attack the use of adaptive data compression on a mixture of chosen plaintext and unknown plaintext can result in content-sensitive changes in the length of the compressed text that can be detected even though the content of the compressed text itself is then encrypted. This can be used in protocol attacks to detect when the injected known plaintext is even partially similar to the unknown content of a secret part of the message, greatly reducing the complexity of a search for a match for the secret text. The CRIME and BREACH attacks are examples of protocol attacks using this phenomenon.

The CRIME attack allow you to retrieve encrypted data send by a client to a server using the length of the encrypted data. It does not allow you to retrieve the private key used to encrypt the message or the request HTTP.

Best explanation of the attack : https://security.stackexchange.com/questions/19911/crime-how-to-beat-the-beast-successor/19914#19914

## Proof Of Concept

### RC4 cipher mode

Naive method but a good way to understand how it works : 

| Request to retrieve  byte q | length
|---|---|
| GET /cookie=  DATA cookie=quokkalight | 80 |
| GET /cookie=a DATA cookie=quokkalight | 81 |
| GET /cookie=b DATA cookie=quokkalight | 81 |
| GET /cookie=. DATA cookie=quokkalight | 81 |
| GET /cookie=q DATA cookie=quokkalight | 80 |

But this method failed some times and cannot be trusted so instead we will use another method.
First we send a request with the char we want to find followed by multiple caracters that cannot be found in the initial request like some specials char `chr(i) + "#:/[|/ç"`. Then we send a second request but we invert the payload like this: `"#:/[|/ç" + chr(i)` and we compare the two length. If len(req1) < (req2) then we found a byte: 

| Request to retrieve  byte q | length
|---|---|
| GET /cookie=a~#:/[|/ç DATA cookie=quokkalight | 81 |
| GET /cookie=~#:/[|/ça DATA cookie=quokkalight | 81 |
| GET /cookie=b~#:/[|/ç DATA cookie=quokkalight | 81 |
| GET /cookie=~#:/[|/çb DATA cookie=quokkalight | 81 |
| GET /cookie=q~#:/[|/ç DATA cookie=quokkalight | 80 |
| GET /cookie=~#:/[|/çq DATA cookie=quokkalight | 81 |

The attacker found a byte !

```
if len(request1) < len(request2):
    print("found byte")
```

Why using recursivity in the method `two_tries` ? some time, more than one byte can be found because the compression match with multiple patterns.

Lets take the secret : `cookie=quokkalight`, if we run the algorithm `two_tries` we will found the following result:

```
result 1: cookie=quokie=quokie=quokie=
result 2: cookie=quokkalight
```

We can see the all the result as a tree that can be respresented like this:

[![img](https://user-images.githubusercontent.com/5891788/39074729-e53f71ca-44f2-11e8-9ce6-2c3ec43248e6.png)]

So to make sure we will take all the path and found all the possibilities the `two_tries` method is recursive.

Full PoC:

[![asciicast](https://asciinema.org/a/igA5aaqc5Mf0RMklxuPu6aPyw.png)](https://asciinema.org/a/igA5aaqc5Mf0RMklxuPu6aPyw)

### CBC cipher mode


## References

https://github.com/cloudflare/cf-nocompress
https://www.ekoparty.org/archive/2012/CRIME_ekoparty2012.pdf
https://security.stackexchange.com/questions/19911/crime-how-to-beat-the-beast-successor/19914#19914