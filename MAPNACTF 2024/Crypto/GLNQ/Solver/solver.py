F, k = GF(2**8), 14

z8 = F.gen()

G = matrix()

H=matrix()

if G.is_invertible():
    m = discrete_log(H, G,algorithm='lambda')
    assert H==G**m, 'not-yet'
    #print(G**m)

    print(f"m= {m}")

else:

    print('no')