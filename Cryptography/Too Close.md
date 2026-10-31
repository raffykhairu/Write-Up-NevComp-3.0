# Too Close (Cryptography, 1000 pts): NevComp 3.0

| Field     | Value                        |
| --------- | ---------------------------- |
| Event     | NevComp 3.0, 31 October 2026 |
| Category  | crypto                       |
| Points    | 1000 (dynamic)               |
| Solves    | 3                            |
| Author    | geng                         |
| Solved by | raffy                        |
| Status    | Solved during event          |

## Challenge

> Keep your friends close, but your prime numbers far apart😂

- Files: `chall.py`
- Service: `nc 172.20.12.248:1111` (event infrastructure, now offline)

## Source code analysis

`chall.py`
```python
from Crypto.Util.number import getPrime, isPrime, bytes_to_long

flag = b"NevComp3.0{REDACTED}"

e = 65537

p = getPrime(1024)

q = p + 2
while not isPrime(q):
    q += 2

n = p * q
ct = pow(bytes_to_long(flag), e, n)

print(f"p = {p}")
print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")
```

`out.txt`
```text
n = 12296437781432367311023394758533510454946268500185385992227716630445727601995910584314842968521352928227417314138385153816557910124048235578185281770990602632417693715625716944046546995632402886484052356513955659794168812964244537524215160645997214883109044647118282844107377690817730069148831583875509687171166607636711923301642447273052010761189267417855147935085641005824593928642859430819905675163057334815302750221807023117394278667914383811255229398918761560855533965666048321785435258462071010641764308704434016691691446433040864905681347049751365476346536727422417330805750541068009315787797659054553806050761
e = 65537
ct = 2706575227493480410193643242745348592600280204888962584838945538811218498594014079972573166027658915211182006780745516151414373780297579950963508704524787238237625136485194232117022505966137585958203864567478367358102010606598844210984608742740443391759475830316782384123595264135200068314220159801897121654032518596467748273656293752497783372691976659471604947370992855164196044676114401449243320485755613700859072763184207500484121805330637684859229686167044206697039071530979046264469720599675677518707486744013547639177601396378291289663765133222480555824691574082749730408943373773066561657135258601315929648796
```

## First look

Pada challenge cryptography ini, kita diberikan sebuah source code generator RSA beserta output berupa Modulus (n) dan Ciphertext (c). Kunci publik (e) menggunakan standar 0x10001 (65537).

Sekilas, Modulus n terlihat sangat aman karena berukuran raksasa (2048-bit). Namun, jika kita memperhatikan fungsi generator bilangan primanya, pembuat soal tidak meng-generate nilai qsecara acak murni. Ia justru mengikat nilai $q$ agar jaraknya sangat dekat dengan $p$ (secara spesifik: $q=p+2$).

Kondisi di mana sepasang bilangan prima memiliki selisih tepat 2 disebut sebagai Twin Primes. Sifat kedekatan ekstrem ini menghancurkan keamanan RSA sepenuhnya, memungkinkan kita mengekstrak nilai pdan $q$ dalam hitungan milidetik menggunakan manipulasi aljabar dasar.

## Dead ends

Disini Program melakukan infinite loop yang akan terus berjalan selama $q$ BUKAN bilangan prima (fungsi isPrime(q) menghasilkan nilai False). Ia membuat variabel $q$ dengan cara mengambil nilai $p$ dan menambahkannya dengan 2 $(q = p + 2)$.

Lalu program mengecek apakah hasil penambahan tersebut ($q$) bukan bilangan prima. Jika iya, looping akan terus berlanjut hingga $q$ mendapatkan bilangan prima, dan nilai Modulus $N$ dihitung $(N=p×q)$.

Nah vuln fatalnya ada pada baris `q = p + 2`.

Dalam kriptografi RSA yang aman, pdan $q$ haruslah dua bilangan acak yang jaraknya sangat jauh. Namun di sini, program memaksa jarak antara pdan $q$ hanya berselisih 2 (kondisi ini disebut Twin Primes).

Akibatnya, nilai Modulus $N$ yang dihasilkan bukanlah angka acak yang sulit difaktorkan, melainkan sebuah angka yang posisinya sangat dekat dengan nilai kuadrat sempurna.

## Solution

Karena jarak $p$ dan $q$ sangat sempit, kita bisa mem bypass proses faktorisasi RSA dengan menggunakan manipulasi aljabar dan pencarian akar kuadrat dasar.

Kita tahu bahwa:

```math
q=p+2
```

```math
N=p×q
```

Jika kita substitusikan nilai $q$ ke dalam rumus $N$:

```math
N=p(p+2)
```

Lalu di kali menjadi:

```math
N=p^2+2p
```

Bentuk $p^2+2p$ ini sangat dekat dengan rumus kuadrat sempurna $(p+1)^2=p^2+2p+1$. Jadi, jika kita menambahkan angka $1$ ke nilai Modulus $N$, persamaannya menjadi sangat rapi:

```math
N+1=p^2+2p+1
```

```math
N+1=(p+1)^2
```

Untuk mengekstrak nilai $p$, kita tinggal menarik akar kuadrat dari kedua sisi, lalu memindahkan angka $1$:

```math
√(N+1)=p+1
```

```math
p=√(N+1)-1
```

Berikut contoh sederhana nya:
Bayangkan server memilih prima $p=11$. Karena aturan program, maka $q=11+2=13$.

Modulus yang diberikan ke kita adalah $N=11×13=143$.

Kita selesaikan sebagai attacker:

- Tambahkan $N$ dengan $1$: $143+1=144$.
- Cari akar kuadratnya: $√144=12$. (Ini adalah titik tengah persis di antara $p$ dan $q$).
- Kurangi hasilnya dengan $1$ untuk mendapatkan $p$: $12-1=11$.
- Tambahkan nilai pdengan $2$ untuk mendapatkan $q$: $11+2=13$.

Boom! kita dapet Faktor $p$ dan $q$ seketika.

`solve.py`
```python
n = 12296437781432367311023394758533510454946268500185385992227716630445727601995910584314842968521352928227417314138385153816557910124048235578185281770990602632417693715625716944046546995632402886484052356513955659794168812964244537524215160645997214883109044647118282844107377690817730069148831583875509687171166607636711923301642447273052010761189267417855147935085641005824593928642859430819905675163057334815302750221807023117394278667914383811255229398918761560855533965666048321785435258462071010641764308704434016691691446433040864905681347049751365476346536727422417330805750541068009315787797659054553806050761
e = 65537
ct = 2706575227493480410193643242745348592600280204888962584838945538811218498594014079972573166027658915211182006780745516151414373780297579950963508704524787238237625136485194232117022505966137585958203864567478367358102010606598844210984608742740443391759475830316782384123595264135200068314220159801897121654032518596467748273656293752497783372691976659471604947370992855164196044676114401449243320485755613700859072763184207500484121805330637684859229686167044206697039071530979046264469720599675677518707486744013547639177601396378291289663765133222480555824691574082749730408943373773066561657135258601315929648796

def ISQRT(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

start_p = ISQRT(n)

if start_p % 2 == 0:
    start_p -= 1

p = None
q = None

for pembagi in range(start_p, 1, -2):
    if n % pembagi == 0:
        p = pembagi
        q = n // pembagi
        break

if p is None:
    print("[-] Gagal menemukan faktor p dan q. Periksa kembali nilai n.")
    exit()

phi = (p - 1) * (q - 1)

try:
    d = pow(e, -1, phi)
except ValueError:
    print("[-] Gagal menghitung d. e dan phi tidak relatif prima.")
    exit()

m = pow(ct, d, n)

try:
    flag = bytes.fromhex(hex(m)[2:]).decode("utf-8", errors="ignore")
    print(f"\n{flag}")
except Exception as e:
    print(
        f"\n[!] Gagal convert ke string, berikut nilai mentah integer m: {m}"
    )
```

```bash
└─$ python3 solve.py 
NevComp3.0{a_little_too_close_for_comfort}
```

## Flag

`NevComp3.0{a_little_too_close_for_comfort}`

---

[Back to home](./../README.md)