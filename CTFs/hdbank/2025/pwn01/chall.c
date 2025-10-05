int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rax
  _QWORD *v4; // rbp
  _BYTE *v5; // rax
  _BYTE *v6; // rbx
  int v7; // eax
  int v8; // r12d
  __int64 i; // rcx
  __int64 v10; // rbp
  char *v11; // rax
  int v12; // eax
  int v13; // ebx
  int v14; // ebp
  int optval; // [rsp+Ch] [rbp-7Ch] BYREF
  sockaddr addr; // [rsp+10h] [rbp-78h] BYREF
  _BYTE buf[72]; // [rsp+20h] [rbp-68h] BYREF
  unsigned __int64 v18; // [rsp+68h] [rbp-20h]

  v18 = __readfsqword(0x28u);
  signal(13, (__sighandler_t)((char *)&dword_0 + 1));
  ensure_upload_dir();
  v3 = calloc(2u, 8u);
  runtime_pw = (__int64)v3;
  if ( !v3 )
    goto LABEL_17;
  v4 = v3;
  v5 = malloc(0x15u);
  *v4 = v5;
  v6 = v5;
  if ( !v5 )
    goto LABEL_17;
  v7 = open("/dev/urandom", 0);
  v8 = v7;
  if ( v7 >= 0 )
  {
    if ( read(v7, buf, 0x14u) == 20 )
    {
      close(v8);
      for ( i = 0; i != 20; ++i )
        v6[i] = aAbcdefghijklmn[(unsigned __int8)buf[i] % 0x3EuLL];
      v6[20] = 0;
      v10 = runtime_pw;
      v11 = strdup("user");
      *(_QWORD *)(v10 + 8) = v11;
      if ( v11 )
      {
        puts("== credentials ==");
        __printf_chk(2, "  %s : %s\n", "admin", *(const char **)runtime_pw);
        __printf_chk(2, "  %s : %s\n", "user", *(const char **)(runtime_pw + 8));
        puts("========================================");
        fflush(stdout);
        v12 = socket(2, 1, 0);
        v13 = v12;
        if ( v12 >= 0 )
        {
          optval = 1;
          setsockopt(v12, 1, 2, &optval, 4u);
          *(_QWORD *)&addr.sa_family = 2417950722LL;
          if ( bind(v13, &addr, 0x10u) >= 0 )
          {
            if ( listen(v13, 10) >= 0 )
            {
              __printf_chk(2, "Listening on http://127.0.0.1:%d/\n", 8080);
              while ( 1 )
              {
                v14 = accept(v13, 0, 0);
                if ( !fork() )
                  break;
                close(v14);
              }
              close(v13);
              handle_client(v14);
              close(v14);
              exit(0);
            }
            perror("listen");
            exit(1);
          }
          perror("bind");
          exit(1);
        }
        main_cold();
      }
LABEL_17:
      fwrite("malloc fail\n", 1u, 0xCu, _bss_start);
      exit(1);
    }
    close(v8);
  }
  fwrite("random fail\n", 1u, 0xCu, _bss_start);
  exit(1);
}

_BYTE *__fastcall b64_encode(__int64 a1, unsigned __int64 a2)
{
  _BYTE *v4; // rax
  _BYTE *v5; // rdi
  _BYTE *v6; // rsi
  unsigned __int64 v7; // rcx
  unsigned __int64 v8; // rax
  unsigned __int8 v9; // dl
  __int64 v10; // rax
  unsigned __int8 v11; // r8
  __int16 v12; // cx
  char v14; // al
  _OWORD v15[4]; // [rsp+0h] [rbp-68h]
  char v16; // [rsp+40h] [rbp-28h]
  unsigned __int64 v17; // [rsp+48h] [rbp-20h]

  v17 = __readfsqword(0x28u);
  v16 = 0;
  v15[0] = _mm_load_si128((const __m128i *)&xmmword_47F0);
  v15[1] = _mm_load_si128((const __m128i *)&xmmword_4800);
  v15[2] = _mm_load_si128((const __m128i *)&xmmword_4810);
  v15[3] = _mm_load_si128((const __m128i *)&xmmword_4820);
  v4 = malloc(4 * ((a2 + 2) / 3) + 1);
  v5 = v4;
  if ( v4 )
  {
    v6 = v4;
    v7 = 0;
    if ( a2 > 2 )
    {
      do
      {
        v6 += 4;
        *((_DWORD *)v6 - 1) = *((unsigned __int8 *)v15 + ((*(_BYTE *)(a1 + v7) >> 2) & 0x3F))
                            | ((*((unsigned __int8 *)v15
                                + ((*(_BYTE *)(a1 + v7 + 1) >> 4) | (16 * *(_BYTE *)(a1 + v7)) & 0x30u))
                              | ((*((unsigned __int8 *)v15
                                  + ((*(_BYTE *)(a1 + v7 + 2) >> 6) | (4 * *(_BYTE *)(a1 + v7 + 1)) & 0x3Cu))
                                | (*((unsigned __int8 *)v15 + (*(_BYTE *)(a1 + v7 + 2) & 0x3F)) << 8)) << 8)) << 8);
        v8 = v7;
        v7 += 3LL;
      }
      while ( v8 + 5 < a2 );
    }
    if ( v7 < a2 )
    {
      v9 = *(_BYTE *)(a1 + v7);
      v10 = (16 * v9) & 0x30;
      *v6 = *((_BYTE *)v15 + (v9 >> 2));
      if ( a2 == v7 + 1 )
      {
        v14 = *((_BYTE *)v15 + v10);
        v6[2] = 61;
        v6[1] = v14;
      }
      else
      {
        v11 = *(_BYTE *)(a1 + v7 + 1);
        LOBYTE(v12) = *((_BYTE *)v15 + (int)((v11 >> 4) | v10));
        HIBYTE(v12) = *((_BYTE *)v15 + ((4 * v11) & 0x3C));
        *(_WORD *)(v6 + 1) = v12;
      }
      v6 += 3;
    }
    *v6 = 0;
  }
  return v5;
}

_BYTE *__fastcall sha1_hex(const char *a1)
{
  size_t v1; // rax
  _BYTE *v2; // rax
  _BYTE *v3; // r14
  char *v4; // rbp
  __int64 i; // rbx
  int v6; // r8d
  char *v7; // rdi
  __int64 v8; // rax
  _BYTE v10[24]; // [rsp+0h] [rbp-48h] BYREF
  unsigned __int64 v11; // [rsp+18h] [rbp-30h]

  v11 = __readfsqword(0x28u);
  v1 = strlen(a1);
  SHA1(a1, v1, v10);
  v2 = malloc(0x29u);
  v3 = v2;
  if ( v2 )
  {
    v4 = v2;
    for ( i = 0; i != 20; ++i )
    {
      v6 = (unsigned __int8)v10[i];
      v7 = v4;
      v8 = -i;
      v4 += 2;
      __sprintf_chk(v7, 2, 2 * v8 + 41, "%02x", v6);
    }
    v3[40] = 0;
  }
  return v3;
}

_BYTE *__fastcall make_token(char *s)
{
  char *v1; // rax
  char *v2; // rbp
  size_t v3; // rbx
  size_t v4; // r13
  char *v5; // rax
  char *v6; // rbx
  size_t v7; // rax
  _BYTE *v8; // r12

  v1 = sha1_hex(s);
  if ( !v1 )
    return 0;
  v2 = v1;
  v3 = strlen(s);
  v4 = v3 + strlen(v2) + 2;
  v5 = (char *)malloc(v4);
  v6 = v5;
  if ( !v5 )
  {
    free(v2);
    return 0;
  }
  __snprintf_chk(v5, v4, 2, v4, "%s|%s", s, v2);
  v7 = strlen(v6);
  v8 = b64_encode((__int64)v6, v7);
  free(v2);
  free(v6);
  return v8;
}

char *__fastcall parse_token(const char *a1)
{
  const char *v1; // r12
  size_t v2; // rbp
  void *v3; // rbx
  int v4; // esi
  int v5; // edx
  int v6; // r9d
  int v7; // eax
  int v8; // eax
  int v9; // ecx
  __int64 v10; // rax
  char *v11; // rax
  signed __int64 v12; // r12
  const char *v13; // rbp
  const char *v14; // rax
  char *v15; // r12
  int v16; // ebp
  char *v17; // rbp
  unsigned __int8 v19; // cl
  char v20[136]; // [rsp+0h] [rbp-B8h] BYREF
  unsigned __int64 v21; // [rsp+88h] [rbp-30h]

  v21 = __readfsqword(0x28u);
  if ( !a1 )
    return 0;
  v1 = a1;
  v2 = strlen(a1);
  v3 = malloc(((3 * v2) >> 2) + 4);
  if ( !v3 )
    return 0;
  if ( !v2 )
  {
LABEL_23:
    free(v3);
    return 0;
  }
  v4 = -8;
  v5 = 0;
  v6 = 0;
  while ( 1 )
  {
    v7 = *a1;
    if ( *a1 > 90 )
    {
      v19 = v7 - 97;
      v8 = v7 - 71;
      if ( v19 <= 0x19u )
      {
LABEL_9:
        v5 = v8 + (v5 << 6);
        v9 = v4 + 6;
        if ( v4 + 6 < 0 )
        {
LABEL_20:
          v4 = v9;
        }
        else
        {
LABEL_10:
          v10 = v6;
          v4 -= 2;
          ++v6;
          *((_BYTE *)v3 + v10) = v5 >> v9;
        }
      }
      goto LABEL_11;
    }
    if ( (char)v7 > 42 )
      break;
LABEL_11:
    if ( ++a1 == &v1[v2] )
      goto LABEL_12;
  }
  switch ( (char)v7 )
  {
    case '+':
      v8 = 62;
      goto LABEL_9;
    case '/':
      v8 = 63;
      goto LABEL_9;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      v5 = v7 + 4 + (v5 << 6);
      v9 = v4 + 6;
      if ( v4 + 6 < 0 )
        goto LABEL_20;
      goto LABEL_10;
    case '=':
      break;
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'G':
    case 'H':
    case 'I':
    case 'J':
    case 'K':
    case 'L':
    case 'M':
    case 'N':
    case 'O':
    case 'P':
    case 'Q':
    case 'R':
    case 'S':
    case 'T':
    case 'U':
    case 'V':
    case 'W':
    case 'X':
    case 'Y':
    case 'Z':
      v8 = v7 - 65;
      goto LABEL_9;
    default:
      goto LABEL_11;
  }
LABEL_12:
  *((_BYTE *)v3 + v6) = 0;
  if ( !v6 )
    goto LABEL_23;
  v11 = (char *)memchr(v3, 124, v6);
  if ( !v11 )
    goto LABEL_23;
  v12 = v11 - (_BYTE *)v3;
  if ( (unsigned __int64)(v11 - (_BYTE *)v3) > 0x7F )
    goto LABEL_23;
  v13 = v11 + 1;
  memcpy(v20, v3, v11 - (_BYTE *)v3);
  v20[v12] = 0;
  v14 = sha1_hex(v20);
  v15 = (char *)v14;
  if ( !v14 )
    goto LABEL_23;
  v16 = strcmp(v14, v13);
  free(v15);
  if ( v16 )
    goto LABEL_23;
  v17 = strdup(v20);
  free(v3);
  return v17;
}

unsigned __int64 __fastcall urldecode(_BYTE *a1, _BYTE *a2)
{
  char v3; // al
  _BYTE *v4; // rbx
  __int64 v5; // rbp
  __int64 v6; // r12
  __int16 v7; // r14
  const unsigned __int16 *v8; // rax
  __int16 v10; // [rsp+4h] [rbp-34h] BYREF
  char v11; // [rsp+6h] [rbp-32h]
  unsigned __int64 v12; // [rsp+8h] [rbp-30h]

  v12 = __readfsqword(0x28u);
  v3 = *a2;
  if ( *a2 )
  {
    v4 = a2;
    do
    {
      while ( 1 )
      {
        ++a1;
        if ( v3 == 37 )
          break;
        if ( v3 != 43 )
          goto LABEL_13;
        *(a1 - 1) = 32;
        ++v4;
LABEL_5:
        v3 = *v4;
        if ( !*v4 )
          goto LABEL_12;
      }
      v5 = (char)v4[1];
      if ( !(_BYTE)v5 || (v6 = (char)v4[2], v7 = *(_WORD *)(v4 + 1), !(_BYTE)v6) )
      {
LABEL_13:
        *(a1 - 1) = v3;
        ++v4;
        goto LABEL_5;
      }
      v8 = *__ctype_b_loc();
      if ( (v8[v5] & 0x1000) != 0 && (v8[v6] & 0x1000) != 0 )
      {
        v4 += 3;
        v10 = v7;
        v11 = 0;
        *(a1 - 1) = __isoc23_strtol(&v10, 0, 16);
        goto LABEL_5;
      }
      ++v4;
      *(a1 - 1) = 37;
      v3 = *v4;
    }
    while ( *v4 );
  }
LABEL_12:
  *a1 = 0;
  return v12 - __readfsqword(0x28u);
}

_BYTE *__fastcall form_get(const char *s1, const char *s2)
{
  const char *v2; // r13
  size_t v3; // rbp
  char *v4; // rax
  char *v5; // rax
  char *v6; // rbx
  const char *v7; // rbx
  char *v8; // rax
  size_t v9; // rbp
  _BYTE *v10; // rax
  _BYTE *v11; // r12
  _BYTE *v13; // [rsp+0h] [rbp-30h]

  if ( !s1 )
    return 0;
  if ( s2 )
  {
    v2 = s1;
    v3 = strlen(s2);
    if ( *s1 )
    {
      while ( 1 )
      {
        v5 = strchr(v2, 61);
        v6 = v5;
        if ( !v5 )
          break;
        if ( v3 == v5 - v2 && !memcmp(v2, s2, v3) )
        {
          v7 = v6 + 1;
          v8 = strchr(v7, 38);
          if ( v8 )
            v9 = v8 - v7;
          else
            v9 = strlen(v7);
          v10 = malloc(v9 + 1);
          v11 = v10;
          if ( v10 )
          {
            __memcpy_chk(v10, v7, v9, v9 + 1);
            v11[v9] = 0;
            v13 = malloc(v9 + 1);
            urldecode(v13, v11);
            free(v11);
            return v13;
          }
          return 0;
        }
        v4 = strchr(v2, 38);
        if ( v4 )
        {
          v2 = v4 + 1;
          if ( v4[1] )
            continue;
        }
        return 0;
      }
    }
  }
  return 0;
}

unsigned __int64 sendf(int fd, __int64 a2, ...)
{
  int v2; // eax
  gcc_va_list va; // [rsp+8h] [rbp-20F0h] BYREF
  _BYTE buf[200]; // [rsp+20h] [rbp-20D8h] BYREF
  unsigned __int64 v6; // [rsp+2028h] [rbp-D0h]

  va_start(va, a2);
  v6 = __readfsqword(0x28u);
  v2 = __vsnprintf_chk(buf, 0x2000, 2, 0x2000, a2, va);
  if ( v2 > 0 )
    send(fd, buf, v2, 0);
  return v6 - __readfsqword(0x28u);
}

unsigned __int64 ensure_upload_dir()
{
  struct stat v1; // [rsp+0h] [rbp-A8h] BYREF
  unsigned __int64 v2; // [rsp+98h] [rbp-10h]

  v2 = __readfsqword(0x28u);
  if ( stat("uploads", &v1) == -1 )
    mkdir("uploads", 0x1EDu);
  return v2 - __readfsqword(0x28u);
}

__int64 __fastcall gen_random_password(__int64 a1, __int64 a2)
{
  int v3; // eax
  int v4; // edi
  __int64 i; // rcx
  _BYTE v7[72]; // [rsp+0h] [rbp-78h] BYREF
  unsigned __int64 v8; // [rsp+48h] [rbp-30h]

  v8 = __readfsqword(0x28u);
  v3 = open("/dev/urandom", 0);
  if ( v3 < 0 )
    return 0xFFFFFFFFLL;
  v4 = v3;
  if ( a2 != __read_chk((unsigned int)v3, v7, a2, 64) )
  {
    close(v4);
    return 0xFFFFFFFFLL;
  }
  close(v4);
  if ( a2 )
  {
    for ( i = 0; i != a2; ++i )
      *(_BYTE *)(a1 + i) = aAbcdefghijklmn[(unsigned __int8)v7[i] % 0x3EuLL];
  }
  *(_BYTE *)(a1 + a2) = 0;
  return 0;
}

const char *__fastcall get_runtime_password(char *s2)
{
  const char *v2; // rdi
  __int64 v3; // rbx

  v2 = "admin";
  v3 = 0;
  while ( strcmp(v2, s2) )
  {
    v2 = USERS[++v3];
    if ( !v2 )
      return v2;
  }
  v2 = (const char *)runtime_pw;
  if ( runtime_pw )
    return *(const char **)(runtime_pw + 8LL * (int)v3);
  return v2;
}

unsigned __int64 __fastcall handle_client(int fd)
{
  int v2; // eax
  char *v3; // rbp
  char *v4; // rax
  const char *v5; // r15
  char *v6; // rsi
  _DWORD *v7; // r13
  char *v8; // rax
  unsigned int v9; // eax
  char *v10; // rax
  __int64 v11; // rdx
  char *v12; // rdi
  __int64 v13; // rcx
  __int64 v14; // rcx
  char *v15; // rbp
  char *v17; // r13
  char *v18; // rbp
  char *v19; // rax
  char *v20; // r12
  char *v21; // rax
  const char *v22; // rsi
  FILE *v23; // r14
  size_t v24; // rax
  char *v25; // rdi
  __int64 v26; // rcx
  char *v27; // rax
  char *v28; // rax
  __int64 v29; // rcx
  char *v30; // rax
  char *v31; // r12
  const char *v32; // rsi
  char *v33; // rax
  FILE *v34; // r13
  char *v35; // rbp
  char *v36; // rax
  char *v37; // r12
  const char *runtime_password; // rdi
  char *token; // r13
  struct stat v40; // [rsp+0h] [rbp-3008h] BYREF
  char s1[16]; // [rsp+90h] [rbp-2F78h] BYREF
  _OWORD v42[2]; // [rsp+A0h] [rbp-2F68h] BYREF
  char v43[256]; // [rsp+C0h] [rbp-2F48h] BYREF
  char s[512]; // [rsp+1C0h] [rbp-2E48h] BYREF
  char v45[512]; // [rsp+3C0h] [rbp-2C48h] BYREF
  char v46[512]; // [rsp+5C0h] [rbp-2A48h] BYREF
  char dest[512]; // [rsp+7C0h] [rbp-2848h] BYREF
  char v48[512]; // [rsp+9C0h] [rbp-2648h] BYREF
  char filename[1024]; // [rsp+BC0h] [rbp-2448h] BYREF
  char buf[24]; // [rsp+FC0h] [rbp-2048h] BYREF
  unsigned __int64 v51; // [rsp+2FC8h] [rbp-40h]

  v51 = __readfsqword(0x28u);
  v2 = recv(fd, buf, 0x1FFFu, 0);
  if ( v2 <= 0 )
    goto LABEL_29;
  buf[v2] = 0;
  v3 = s;
  *(_OWORD *)s1 = 0;
  memset(s, 0, sizeof(s));
  memset(v42, 0, sizeof(v42));
  if ( (unsigned int)__isoc23_sscanf(buf, "%15s %511s %31s", s1, s, v42) != 3 )
    goto LABEL_29;
  v4 = strstr(buf, "\r\n\r\n");
  v5 = v4 + 4;
  if ( !v4 )
    v5 = "";
  v6 = strstr(buf, "\r\nCookie:");
  memset(v45, 0, sizeof(v45));
  if ( v6 )
  {
    v7 = v6 + 2;
    v8 = strstr(v6 + 2, "\r\n");
    if ( v8 )
    {
      v9 = (_DWORD)v8 - (_DWORD)v7;
      if ( v9 - 1 <= 0x1FE )
      {
        v25 = filename;
        if ( v9 > 7 )
        {
          v29 = v9 >> 3;
          qmemcpy(filename, v7, 8 * v29);
          v25 = &filename[8 * v29];
          v7 += 2 * v29;
        }
        v26 = 0;
        if ( (v9 & 4) != 0 )
        {
          v26 = 4;
          *(_DWORD *)v25 = *v7;
        }
        if ( (v9 & 2) != 0 )
        {
          *(_WORD *)&v25[v26] = *(_WORD *)((char *)v7 + v26);
          v26 += 2;
        }
        if ( (v9 & 1) != 0 )
          v25[v26] = *((_BYTE *)v7 + v26);
        filename[v9] = 0;
        v27 = strstr(filename, "session=");
        if ( v27 )
        {
          strncpy(v45, v27 + 8, 0x1FFu);
          v28 = strchr(v45, 59);
          if ( v28 )
            *v28 = 0;
        }
      }
    }
  }
  v46[0] = 0;
  dest[0] = 0;
  v10 = strchr(s, 63);
  if ( v10 )
  {
    v11 = v10 - s;
    v12 = v46;
    if ( (unsigned __int64)(v10 - s) > 0x1FF )
      v11 = 511;
    if ( (unsigned int)v11 >= 8 )
    {
      v13 = (unsigned int)v11 >> 3;
      qmemcpy(v46, s, 8 * v13);
      v12 = &v46[8 * v13];
      v3 = &s[8 * v13];
    }
    v14 = 0;
    if ( (v11 & 4) != 0 )
    {
      *(_DWORD *)v12 = *(_DWORD *)v3;
      v14 = 4;
      if ( (v11 & 2) == 0 )
      {
LABEL_15:
        if ( (v11 & 1) == 0 )
        {
LABEL_16:
          v46[v11] = 0;
          strncpy(dest, v10 + 1, 0x1FFu);
          goto LABEL_17;
        }
LABEL_46:
        v12[v14] = v3[v14];
        goto LABEL_16;
      }
    }
    else if ( (v11 & 2) == 0 )
    {
      goto LABEL_15;
    }
    *(_WORD *)&v12[v14] = *(_WORD *)&v3[v14];
    v14 += 2;
    if ( (v11 & 1) == 0 )
      goto LABEL_16;
    goto LABEL_46;
  }
  strncpy(v46, s, 0x1FFu);
LABEL_17:
  if ( strcmp(s1, "GET") )
  {
    if ( !strcmp(s1, "POST") )
    {
      if ( strcmp(v46, "/login") )
      {
        if ( strcmp(v46, "/upload") )
        {
LABEL_63:
          sendf(fd, (__int64)"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found\n");
          goto LABEL_29;
        }
        v17 = parse_token(v45);
        if ( !v17 )
        {
LABEL_99:
          sendf(fd, (__int64)"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAuth required\n");
          goto LABEL_29;
        }
        v18 = form_get(v5, "filename");
        v19 = form_get(v5, "data");
        v20 = v19;
        if ( v18 && v19 )
        {
          if ( stat("uploads", &v40) == -1 )
            mkdir("uploads", 0x1EDu);
          memset(v48, 0, sizeof(v48));
          v21 = strrchr(v18, 47);
          v22 = v21 + 1;
          if ( !v21 )
            v22 = v18;
          strncpy(v48, v22, 0x1FFu);
          __snprintf_chk(filename, 1024, 2, 1024, "%s/%s", "uploads", v48);
          v23 = fopen(filename, "w");
          if ( v23 )
          {
            v24 = strlen(v20);
            fwrite(v20, 1u, v24, v23);
            fclose(v23);
            sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuploaded to %s\n", filename);
          }
          else
          {
            sendf(fd, (__int64)"HTTP/1.1 500 Internal\r\nContent-Type: text/plain\r\n\r\nfailed to save\n");
          }
          free(v18);
        }
        else
        {
          sendf(fd, (__int64)"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nmissing fields\n");
          if ( v18 )
            free(v18);
          if ( !v20 )
            goto LABEL_45;
        }
        free(v20);
LABEL_45:
        free(v17);
        close(fd);
        return v51 - __readfsqword(0x28u);
      }
      v35 = form_get(v5, "user");
      v36 = form_get(v5, "pass");
      v37 = v36;
      if ( v35 && v36 )
      {
        runtime_password = get_runtime_password(v35);
        if ( runtime_password && !strcmp(runtime_password, v37) )
        {
          token = make_token(v35);
          sendf(fd, (__int64)"HTTP/1.1 302 Found\r\nLocation: /\r\nSet-Cookie: session=%s; HttpOnly\r\n\r\n", token);
          free(token);
          free(v35);
        }
        else
        {
          sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nLogin failed\n");
          free(v35);
        }
      }
      else
      {
        sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nLogin failed\n");
        if ( v35 )
        {
          free(v35);
          goto LABEL_29;
        }
        if ( !v37 )
          goto LABEL_29;
      }
      free(v37);
    }
LABEL_29:
    close(fd);
    return v51 - __readfsqword(0x28u);
  }
  if ( v46[0] == 47 && !v46[1] || !strcmp(v46, "/index.html") )
  {
    v15 = parse_token(v45);
    sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
    sendf(fd, (__int64)"<h2>Welcome</h2>\n");
    sendf(fd, (__int64)"<ul><li><a href=\"/status\">Status</a></li>\n");
    if ( v15 )
    {
      sendf(fd, (__int64)"<li>Hi %s | <a href='/logout'>Logout</a></li>\n", v15);
      sendf(fd, (__int64)"<li><a href=\"/upload\">Upload</a></li></ul>\n");
      free(v15);
    }
    else
    {
      sendf(fd, (__int64)"<li><a href=\"/login\">Login</a></li>\n");
      sendf(fd, (__int64)"<li><a href=\"/upload\">Upload</a></li></ul>\n");
    }
    goto LABEL_29;
  }
  if ( !strcmp(v46, "/status") )
  {
    sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
    sendf(fd, (__int64)"{\"model\":\"CTF-R1\",\"uptime\":\"1 day\",\"users\":[\"admin\",\"user\"]}\n");
    goto LABEL_29;
  }
  if ( !strcmp(v46, "/login") )
  {
    sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
    sendf(fd, (__int64)"<h3>Login</h3>");
    sendf(
      fd,
      (__int64)"<form method='POST' action='/login'>user:<input name='user'>pass:<input name='pass' type='password'><inpu"
               "t type='submit'></form>");
    goto LABEL_29;
  }
  if ( !strcmp(v46, "/upload") )
  {
    sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
    sendf(fd, (__int64)"<h3>Upload</h3>");
    sendf(
      fd,
      (__int64)"<form method='POST' action='/upload'>filename:<input name='filename'><br>data:<textarea name='data'></tex"
               "tarea><br><input type='submit'></form>");
    goto LABEL_29;
  }
  if ( strcmp(v46, "/apply") )
  {
    if ( !strcmp(v46, "/logout") )
    {
      sendf(
        fd,
        (__int64)"HTTP/1.1 302 Found\r\n"
                 "Location: /\r\n"
                 "Set-Cookie: session=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly\r\n"
                 "\r\n");
      close(fd);
      return v51 - __readfsqword(0x28u);
    }
    goto LABEL_63;
  }
  v30 = parse_token(v45);
  v31 = v30;
  if ( !v30 )
    goto LABEL_99;
  v32 = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAdmin only\n";
  if ( !strcmp(v30, "admin") )
  {
    memset(v48, 0, sizeof(v48));
    if ( dest[0] )
    {
      v33 = strstr(dest, "file=");
      if ( v33 )
      {
        strncpy(v48, v33 + 5, 0x1FFu);
        urldecode(filename, v48);
        strncpy(v48, filename, 0x1FFu);
      }
    }
    sendf(fd, (__int64)"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
    sendf(fd, (__int64)"<pre>Applying firmware: %s\n", v48);
    if ( v48[0] )
    {
      __snprintf_chk(filename, 1024, 2, 1024, "fwapply %s", v48);
      v34 = popen(filename, "r");
      if ( v34 )
      {
        while ( fgets(v43, 256, v34) )
          sendf(fd, (__int64)"%s", v43);
        pclose(v34);
      }
      else
      {
        sendf(fd, (__int64)"apply failed\n");
      }
    }
    else
    {
      sendf(fd, (__int64)"no file specified\n");
    }
    v32 = "</pre>";
  }
  sendf(fd, (__int64)v32);
  free(v31);
  close(fd);
  return v51 - __readfsqword(0x28u);
}

