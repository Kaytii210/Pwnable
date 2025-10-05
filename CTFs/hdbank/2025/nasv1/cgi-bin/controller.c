__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *nptr; // [rsp+18h] [rbp-28h] BYREF
  char *i; // [rsp+20h] [rbp-20h]
  char *j; // [rsp+28h] [rbp-18h]
  char *s; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  sub_55D0(a1, a2, a3);
  sub_38C5(&ptr, "SERVER_SOFTWARE");
  sub_38C5(&qword_C108, "SERVER_NAME");
  sub_38C5(&qword_C110, "GATEWAY_INTERFACE");
  sub_38C5(&qword_C118, "SERVER_PROTOCOL");
  sub_38C5(&qword_C120, "SERVER_PORT");
  sub_38C5(&qword_C128, "REQUEST_METHOD");
  sub_38C5(&qword_C130, "PATH_INFO");
  sub_38C5(&qword_C138, "PATH_TRANSLATED");
  sub_38C5(&qword_C140, "SCRIPT_NAME");
  sub_38C5(&qword_C148, "QUERY_STRING");
  sub_38C5(&qword_C150, "REMOTE_HOST");
  sub_38C5(&qword_C158, "REMOTE_ADDR");
  sub_38C5(&qword_C160, "AUTH_TYPE");
  sub_38C5(&qword_C168, "REMOTE_USER");
  sub_38C5(&qword_C170, "REMOTE_IDENT");
  s = getenv("CONTENT_TYPE");
  if ( s )
  {
    if ( strlen(s) > 0x3FF )
    {
      strncpy(dest, s, 0x400u);
      dest[1023] = 0;
    }
    else
    {
      strcpy(dest, s);
    }
  }
  else
  {
    *dest = 0;
  }
  qword_C580 = (__int64)&unk_92E4;
  if ( strchr(dest, 59) )
  {
    for ( i = strchr(dest, 59); i; i = strchr(i, 59) )
    {
      *i++ = 0;
      while ( ((*__ctype_b_loc())[*i] & 0x2000) != 0 )
        ++i;
      if ( (unsigned int)sub_7BD1(i, "boundary=") )
      {
        qword_C580 = (__int64)(i + 9);
        for ( j = i + 9; *j && ((*__ctype_b_loc())[*j] & 0x2000) == 0; ++j )
          ;
        *j = 0;
        break;
      }
    }
  }
  sub_38C5(&nptr, "CONTENT_LENGTH");
  dword_C590 = atoi(nptr);
  sub_38C5(&qword_C598, "HTTP_ACCEPT");
  sub_38C5(&qword_C5A0, "HTTP_USER_AGENT");
  sub_38C5(&qword_C5A8, "HTTP_REFERER");
  sub_38C5(&qword_C588, "HTTP_COOKIE");
  qword_C5C8 = 0;
  stream = (FILE *)stdin;
  ::s = (FILE *)stdout;
  dword_C5C0 = 0;
  if ( (_DWORD)a1 && *a2 )
    dword_C5C0 = 0;
  if ( (unsigned int)sub_7AFB(qword_C128, "post") )
  {
    if ( (unsigned int)sub_7AFB(dest, "application/x-www-form-urlencoded") )
    {
      if ( (unsigned int)sub_3909() )
      {
LABEL_31:
        sub_6B3E(500, "Error reading form data");
        sub_56E8();
        return 0xFFFFFFFFLL;
      }
    }
    else if ( (unsigned int)sub_7AFB(dest, "multipart/form-data") && (unsigned int)sub_3BB0() )
    {
      goto LABEL_31;
    }
  }
  else if ( (unsigned int)sub_7AFB(qword_C128, "get") )
  {
    dword_C590 = strlen(qword_C148);
    if ( (unsigned int)sub_516C() )
      goto LABEL_31;
  }
  return (unsigned int)sub_31CC();
}
__int64 *sub_2610()
{
  return &stdout;
}
__int64 sub_2640()
{
  return 0;
}
__int64 *sub_2680()
{
  __int64 *result; // rax

  if ( !byte_C0F8 )
  {
    if ( &__cxa_finalize )
      _cxa_finalize(off_C008);
    result = sub_2610();
    byte_C0F8 = 1;
  }
  return result;
}
// attributes: thunk
__int64 sub_26C0()
{
  return sub_2640();
}
char *sub_26C9()
{
  char *v1; // [rsp+8h] [rbp-128h]
  struct passwd *v2; // [rsp+10h] [rbp-120h]
  struct spwd *v3; // [rsp+18h] [rbp-118h]
  char s1[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v5; // [rsp+128h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v1 = 0;
  sub_58CB("session", s1, 256);
  if ( !strcmp(s1, "*") )
  {
    sub_6B76("text/plain");
    return 0;
  }
  else
  {
    while ( 1 )
    {
      v2 = getpwent();
      if ( !v2 )
        break;
      v3 = getspnam(v2->pw_name);
      if ( !v3 )
      {
        endpwent();
        return 0;
      }
      if ( !strcmp(s1, v3->sp_pwdp) )
      {
        v1 = strdup(v2->pw_name);
        break;
      }
    }
    endpwent();
    return v1;
  }
}
int sub_2807()
{
  const char *format; // [rsp+8h] [rbp-8h]

  format = sub_26C9();
  if ( !format )
    return sub_6B76("text/plain");
  sub_6B76("text/plain");
  return fprintf(s, format);
}
unsigned __int64 login()
{
  size_t v0; // rax
  char *v1; // rax
  char *v2; // rax
  char *v3; // rax
  const char *s2; // [rsp+8h] [rbp-248h]
  const char *s; // [rsp+10h] [rbp-240h]
  struct passwd *v7; // [rsp+18h] [rbp-238h]
  struct spwd *v8; // [rsp+20h] [rbp-230h]
  const char *v9; // [rsp+28h] [rbp-228h]
  const char *salt; // [rsp+30h] [rbp-220h]
  char s1[256]; // [rsp+40h] [rbp-210h] BYREF
  char key[264]; // [rsp+140h] [rbp-110h] BYREF
  unsigned __int64 v13; // [rsp+248h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  s2 = 0;
  s = 0;
  sub_58CB("username", s1, 256);
  sub_58CB("password", key, 256);
  while ( 1 )
  {
    v7 = getpwent();
    if ( !v7 )
      break;
    v0 = strlen(v7->pw_name);
    if ( !strncmp(s1, v7->pw_name, v0) )
    {
      v8 = getspnam(v7->pw_name);
      if ( !v8 )
      {
        sub_6B76("text/plain");
        fwrite("Fail to read local password", 1u, 0x1Bu, ::s);
        endpwent();
        return v13 - __readfsqword(0x28u);
      }
      s2 = strdup(v7->pw_name);
      s = strdup(v8->sp_pwdp);
      break;
    }
  }
  endpwent();
  if ( s2 && !strcmp(s1, s2) )
  {
    salt = strdup(s);
    v1 = strchr(salt, 36);
    v2 = strchr(v1 + 1, 36);
    v3 = strchr(v2 + 1, 36);
    *strchr(v3 + 1, 36) = 0;
    v9 = crypt(key, salt);
    if ( !strcmp(v9, s) )
    {
      fwrite("Status: 302 Found\r\n", 1u, 0x13u, ::s);
      sub_693B("session", s, 86400, "/", qword_C108, 0);
      fwrite("Location: /", 1u, 0xBu, ::s);
    }
    else
    {
      fwrite("Status: 302 Found\r\n", 1u, 0x13u, ::s);
      fwrite("Location: /login.html?error=Incorrect username or password", 1u, 0x3Au, ::s);
    }
    fwrite("\r\n\r\n", 1u, 4u, ::s);
  }
  else
  {
    fwrite("Status: 302 Found\r\n", 1u, 0x13u, ::s);
    fwrite("Location: /login.html?error=Invalid user ", 1u, 0x29u, ::s);
    fprintf(::s, s1);
    fwrite("\r\n\r\n", 1u, 4u, ::s);
  }
  return v13 - __readfsqword(0x28u);
}
void sub_2C8D()
{
  const char *s1; // [rsp+8h] [rbp-18h]
  struct passwd *v1; // [rsp+10h] [rbp-10h]
  struct spwd *v2; // [rsp+18h] [rbp-8h]

  s1 = sub_26C9();
  if ( s1 && !strcmp(s1, "admin") )
  {
    sub_6B76("text/plain");
    while ( 1 )
    {
      v1 = getpwent();
      if ( !v1 )
        break;
      v2 = getspnam(v1->pw_name);
      if ( v2 )
      {
        if ( strcmp(v2->sp_pwdp, "*") )
          fprintf(
            s,
            "<tr><td><input class=\"form-check-input\" type=\"checkbox\" name=\"users\" value=\"%s\"><td>%s</td></tr>",
            v1->pw_name,
            v1->pw_name);
      }
    }
    endpwent();
  }
  else
  {
    sub_6B3E(401, &unk_90E8);
    fwrite("UNAUTHORIZED! GET AWAY, HACKER!", 1u, 0x1Fu, s);
  }
}
size_t sub_2D9D()
{
  const char *s1; // [rsp+8h] [rbp-8h]

  s1 = sub_26C9();
  if ( s1 && !strcmp(s1, "admin") )
  {
    fwrite("Status: 302 Found\r\n", 1u, 0x13u, s);
    fwrite("Location: /manage.html", 1u, 0x16u, s);
    return fwrite("\r\n\r\n", 1u, 4u, s);
  }
  else
  {
    sub_6B3E(401, &unk_90E8);
    return fwrite("UNAUTHORIZED! GET AWAY, HACKER!", 1u, 0x1Fu, s);
  }
}
size_t sub_2E7C()
{
  const char *s1; // [rsp+8h] [rbp-8h]

  s1 = sub_26C9();
  if ( s1 && !strcmp(s1, "admin") )
  {
    fwrite("Status: 302 Found\r\n", 1u, 0x13u, s);
    fwrite("Location: /manage.html", 1u, 0x16u, s);
    return fwrite("\r\n\r\n", 1u, 4u, s);
  }
  else
  {
    sub_6B3E(401, &unk_90E8);
    return fwrite("UNAUTHORIZED! GET AWAY, HACKER!", 1u, 0x1Fu, s);
  }
}
unsigned __int64 sub_2F5B()
{
  size_t v0; // rax
  const char *v1; // rbx
  size_t v2; // rax
  int i; // [rsp+4h] [rbp-13Ch]
  __int64 v5; // [rsp+8h] [rbp-138h] BYREF
  char *s1; // [rsp+10h] [rbp-130h]
  char *s; // [rsp+18h] [rbp-128h]
  char v8[264]; // [rsp+20h] [rbp-120h] BYREF
  unsigned __int64 v9; // [rsp+128h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  s1 = (char *)sub_26C9();
  if ( s1 )
  {
    if ( !strcmp(s1, "admin") )
    {
      sub_58CB("new_password", v8, 256);
      if ( !(unsigned int)sub_5D5F("users", &v5) )
      {
        for ( i = 0; *(_QWORD *)(v5 + 8LL * i); ++i )
        {
          v0 = strlen(*(const char **)(v5 + 8LL * i));
          s = (char *)malloc(v0 + 275);
          v1 = *(const char **)(v5 + 8LL * i);
          v2 = strlen(v1);
          snprintf(s, v2 + 275, "echo '%s:%s' | chpasswd", v1, v8);
          system(s);
        }
      }
      fwrite("Status: 302 Found\r\n", 1u, 0x13u, ::s);
      fwrite("Location: /manage.html", 1u, 0x16u, ::s);
      fwrite("\r\n\r\n", 1u, 4u, ::s);
    }
  }
  else
  {
    fwrite("Status: 302 Found\r\n", 1u, 0x13u, ::s);
    fwrite("Location: /", 1u, 0xBu, ::s);
    fwrite("\r\n\r\n", 1u, 4u, ::s);
  }
  return v9 - __readfsqword(0x28u);
}
__int64 sub_31CC()
{
  __uid_t v0; // ebx
  __uid_t v1; // eax
  const char *s1; // [rsp+8h] [rbp-58h]
  char v4[56]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  v0 = geteuid();
  v1 = geteuid();
  setreuid(v1, v0);
  s1 = getenv("REQUEST_METHOD");
  sub_58CB("action", v4, 50);
  if ( !s1 || !strcmp(s1, "GET") )
  {
    if ( !strcmp(v4, "check_session") )
    {
      sub_2807();
    }
    else if ( !strcmp(v4, "login") )
    {
      login();
    }
    else if ( !strcmp(v4, "list_user") )
    {
      sub_2C8D();
    }
    else if ( !strcmp(v4, "add_user") )
    {
      sub_2D9D();
    }
    else if ( !strcmp(v4, "delete_user") )
    {
      sub_2E7C();
    }
    else if ( !strcmp(v4, "change_password") )
    {
      sub_2F5B();
    }
  }
  return 0;
}
char **__fastcall sub_38C5(char **a1, const char *a2)
{
  char **result; // rax

  *a1 = getenv(a2);
  result = (char **)*a1;
  if ( !*a1 )
  {
    result = a1;
    *a1 = (char *)&unk_92E4;
  }
  return result;
}
__int64 sub_3909()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  void *ptr; // [rsp+8h] [rbp-8h]

  if ( !dword_C590 )
    return 0;
  ptr = malloc(dword_C590);
  if ( !ptr )
    return 1;
  if ( (unsigned int)fread(ptr, 1u, dword_C590, stream) != dword_C590 )
    return 2;
  v1 = sub_518D(ptr, (unsigned int)dword_C590);
  free(ptr);
  return v1;
}
__int64 __fastcall sub_39A4(_DWORD *a1, char *a2, int a3)
{
  int v3; // edx
  char *v4; // rax
  int v6; // [rsp+Ch] [rbp-24h]
  int v8; // [rsp+24h] [rbp-Ch]
  int v10; // [rsp+2Ch] [rbp-4h]

  v6 = a3;
  v8 = 0;
  if ( a3 > dword_C590 - a1[258] )
    v6 = dword_C590 - a1[258];
  while ( v6 && a1[256] != a1[257] )
  {
    v3 = a1[256];
    a1[256] = v3 + 1;
    v4 = a2++;
    *v4 = *((_BYTE *)a1 + v3);
    a1[256] &= 0x3FFu;
    ++v8;
    --v6;
  }
  if ( v6 )
  {
    v10 = fread(a2, 1u, v6, stream);
    if ( v10 < 0 )
    {
      if ( v8 <= 0 )
      {
        return (unsigned int)v10;
      }
      else
      {
        a1[258] += v8;
        return (unsigned int)v8;
      }
    }
    else
    {
      a1[258] += v8 + v10;
      return (unsigned int)(v8 + v10);
    }
  }
  else if ( v8 )
  {
    a1[258] += v8;
    return (unsigned int)v8;
  }
  else if ( a3 )
  {
    return 0xFFFFFFFFLL;
  }
  else
  {
    return 0;
  }
}
__int64 __fastcall sub_3B28(__int64 a1, _BYTE *a2, int a3)
{
  __int64 result; // rax
  _BYTE *v4; // rax
  int v5; // edx
  int v6; // [rsp+0h] [rbp-14h]

  v6 = a3;
  result = a1;
  *(_DWORD *)(a1 + 1032) -= a3;
  while ( v6 )
  {
    v4 = a2++;
    v5 = *(_DWORD *)(a1 + 1028);
    *(_DWORD *)(a1 + 1028) = v5 + 1;
    *(_BYTE *)(a1 + v5) = *v4;
    result = a1;
    *(_DWORD *)(a1 + 1028) &= 0x3FFu;
    --v6;
  }
  return result;
}__int64 sub_3BB0()
{
  size_t v1; // rax
  void *v2; // rax
  size_t v3; // rax
  void *v4; // rax
  size_t v5; // rax
  void *v6; // rax
  int v7; // eax
  int v8; // eax
  FILE *v9; // rax
  int v10; // [rsp+Ch] [rbp-2084h] BYREF
  unsigned int v11; // [rsp+10h] [rbp-2080h]
  int v12; // [rsp+14h] [rbp-207Ch]
  FILE *stream; // [rsp+18h] [rbp-2078h] BYREF
  void *ptr; // [rsp+20h] [rbp-2070h] BYREF
  _QWORD *v15; // [rsp+28h] [rbp-2068h]
  void *v16; // [rsp+30h] [rbp-2060h]
  _DWORD *v17; // [rsp+38h] [rbp-2058h]
  _QWORD v18[2]; // [rsp+40h] [rbp-2050h] BYREF
  _QWORD v19[4]; // [rsp+50h] [rbp-2040h] BYREF
  _BYTE s[32]; // [rsp+70h] [rbp-2020h] BYREF
  char v21[1024]; // [rsp+480h] [rbp-1C10h] BYREF
  _BYTE v22[1024]; // [rsp+880h] [rbp-1810h] BYREF
  char src[1024]; // [rsp+C80h] [rbp-1410h] BYREF
  char v24[16]; // [rsp+1080h] [rbp-1010h] BYREF
  char v25[1024]; // [rsp+1480h] [rbp-C10h] BYREF
  _BYTE v26[1024]; // [rsp+1880h] [rbp-810h] BYREF
  _BYTE v27[1032]; // [rsp+1C80h] [rbp-410h] BYREF
  unsigned __int64 v28; // [rsp+2088h] [rbp-8h]

  v28 = __readfsqword(0x28u);
  v16 = 0;
  v15 = 0;
  stream = 0;
  ptr = 0;
  v17 = s;
  memset(s, 0, 0x40Cu);
  if ( !dword_C590 )
    return 0;
  v11 = sub_4411(v17, 0, 0, 0, 1);
  if ( v11 == 2 )
    return 0;
  if ( v11 )
    return v11;
  while ( 1 )
  {
    while ( 1 )
    {
      v10 = 0;
      v22[0] = 0;
      src[0] = 0;
      v24[0] = 0;
      v25[0] = 0;
      ptr = 0;
      stream = 0;
      v12 = sub_39A4(v17, v21, 2);
      if ( v12 <= 1 || v21[0] == 45 && v21[1] == 45 )
        return 0;
      sub_3B28((__int64)v17, v21, 2);
      while ( (unsigned int)sub_4F2F(v17, v26, 1024, v27, 1024) )
      {
        if ( (unsigned int)sub_7AFB(v26, "Content-Disposition") )
        {
          v19[0] = "name";
          v19[1] = "filename";
          v19[2] = 0;
          v18[0] = src;
          v18[1] = v24;
          sub_4966(v27, v22, 1024, v19, v18, 1024);
        }
        else if ( (unsigned int)sub_7AFB(v26, "Content-Type") )
        {
          v19[0] = 0;
          sub_4966(v27, v25, 1024, v19, 0, 0);
        }
      }
      if ( (unsigned int)sub_7AFB(v22, "form-data") )
        break;
      v11 = sub_4411(v17, 0, 0, 0, 0);
      if ( v11 )
        return v11;
    }
    if ( v24[0] )
    {
      if ( (unsigned int)sub_431A(&stream) )
        return 2;
    }
    else
    {
      stream = 0;
    }
    v11 = sub_4411(v17, stream, &ptr, &v10, 0);
    if ( v11 )
    {
      if ( stream )
        fclose(stream);
      if ( ptr )
        free(ptr);
      return v11;
    }
    v16 = malloc(0x38u);
    if ( !v16 )
      break;
    memset(v16, 0, 0x38u);
    v1 = strlen(src);
    v2 = malloc(v1 + 1);
    *(_QWORD *)v16 = v2;
    if ( !*(_QWORD *)v16 )
      break;
    strcpy(*(char **)v16, src);
    if ( ptr )
    {
      *((_QWORD *)v16 + 1) = ptr;
      ptr = 0;
    }
    else if ( stream )
    {
      *((_QWORD *)v16 + 1) = malloc(1u);
      if ( !*((_QWORD *)v16 + 1) )
        break;
      **((_BYTE **)v16 + 1) = 0;
    }
    *((_DWORD *)v16 + 4) = v10;
    *((_QWORD *)v16 + 6) = 0;
    if ( v15 )
      v15[6] = v16;
    else
      qword_C5C8 = (__int64)v16;
    v3 = strlen(v24);
    v4 = malloc(v3 + 1);
    *((_QWORD *)v16 + 3) = v4;
    if ( !*((_QWORD *)v16 + 3) )
      break;
    strcpy(*((char **)v16 + 3), v24);
    v5 = strlen(v25);
    v6 = malloc(v5 + 1);
    *((_QWORD *)v16 + 4) = v6;
    if ( !*((_QWORD *)v16 + 4) )
      break;
    strcpy(*((char **)v16 + 4), v25);
    if ( stream )
    {
      v7 = fileno(stream);
      v8 = dup(v7);
      v9 = fdopen(v8, "w+b");
      *((_QWORD *)v16 + 5) = v9;
      fclose(stream);
    }
    v15 = v16;
  }
  if ( v16 )
  {
    if ( *(_QWORD *)v16 )
      free(*(void **)v16);
    if ( *((_QWORD *)v16 + 1) )
      free(*((void **)v16 + 1));
    if ( *((_QWORD *)v16 + 3) )
      free(*((void **)v16 + 3));
    if ( *((_QWORD *)v16 + 5) )
      fclose(*((FILE **)v16 + 5));
    if ( *((_QWORD *)v16 + 4) )
      free(*((void **)v16 + 4));
    free(v16);
  }
  if ( ptr )
    free(ptr);
  if ( stream )
    fclose(stream);
  return 1;
}
__int64 __fastcall sub_431A(FILE **a1)
{
  int fd; // [rsp+1Ch] [rbp-414h]
  char file[1032]; // [rsp+20h] [rbp-410h] BYREF
  unsigned __int64 v4; // [rsp+428h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  strcpy(file, "/tmp/cgicXXXXXX");
  fd = mkstemp(file);
  if ( fd == -1 )
    return 2;
  close(fd);
  if ( chmod(file, 0x180u) )
  {
    unlink(file);
    return 2;
  }
  else
  {
    *a1 = fopen(file, "w+b");
    unlink(file);
    return 0;
  }
}
__int64 __fastcall sub_4411(_DWORD *a1, FILE *a2, _QWORD *a3, int *a4, int a5)
{
  int v5; // eax
  int v6; // eax
  int v7; // eax
  int v12; // [rsp+38h] [rbp-458h]
  int v13; // [rsp+3Ch] [rbp-454h]
  unsigned int v14; // [rsp+40h] [rbp-450h]
  int v15; // [rsp+44h] [rbp-44Ch]
  int v16; // [rsp+48h] [rbp-448h]
  void *ptr; // [rsp+50h] [rbp-440h]
  void *ptra; // [rsp+50h] [rbp-440h]
  char *v19; // [rsp+58h] [rbp-438h]
  void *v20; // [rsp+60h] [rbp-430h]
  void *v21; // [rsp+68h] [rbp-428h]
  void *v22; // [rsp+70h] [rbp-420h]
  char v23[2]; // [rsp+7Eh] [rbp-412h] BYREF
  char s[2]; // [rsp+80h] [rbp-410h] BYREF
  _BYTE v25[1038]; // [rsp+82h] [rbp-40Eh] BYREF

  *(_QWORD *)&v25[1030] = __readfsqword(0x28u);
  v12 = 0;
  v13 = 256;
  ptr = 0;
  v19 = s;
  if ( !a2 )
  {
    if ( a3 )
    {
      ptr = malloc(0x100u);
      if ( !ptr )
      {
LABEL_44:
        v14 = 1;
        if ( a3 )
        {
          if ( ptr )
            free(ptr);
          *a3 = 0;
        }
LABEL_48:
        if ( a4 )
          *a4 = 0;
        if ( ptr )
          free(ptr);
        if ( a3 )
          *a3 = 0;
        return v14;
      }
    }
  }
  v15 = 0;
  sprintf(s, "\r\n--%s", (const char *)qword_C580);
  if ( a5 )
    v19 = v25;
  v16 = strlen(v19);
  while ( 1 )
  {
    if ( (unsigned int)sub_39A4(a1, v23, 1) != 1 )
    {
      v14 = 2;
      goto LABEL_48;
    }
    if ( v23[0] == v19[v15] )
      break;
    if ( v15 <= 0 )
    {
      if ( a2 )
      {
        putc(v23[0], a2);
        ++v12;
      }
      else if ( ptr )
      {
        if ( v13 == v12 + 1 )
        {
          v20 = ptr;
          v13 *= 2;
          ptr = realloc(ptr, v13);
          if ( !ptr )
          {
            ptr = v20;
            goto LABEL_44;
          }
        }
        v6 = v12++;
        *((_BYTE *)ptr + v6) = v23[0];
      }
    }
    else
    {
      if ( a2 )
      {
        putc(*v19, a2);
        ++v12;
      }
      else if ( ptr )
      {
        if ( v13 == v12 + 1 )
        {
          v21 = ptr;
          v13 *= 2;
          ptr = realloc(ptr, v13);
          if ( !ptr )
          {
            ptr = v21;
            goto LABEL_44;
          }
        }
        v5 = v12++;
        *((_BYTE *)ptr + v5) = *v19;
      }
      sub_3B28((__int64)a1, v19 + 1, v15 - 1);
      sub_3B28((__int64)a1, v23, 1);
      v15 = 0;
    }
LABEL_28:
    if ( v12 > 0x40000000 )
      goto LABEL_44;
  }
  if ( ++v15 != v16 )
    goto LABEL_28;
  v7 = sub_39A4(a1, v23, 2);
  if ( v7 != 2 )
  {
    v14 = 2;
    goto LABEL_48;
  }
  if ( (v23[0] != 13 || v23[1] != 10) && v23[0] == 45 )
    sub_3B28((__int64)a1, v23, 2);
  if ( ptr && v13 )
  {
    v22 = ptr;
    *((_BYTE *)ptr + v12) = 0;
    ptra = realloc(ptr, v12 + 1);
    if ( !ptra )
      ptra = v22;
    *a3 = ptra;
  }
  if ( a4 )
    *a4 = v12;
  return 0;
}
unsigned __int64 __fastcall sub_4966(_BYTE *k, __int64 a2, int a3, __int64 a4, __int64 a5, int a6)
{
  int v6; // eax
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  _BYTE *j; // [rsp+28h] [rbp-438h]
  int v18; // [rsp+30h] [rbp-430h]
  int v19; // [rsp+34h] [rbp-42Ch]
  int i; // [rsp+38h] [rbp-428h]
  int v21; // [rsp+3Ch] [rbp-424h]
  int v22; // [rsp+40h] [rbp-420h]
  __int64 v23; // [rsp+48h] [rbp-418h]
  _BYTE v24[1032]; // [rsp+50h] [rbp-410h] BYREF
  unsigned __int64 v25; // [rsp+458h] [rbp-8h]

  v25 = __readfsqword(0x28u);
  v19 = 0;
  for ( i = 0; *(_QWORD *)(8LL * i + a4); ++i )
  {
    if ( a6 )
      **(_BYTE **)(8LL * i + a5) = 0;
  }
  while ( ((*__ctype_b_loc())[(char)*k] & 0x2000) != 0 )
    ++k;
  if ( *k == 34 )
  {
    ++k;
    while ( *k && *k != 34 )
    {
      if ( a3 > v19 + 1 )
      {
        v6 = v19++;
        *(_BYTE *)(a2 + v6) = *k;
      }
      ++k;
    }
    while ( *k && *k != 59 )
      ++k;
  }
  else
  {
    while ( *k && *k != 59 )
    {
      if ( a3 > v19 + 1 )
      {
        v7 = v19++;
        *(_BYTE *)(a2 + v7) = *k;
      }
      ++k;
    }
  }
  if ( a3 )
    *(_BYTE *)(v19 + a2) = 0;
  while ( *k == 59 )
  {
    v22 = 0;
    for ( j = k + 1; *j && ((*__ctype_b_loc())[(char)*j] & 0x2000) != 0; ++j )
      ;
    v18 = 0;
    while ( *j && ((*__ctype_b_loc())[(char)*j] & 8) != 0 )
    {
      if ( v18 + 1 < 1024 )
      {
        v8 = v18++;
        v24[v8] = *j;
      }
      ++j;
    }
    v24[v18] = 0;
    while ( *j && ((*__ctype_b_loc())[(char)*j] & 0x2000) != 0 )
      ++j;
    if ( *j != 61 )
      break;
    for ( k = j + 1; *k && ((*__ctype_b_loc())[(char)*k] & 0x2000) != 0; ++k )
      ;
    v21 = 0;
    v23 = 0;
    while ( *(_QWORD *)(8LL * v21 + a4) )
    {
      if ( (unsigned int)sub_7AFB(v24, *(_QWORD *)(8LL * v21 + a4)) )
      {
        v23 = *(_QWORD *)(8LL * v21 + a5);
        break;
      }
      ++v21;
    }
    if ( *k == 34 )
    {
      ++k;
      while ( *k && *k != 34 )
      {
        if ( v23 && a6 > v22 + 1 )
        {
          v9 = v22++;
          *(_BYTE *)(v23 + v9) = *k;
        }
        ++k;
      }
      while ( *k && *k != 59 )
        ++k;
    }
    else
    {
      while ( *k && *k != 59 )
      {
        if ( *(_QWORD *)(8LL * v21 + a4) && a6 > v22 + 1 )
        {
          v10 = v22++;
          *(_BYTE *)(v23 + v10) = *k;
        }
        ++k;
      }
    }
    if ( a6 && v23 )
      *(_BYTE *)(v22 + v23) = 0;
  }
  return v25 - __readfsqword(0x28u);
}
_BOOL8 __fastcall sub_4F2F(_DWORD *a1, __int64 a2, int a3, __int64 a4, int a5)
{
  int v6; // eax
  int v7; // eax
  int v11; // [rsp+24h] [rbp-1Ch]
  int v12; // [rsp+28h] [rbp-18h]
  int v13; // [rsp+2Ch] [rbp-14h]
  char v14; // [rsp+37h] [rbp-9h] BYREF
  unsigned __int64 v15; // [rsp+38h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  v11 = 0;
  v12 = 0;
  v13 = 0;
  while ( 1 )
  {
LABEL_2:
    if ( (unsigned int)sub_39A4(a1, &v14, 1) != 1 )
      return 0;
    if ( v14 == 13 )
      break;
    if ( v14 == 10 )
      goto LABEL_22;
    if ( v14 == 58 && v11 )
    {
      v13 = 1;
      while ( (unsigned int)sub_39A4(a1, &v14, 1) == 1 )
      {
        if ( ((*__ctype_b_loc())[v14] & 0x2000) == 0 )
        {
          sub_3B28((__int64)a1, &v14, 1);
          goto LABEL_2;
        }
      }
    }
    else if ( v13 )
    {
      if ( v12 < a5 - 1 )
      {
        v7 = v12++;
        *(_BYTE *)(a4 + v7) = v14;
      }
    }
    else if ( ((*__ctype_b_loc())[v14] & 0x2000) == 0 && v11 < a3 - 1 )
    {
      v6 = v11++;
      *(_BYTE *)(a2 + v6) = v14;
    }
  }
  if ( (unsigned int)sub_39A4(a1, &v14, 1) == 1 && v14 != 10 )
    sub_3B28((__int64)a1, &v14, 1);
LABEL_22:
  if ( a3 )
    *(_BYTE *)(v11 + a2) = 0;
  if ( a5 )
    *(_BYTE *)(v12 + a4) = 0;
  return v11 && v12;
}
__int64 sub_516C()
{
  return sub_518D(qword_C148, (unsigned int)dword_C590);
}
__int64 __fastcall sub_518D(__int64 a1, int a2)
{
  int v3; // eax
  int v4; // [rsp+18h] [rbp-38h]
  int v5; // [rsp+1Ch] [rbp-34h]
  unsigned int v6; // [rsp+20h] [rbp-30h]
  unsigned int v7; // [rsp+20h] [rbp-30h]
  int v8; // [rsp+24h] [rbp-2Ch]
  int v9; // [rsp+24h] [rbp-2Ch]
  void *ptr; // [rsp+28h] [rbp-28h] BYREF
  void *v11; // [rsp+30h] [rbp-20h] BYREF
  _QWORD *v12; // [rsp+38h] [rbp-18h]
  void *v13; // [rsp+40h] [rbp-10h]
  unsigned __int64 v14; // [rsp+48h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  v4 = 0;
  v12 = 0;
  do
  {
    if ( v4 == a2 )
      break;
    v5 = 0;
    v8 = v4;
    v6 = 0;
    while ( v4 != a2 && *(_BYTE *)(v4 + a1) != 38 )
    {
      if ( *(_BYTE *)(v4 + a1) == 61 )
      {
        ++v4;
        break;
      }
      ++v4;
      ++v6;
    }
    if ( !v6 )
      break;
    if ( (unsigned int)sub_545D(&ptr, v8 + a1, v6) )
      return 1;
    v9 = v4;
    v7 = 0;
    while ( v4 != a2 )
    {
      if ( *(_BYTE *)(v4 + a1) == 38 )
      {
        v5 = 1;
        ++v4;
        break;
      }
      ++v4;
      ++v7;
    }
    if ( (unsigned int)sub_545D(&v11, v9 + a1, v7) )
    {
      free(ptr);
      return 1;
    }
    v13 = malloc(0x38u);
    if ( !v13 )
    {
      free(ptr);
      free(v11);
      return 1;
    }
    *(_QWORD *)v13 = ptr;
    *((_QWORD *)v13 + 1) = v11;
    v3 = strlen(*((const char **)v13 + 1));
    *((_DWORD *)v13 + 4) = v3;
    *((_QWORD *)v13 + 3) = malloc(1u);
    if ( !*((_QWORD *)v13 + 3) )
    {
      free(ptr);
      free(v11);
      free(v13);
      return 1;
    }
    **((_BYTE **)v13 + 3) = 0;
    *((_QWORD *)v13 + 4) = malloc(1u);
    if ( !*((_QWORD *)v13 + 4) )
    {
      free(ptr);
      free(v11);
      free(*((void **)v13 + 3));
      free(v13);
      return 1;
    }
    **((_BYTE **)v13 + 4) = 0;
    *((_QWORD *)v13 + 6) = 0;
    if ( v12 )
      v12[6] = v13;
    else
      qword_C5C8 = (__int64)v13;
    v12 = v13;
  }
  while ( v5 );
  return 0;
}
__int64 __fastcall sub_545D(_QWORD *a1, __int64 a2, int a3)
{
  int v4; // eax
  int v5; // eax
  int v7; // [rsp+24h] [rbp-1Ch]
  int v8; // [rsp+28h] [rbp-18h]
  int v9; // [rsp+2Ch] [rbp-14h]
  int v10; // [rsp+30h] [rbp-10h]
  int v11; // [rsp+34h] [rbp-Ch]
  _BYTE *v12; // [rsp+38h] [rbp-8h]

  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v12 = malloc(a3 + 1);
  if ( !v12 )
    return 1;
  while ( v9 < a3 )
  {
    v11 = *(char *)(v9 + a2);
    if ( v7 == 2 )
    {
      v8 += dword_C5E0[*(char *)(v9 + a2)];
      v5 = v10++;
      v12[v5] = v8;
      v7 = 0;
    }
    else if ( v7 )
    {
      v8 = 16 * dword_C5E0[*(char *)(v9 + a2)];
      v7 = 2;
    }
    else if ( v11 == 37 )
    {
      v7 = 1;
    }
    else
    {
      v4 = v10++;
      if ( v11 == 43 )
        v12[v4] = 32;
      else
        v12[v4] = v11;
    }
    ++v9;
  }
  v12[v10] = 0;
  *a1 = v12;
  return 0;
}
_DWORD *sub_55D0()
{
  _DWORD *result; // rax
  int i; // [rsp+0h] [rbp-4h]

  for ( i = 0; i <= 255; ++i )
  {
    result = dword_C5E0;
    dword_C5E0[i] = 0;
  }
  dword_C6A0 = 0;
  dword_C6A4 = 1;
  dword_C6A8 = 2;
  dword_C6AC = 3;
  dword_C6B0 = 4;
  dword_C6B4 = 5;
  dword_C6B8 = 6;
  dword_C6BC = 7;
  dword_C6C0 = 8;
  dword_C6C4 = 9;
  dword_C6E4 = 10;
  dword_C6E8 = 11;
  dword_C6EC = 12;
  dword_C6F0 = 13;
  dword_C6F4 = 14;
  dword_C6F8 = 15;
  dword_C764 = 10;
  dword_C768 = 11;
  dword_C76C = 12;
  dword_C770 = 13;
  dword_C774 = 14;
  dword_C778 = 15;
  return result;
}
void sub_56E8()
{
  void *ptr; // [rsp+0h] [rbp-10h]
  void *v1; // [rsp+8h] [rbp-8h]

  for ( ptr = (void *)qword_C5C8; ptr; ptr = v1 )
  {
    v1 = (void *)*((_QWORD *)ptr + 6);
    free(*(void **)ptr);
    free(*((void **)ptr + 1));
    free(*((void **)ptr + 3));
    free(*((void **)ptr + 4));
    if ( *((_QWORD *)ptr + 5) )
      fclose(*((FILE **)ptr + 5));
    free(ptr);
  }
  if ( dword_C5C0 )
  {
    free(::ptr);
    free(qword_C108);
    free(qword_C110);
    free(qword_C118);
    free(qword_C120);
    free(qword_C128);
    free(qword_C130);
    free(qword_C138);
    free(qword_C140);
    free(qword_C148);
    free(qword_C150);
    free(qword_C158);
    free(qword_C160);
    free(qword_C168);
    free(qword_C170);
    free(dest);
    free(qword_C598);
    free(qword_C5A0);
    free(qword_C5A8);
  }
  qword_C5C8 = 0;
  dword_C5C0 = 0;
}
__int64 __fastcall sub_58CB(__int64 a1, _BYTE *a2, unsigned int a3)
{
  __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = sub_7C92(a1);
  if ( v5 )
    return sub_5FA0(v5, a2, a3, 1);
  *a2 = 0;
  return 4;
}
__int64 __fastcall sub_5921(__int64 a1, _BYTE *a2, int a3)
{
  int v4; // eax
  int v6; // [rsp+2Ch] [rbp-14h]
  _BYTE *i; // [rsp+30h] [rbp-10h]
  __int64 v8; // [rsp+38h] [rbp-8h]

  v6 = 0;
  v8 = sub_7C92(a1);
  if ( v8 )
  {
    for ( i = *(_BYTE **)(v8 + 24); *i; ++i )
    {
      if ( a3 > v6 + 1 )
      {
        v4 = v6++;
        a2[v4] = *i;
      }
    }
    if ( a3 )
      a2[v6] = 0;
    if ( **(_BYTE **)(v8 + 24) )
      return a3 <= (int)strlen(*(const char **)(v8 + 24));
    else
      return 8;
  }
  else
  {
    *a2 = 0;
    return 4;
  }
}
__int64 __fastcall sub_59FB(__int64 a1, _BYTE *a2, int a3)
{
  int v4; // eax
  int v6; // [rsp+2Ch] [rbp-14h]
  _BYTE *i; // [rsp+30h] [rbp-10h]
  __int64 v8; // [rsp+38h] [rbp-8h]

  v6 = 0;
  v8 = sub_7C92(a1);
  if ( v8 )
  {
    for ( i = *(_BYTE **)(v8 + 32); *i; ++i )
    {
      if ( a3 > v6 + 1 )
      {
        v4 = v6++;
        a2[v4] = *i;
      }
    }
    if ( a3 )
      a2[v6] = 0;
    if ( **(_BYTE **)(v8 + 32) )
      return a3 <= (int)strlen(*(const char **)(v8 + 32));
    else
      return 9;
  }
  else
  {
    if ( a3 )
      *a2 = 0;
    return 4;
  }
}
__int64 __fastcall sub_5ADB(__int64 a1, _DWORD *a2)
{
  __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = sub_7C92(a1);
  if ( v3 )
  {
    if ( *(_QWORD *)(v3 + 40) )
    {
      if ( a2 )
        *a2 = *(_DWORD *)(v3 + 16);
      return 0;
    }
    else
    {
      if ( a2 )
        *a2 = 0;
      return 10;
    }
  }
  else
  {
    if ( a2 )
      *a2 = 0;
    return 4;
  }
}
__int64 __fastcall sub_5B5E(__int64 a1, FILE ***a2)
{
  int v3; // eax
  int v4; // eax
  __int64 v5; // [rsp+10h] [rbp-10h]
  FILE **ptr; // [rsp+18h] [rbp-8h]

  v5 = sub_7C92(a1);
  if ( v5 )
  {
    if ( *(_QWORD *)(v5 + 40) )
    {
      ptr = (FILE **)malloc(8u);
      if ( ptr )
      {
        v3 = fileno(*(FILE **)(v5 + 40));
        v4 = dup(v3);
        *ptr = fdopen(v4, "rb");
        rewind(*ptr);
        if ( *ptr )
        {
          *a2 = ptr;
          return 0;
        }
        else
        {
          free(ptr);
          return 12;
        }
      }
      else
      {
        *a2 = 0;
        return 7;
      }
    }
    else
    {
      *a2 = 0;
      return 10;
    }
  }
  else
  {
    *a2 = 0;
    return 4;
  }
}
__int64 __fastcall sub_5C5B(FILE **a1, void *a2, int a3, int *a4)
{
  int v6; // [rsp+2Ch] [rbp-4h]

  if ( !a1 )
    return 11;
  v6 = fread(a2, 1u, a3, *a1);
  if ( v6 <= 0 )
    return 13;
  *a4 = v6;
  return 0;
}
__int64 __fastcall sub_5CC9(FILE **a1)
{
  if ( !a1 )
    return 11;
  fclose(*a1);
  free(a1);
  return 0;
}
__int64 __fastcall sub_5D09(__int64 a1, _BYTE *a2, unsigned int a3)
{
  __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = sub_7C92(a1);
  if ( v5 )
    return sub_5FA0(v5, a2, a3, 0);
  *a2 = 0;
  return 4;
}
__int64 __fastcall sub_5D5F(__int64 a1, _QWORD *a2)
{
  int i; // [rsp+14h] [rbp-2Ch]
  int v4; // [rsp+14h] [rbp-2Ch]
  int v5; // [rsp+18h] [rbp-28h]
  unsigned int v6; // [rsp+1Ch] [rbp-24h]
  __int64 v7; // [rsp+20h] [rbp-20h]
  _QWORD *v8; // [rsp+28h] [rbp-18h]

  v5 = 0;
  if ( sub_7C92(a1) )
  {
    do
      ++v5;
    while ( sub_7CC7() );
  }
  v8 = malloc(8LL * (v5 + 1));
  if ( v8 )
  {
    for ( i = 0; i <= v5; ++i )
      v8[i] = 0;
    v7 = sub_7C92(a1);
    if ( v7 )
    {
      v4 = 0;
      do
      {
        v6 = strlen(*(const char **)(v7 + 8)) + 1;
        v8[v4] = malloc((int)v6);
        if ( !v8[v4] )
        {
          sub_7D63(v8);
          *a2 = 0;
          return 7;
        }
        strcpy((char *)v8[v4], *(const char **)(v7 + 8));
        sub_5FA0(v7, v8[v4++], v6, 1);
        v7 = sub_7CC7();
      }
      while ( v7 );
      *a2 = v8;
      return 0;
    }
    else
    {
      *a2 = v8;
      return 4;
    }
  }
  else
  {
    *a2 = 0;
    return 7;
  }
}
__int64 __fastcall sub_5F44(__int64 a1, _DWORD *a2)
{
  __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = sub_7C92(a1);
  if ( v3 )
  {
    *a2 = strlen(*(const char **)(v3 + 8)) + 1;
    return 0;
  }
  else
  {
    *a2 = 1;
    return 4;
  }
}
__int64 __fastcall sub_5FA0(__int64 a1, _BYTE *a2, int a3, int a4)
{
  int v5; // [rsp+1Ch] [rbp-2Ch]
  int v6; // [rsp+20h] [rbp-28h]
  int v7; // [rsp+24h] [rbp-24h]
  int v8; // [rsp+28h] [rbp-20h]
  int v9; // [rsp+2Ch] [rbp-1Ch]
  int v10; // [rsp+30h] [rbp-18h]
  int v11; // [rsp+34h] [rbp-14h]
  char *i; // [rsp+40h] [rbp-8h]

  v5 = 0;
  v6 = 0;
  v10 = a3 - 1;
  v7 = 0;
  v8 = 0;
  for ( i = *(char **)(a1 + 8); ; ++i )
  {
    v11 = *i;
    if ( v11 != 13 && v11 != 10 )
      break;
    if ( v11 == 13 )
      ++v7;
    else
      ++v8;
LABEL_22:
    ;
  }
  if ( v7 || v8 )
  {
    v9 = v7;
    if ( v8 > v7 )
      v9 = v8;
    if ( !a4 )
      v9 = 0;
    while ( v9 )
    {
      if ( v6 >= v10 )
      {
        v5 = 1;
        break;
      }
      *a2++ = 10;
      --v9;
      ++v6;
    }
    v7 = 0;
    v8 = 0;
  }
  if ( !v11 )
    goto LABEL_23;
  if ( v6 < v10 )
  {
    *a2++ = v11;
    ++v6;
    goto LABEL_22;
  }
  v5 = 1;
LABEL_23:
  *a2 = 0;
  if ( v5 )
    return 1;
  if ( v6 )
    return 0;
  return 3;
}
__int64 __fastcall sub_60E6(__int64 a1, int *a2, int a3)
{
  int v5; // [rsp+24h] [rbp-Ch]
  __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = sub_7C92(a1);
  if ( v6 )
  {
    if ( **(_BYTE **)(v6 + 8) )
    {
      v5 = sub_7D25(*(_QWORD *)(v6 + 8));
      if ( ((*__ctype_b_loc())[v5] & 0x800) != 0 || v5 == 45 || v5 == 43 )
      {
        *a2 = atoi(*(const char **)(v6 + 8));
        return 0;
      }
      else
      {
        *a2 = a3;
        return 2;
      }
    }
    else
    {
      *a2 = a3;
      return 3;
    }
  }
  else
  {
    *a2 = a3;
    return 4;
  }
}
__int64 __fastcall sub_61B4(__int64 a1, int *a2, int a3, int a4, int a5)
{
  unsigned int v8; // [rsp+2Ch] [rbp-4h]

  v8 = sub_60E6(a1, a2, a5);
  if ( v8 )
    return v8;
  if ( a3 <= *a2 )
  {
    if ( a4 >= *a2 )
    {
      return 0;
    }
    else
    {
      *a2 = a4;
      return 5;
    }
  }
  else
  {
    *a2 = a3;
    return 5;
  }
}
__int64 __fastcall sub_6233(__int64 a1, double *a2, double a3)
{
  int v4; // [rsp+24h] [rbp-Ch]
  __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = sub_7C92(a1);
  if ( v5 )
  {
    if ( **(_BYTE **)(v5 + 8) )
    {
      v4 = sub_7D25(*(_QWORD *)(v5 + 8));
      if ( ((*__ctype_b_loc())[v4] & 0x800) != 0 || v4 == 46 || v4 == 45 || v4 == 43 )
      {
        *a2 = atof(*(const char **)(v5 + 8));
        return 0;
      }
      else
      {
        *a2 = a3;
        return 2;
      }
    }
    else
    {
      *a2 = a3;
      return 3;
    }
  }
  else
  {
    *a2 = a3;
    return 4;
  }
}
__int64 __fastcall sub_631B(__int64 a1, double *a2, double a3, double a4, double a5)
{
  unsigned int v6; // [rsp+3Ch] [rbp-4h]

  v6 = sub_6233(a1, a2, a5);
  if ( v6 )
    return v6;
  if ( a3 <= *a2 )
  {
    if ( *a2 <= a4 )
    {
      return 0;
    }
    else
    {
      *a2 = a4;
      return 5;
    }
  }
  else
  {
    *a2 = a3;
    return 5;
  }
}
__int64 __fastcall sub_63B9(__int64 a1, __int64 a2, int a3, _DWORD *a4, int a5)
{
  int i; // [rsp+24h] [rbp-Ch]
  __int64 v10; // [rsp+28h] [rbp-8h]

  v10 = sub_7C92(a1);
  if ( v10 )
  {
    for ( i = 0; i < a3; ++i )
    {
      if ( !strcmp(*(const char **)(8LL * i + a2), *(const char **)(v10 + 8)) )
      {
        *a4 = i;
        return 0;
      }
    }
    *a4 = a5;
    return 6;
  }
  else
  {
    *a4 = a5;
    return 4;
  }
}
__int64 __fastcall sub_6462(__int64 a1, __int64 a2, int a3, __int64 a4, _DWORD *a5)
{
  int i; // [rsp+38h] [rbp-18h]
  int j; // [rsp+38h] [rbp-18h]
  int v11; // [rsp+3Ch] [rbp-14h]
  int v12; // [rsp+40h] [rbp-10h]
  int v13; // [rsp+44h] [rbp-Ch]
  __int64 v14; // [rsp+48h] [rbp-8h]

  v11 = 0;
  v12 = 0;
  for ( i = 0; i < a3; ++i )
    *(_DWORD *)(4LL * i + a4) = 0;
  v14 = sub_7C92(a1);
  if ( v14 )
  {
    do
    {
      v13 = 0;
      for ( j = 0; j < a3; ++j )
      {
        if ( !strcmp(*(const char **)(8LL * j + a2), *(const char **)(v14 + 8)) )
        {
          *(_DWORD *)(4LL * j + a4) = 1;
          ++v11;
          v13 = 1;
          break;
        }
      }
      if ( !v13 )
        ++v12;
      v14 = sub_7CC7();
    }
    while ( v14 );
    *a5 = v12;
    if ( v11 )
      return 0;
    else
      return 4;
  }
  else
  {
    *a5 = 0;
    return 4;
  }
}
__int64 __fastcall sub_6599(__int64 a1)
{
  if ( sub_7C92(a1) )
    return 0;
  else
    return 4;
}
__int64 __fastcall sub_65CE(__int64 a1, __int64 a2, int a3, __int64 a4, _DWORD *a5)
{
  return sub_6462(a1, a2, a3, a4, a5);
}
__int64 __fastcall sub_660D(__int64 a1, __int64 a2, int a3, _DWORD *a4, int a5)
{
  return sub_63B9(a1, a2, a3, a4, a5);
}
__int64 __fastcall sub_664B(_BYTE *a1, _BYTE *a2, int a3)
{
  _BYTE *v5; // [rsp+10h] [rbp-20h]
  _BYTE *v6; // [rsp+20h] [rbp-10h]
  _BYTE *j; // [rsp+20h] [rbp-10h]
  _BYTE *i; // [rsp+28h] [rbp-8h]

  v5 = a2;
  v6 = (_BYTE *)qword_C588;
  while ( 1 )
  {
    if ( !*v6 )
    {
      if ( a3 )
        *a2 = 0;
      return 4;
    }
    for ( i = a1; *v6 == *i; ++i )
    {
      if ( !*v6 && !*i )
        return 4;
      ++v6;
    }
    if ( !*i && *v6 == 61 )
    {
      for ( j = v6 + 1; *j != 59 && *j && a3 > 1; ++j )
      {
        *v5++ = *j;
        --a3;
      }
      if ( a3 > 0 )
        *v5 = 0;
      return *j != 59 && *j;
    }
    while ( *v6 && *v6 != 59 )
      ++v6;
    if ( !*v6 )
      break;
    ++v6;
    while ( *v6 && ((*__ctype_b_loc())[(char)*v6] & 0x2000) != 0 )
      ++v6;
  }
  if ( a3 )
    *a2 = 0;
  return 4;
}
__int64 __fastcall sub_67EA(_BYTE *a1, int *a2, int a3)
{
  unsigned int v5; // [rsp+2Ch] [rbp-114h]
  char nptr[264]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v7; // [rsp+138h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v5 = sub_664B(a1, nptr, 256);
  if ( v5 )
    *a2 = a3;
  else
    *a2 = atoi(nptr);
  return v5;
}
unsigned __int64 __fastcall sub_688E(__int64 a1, int a2, unsigned int a3, __int64 a4, __int64 a5)
{
  char s[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v10; // [rsp+128h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  sprintf(s, "%d", a2);
  sub_693B(a1, s, a3, a4, a5, 0);
  return v10 - __readfsqword(0x28u);
}
unsigned __int64 __fastcall sub_693B(const char *a1, const char *a2, int a3, const char *a4, const char *a5, char a6)
{
  const char *v6; // rcx
  const char *v7; // rdx
  const char *v8; // rax
  time_t timer; // [rsp+30h] [rbp-50h] BYREF
  time_t v15; // [rsp+38h] [rbp-48h] BYREF
  struct tm *v16; // [rsp+40h] [rbp-40h]
  unsigned __int64 v17; // [rsp+48h] [rbp-38h]

  v17 = __readfsqword(0x28u);
  time(&timer);
  v15 = a3 + timer;
  v16 = gmtime(&v15);
  if ( (a6 & 4) != 0 )
    v6 = "; SameSite=Strict";
  else
    v6 = (const char *)&unk_92E4;
  if ( (a6 & 2) != 0 )
    v7 = "; HttpOnly";
  else
    v7 = (const char *)&unk_92E4;
  if ( (a6 & 1) != 0 )
    v8 = "; Secure";
  else
    v8 = (const char *)&unk_92E4;
  fprintf(
    s,
    "Set-Cookie: %s=%s; domain=%s; expires=%s, %02d-%s-%04d %02d:%02d:%02d GMT; path=%s%s%s%s\r\n",
    a1,
    a2,
    a5,
    off_C040[v16->tm_wday],
    v16->tm_mday,
    (&off_C080)[v16->tm_mon],
    v16->tm_year + 1900,
    v16->tm_hour,
    v16->tm_min,
    v16->tm_sec,
    a4,
    v8,
    v7,
    v6);
  return v17 - __readfsqword(0x28u);
}
unsigned __int64 __fastcall sub_6AC3(const char *a1, const char *a2, int a3, const char *a4, const char *a5)
{
  return sub_693B(a1, a2, a3, a4, a5, 0);
}
int __fastcall sub_6B09(const char *a1)
{
  return fprintf(s, "Location: %s\r\n\r\n", a1);
}
int __fastcall sub_6B3E(int a1, const char *a2)
{
  return fprintf(s, "Status: %d %s\r\n\r\n", a1, a2);
}
int __fastcall sub_6B76(const char *a1)
{
  return fprintf(s, "Content-type: %s\r\n\r\n", a1);
}
__int64 __fastcall sub_6BAB(const char *a1)
{
  int v2; // eax
  int v3; // [rsp+14h] [rbp-42Ch] BYREF
  FILE **v4; // [rsp+18h] [rbp-428h] BYREF
  __int64 *i; // [rsp+20h] [rbp-420h]
  FILE *s; // [rsp+28h] [rbp-418h]
  _BYTE ptr[1032]; // [rsp+30h] [rbp-410h] BYREF
  unsigned __int64 v8; // [rsp+438h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  s = fopen(a1, "wb");
  if ( !s )
    return 0;
  if ( (unsigned int)sub_7151(s, "CGIC2.0")
    && (unsigned int)sub_7151(s, ::ptr)
    && (unsigned int)sub_7151(s, qword_C108)
    && (unsigned int)sub_7151(s, qword_C110)
    && (unsigned int)sub_7151(s, qword_C118)
    && (unsigned int)sub_7151(s, qword_C120)
    && (unsigned int)sub_7151(s, qword_C128)
    && (unsigned int)sub_7151(s, qword_C130)
    && (unsigned int)sub_7151(s, qword_C138)
    && (unsigned int)sub_7151(s, qword_C140)
    && (unsigned int)sub_7151(s, qword_C148)
    && (unsigned int)sub_7151(s, qword_C150)
    && (unsigned int)sub_7151(s, qword_C158)
    && (unsigned int)sub_7151(s, qword_C160)
    && (unsigned int)sub_7151(s, qword_C168)
    && (unsigned int)sub_7151(s, qword_C170)
    && (unsigned int)sub_7151(s, dest)
    && (unsigned int)sub_7151(s, qword_C598)
    && (unsigned int)sub_7151(s, qword_C5A0)
    && (unsigned int)sub_7151(s, qword_C5A8)
    && (unsigned int)sub_7151(s, qword_C588)
    && (unsigned int)sub_71B3(s, (unsigned int)dword_C590) )
  {
    for ( i = (__int64 *)qword_C5C8; i; i = (__int64 *)i[6] )
    {
      if ( !(unsigned int)sub_7151(s, *i)
        || !(unsigned int)sub_7151(s, i[1])
        || !(unsigned int)sub_7151(s, i[3])
        || !(unsigned int)sub_7151(s, i[4])
        || !(unsigned int)sub_71B3(s, *((unsigned int *)i + 4)) )
      {
        goto LABEL_42;
      }
      if ( (unsigned int)sub_5B5E(*i, &v4) )
      {
        if ( !(unsigned int)sub_71B3(s, 0) )
          goto LABEL_42;
      }
      else
      {
        if ( !(unsigned int)sub_71B3(s, 1) )
        {
LABEL_33:
          sub_5CC9(v4);
          goto LABEL_42;
        }
        while ( !(unsigned int)sub_5C5B(v4, ptr, 1024, &v3) )
        {
          v2 = fwrite(ptr, 1u, v3, s);
          if ( v2 != v3 )
            goto LABEL_33;
        }
        if ( (unsigned int)sub_5CC9(v4) )
          goto LABEL_42;
      }
    }
    fclose(s);
    return 2;
  }
  else
  {
LABEL_42:
    fclose(s);
    unlink(a1);
    return 0;
  }
}
_BOOL8 __fastcall sub_7151(FILE *a1, const char *a2)
{
  unsigned int v3; // [rsp+1Ch] [rbp-4h]

  v3 = strlen(a2);
  sub_71B3(a1, v3);
  return v3 == (unsigned int)fwrite(a2, 1u, (int)v3, a1);
}
_BOOL8 __fastcall sub_71B3(FILE *a1, int a2)
{
  int ptr; // [rsp+4h] [rbp-Ch] BYREF
  FILE *s; // [rsp+8h] [rbp-8h]

  s = a1;
  ptr = a2;
  return fwrite(&ptr, 4u, 1u, a1) != 0;
}
__int64 __fastcall sub_71F6(const char *a1)
{
  int v2; // eax
  int v3; // [rsp+14h] [rbp-44Ch] BYREF
  unsigned int v4; // [rsp+18h] [rbp-448h]
  int v5; // [rsp+1Ch] [rbp-444h]
  int v6; // [rsp+20h] [rbp-440h]
  int v7; // [rsp+24h] [rbp-43Ch]
  char *s1; // [rsp+28h] [rbp-438h] BYREF
  FILE *v9; // [rsp+30h] [rbp-430h] BYREF
  void *s; // [rsp+38h] [rbp-428h]
  _QWORD *i; // [rsp+40h] [rbp-420h]
  FILE *stream; // [rsp+48h] [rbp-418h]
  _BYTE ptr[1032]; // [rsp+50h] [rbp-410h] BYREF
  unsigned __int64 v14; // [rsp+458h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  s = 0;
  v4 = 0;
  sub_56E8();
  stream = fopen(a1, "rb");
  if ( !stream )
    return 0;
  if ( (unsigned int)sub_79EE(stream, &s1) )
  {
    if ( strcmp(s1, "CGIC2.0") )
    {
      free(s1);
      return 3;
    }
    free(s1);
    if ( (unsigned int)sub_79EE(stream, &::ptr)
      && (unsigned int)sub_79EE(stream, &qword_C108)
      && (unsigned int)sub_79EE(stream, &qword_C110)
      && (unsigned int)sub_79EE(stream, &qword_C118)
      && (unsigned int)sub_79EE(stream, &qword_C120)
      && (unsigned int)sub_79EE(stream, &qword_C128)
      && (unsigned int)sub_79EE(stream, &qword_C130)
      && (unsigned int)sub_79EE(stream, &qword_C138)
      && (unsigned int)sub_79EE(stream, &qword_C140)
      && (unsigned int)sub_79EE(stream, &qword_C148)
      && (unsigned int)sub_79EE(stream, &qword_C150)
      && (unsigned int)sub_79EE(stream, &qword_C158)
      && (unsigned int)sub_79EE(stream, &qword_C160)
      && (unsigned int)sub_79EE(stream, &qword_C168)
      && (unsigned int)sub_79EE(stream, &qword_C170)
      && (unsigned int)sub_79EE(stream, &dest)
      && (unsigned int)sub_79EE(stream, &qword_C598)
      && (unsigned int)sub_79EE(stream, &qword_C5A0)
      && (unsigned int)sub_79EE(stream, &qword_C5A8)
      && (unsigned int)sub_79EE(stream, &qword_C588)
      && (unsigned int)sub_7AB7(stream, &dword_C590) )
    {
      for ( i = 0; ; i = s )
      {
        s = calloc(1u, 0x38u);
        if ( !s )
        {
          sub_56E8();
          fclose(stream);
          return 1;
        }
        memset(s, 0, 0x38u);
        if ( !(unsigned int)sub_79EE(stream, s) )
        {
          free(s);
          fclose(stream);
          dword_C5C0 = 1;
          return 2;
        }
        if ( !(unsigned int)sub_79EE(stream, (char *)s + 8)
          || !(unsigned int)sub_79EE(stream, (char *)s + 24)
          || !(unsigned int)sub_79EE(stream, (char *)s + 32)
          || !(unsigned int)sub_7AB7(stream, (char *)s + 16)
          || !(unsigned int)sub_7AB7(stream, &v3) )
        {
          break;
        }
        if ( v3 )
        {
          v9 = 0;
          v5 = *((_DWORD *)s + 4);
          if ( (unsigned int)sub_431A(&v9) || !v9 )
          {
            v4 = 0;
            goto LABEL_55;
          }
          while ( v5 > 0 )
          {
            v6 = v5;
            if ( v5 > 1024 )
              v6 = 1024;
            v7 = fread(ptr, 1u, v6, stream);
            if ( v7 <= 0 || (v2 = fwrite(ptr, 1u, v7, v9), v7 != v2) )
            {
              v4 = 0;
              fclose(v9);
              goto LABEL_55;
            }
            v5 -= v7;
          }
          *((_QWORD *)s + 5) = v9;
        }
        else
        {
          *((_QWORD *)s + 5) = 0;
        }
        *((_QWORD *)s + 6) = 0;
        if ( i )
          i[6] = s;
        else
          qword_C5C8 = (__int64)s;
      }
      v4 = 1;
    }
  }
LABEL_55:
  sub_56E8();
  fclose(stream);
  if ( s )
  {
    if ( *(_QWORD *)s )
      free(*(void **)s);
    if ( *((_QWORD *)s + 1) )
      free(*((void **)s + 1));
    if ( *((_QWORD *)s + 3) )
      free(*((void **)s + 3));
    if ( *((_QWORD *)s + 4) )
      free(*((void **)s + 4));
    if ( *((_QWORD *)s + 5) )
      fclose(*((FILE **)s + 5));
    free(s);
  }
  return v4;
}
__int64 __fastcall sub_79EE(FILE *a1, void **a2)
{
  int v3; // eax
  int v4; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( !(unsigned int)sub_7AB7(a1, &v4) )
    return 0;
  *a2 = malloc(v4 + 1);
  if ( !*a2 )
    return 0;
  v3 = fread(*a2, 1u, v4, a1);
  if ( v3 != v4 )
    return 0;
  *((_BYTE *)*a2 + v4) = 0;
  return 1;
}
_BOOL8 __fastcall sub_7AB7(FILE *a1, void *a2)
{
  return fread(a2, 4u, 1u, a1) != 0;
}
_BOOL8 __fastcall sub_7AFB(_BYTE *a1, _BYTE *a2)
{
  int v3; // ebx

  while ( 1 )
  {
    if ( !*a1 )
      return *a2 == 0;
    if ( !*a2 )
      return 0;
    if ( ((*__ctype_b_loc())[(char)*a1] & 0x400) == 0 )
      break;
    v3 = tolower((char)*a1);
    if ( v3 != tolower((char)*a2) )
      return 0;
LABEL_10:
    ++a1;
    ++a2;
  }
  if ( *a1 == *a2 )
    goto LABEL_10;
  return 0;
}
__int64 __fastcall sub_7BD1(_BYTE *a1, _BYTE *a2)
{
  int v3; // ebx

  while ( 1 )
  {
    if ( !*a2 )
      return 1;
    if ( !*a1 )
      return 0;
    if ( ((*__ctype_b_loc())[(char)*a1] & 0x400) == 0 )
      break;
    v3 = tolower((char)*a1);
    if ( v3 != tolower((char)*a2) )
      return 0;
LABEL_10:
    ++a1;
    ++a2;
  }
  if ( *a1 == *a2 )
    goto LABEL_10;
  return 0;
}
__int64 __fastcall sub_7C92(char *a1)
{
  qword_C9E0 = a1;
  qword_C9E8 = qword_C5C8;
  return sub_7CC7();
}
const char **sub_7CC7()
{
  const char **v1; // [rsp+8h] [rbp-8h]

  while ( qword_C9E8 )
  {
    v1 = (const char **)qword_C9E8;
    qword_C9E8 = *(_QWORD *)(qword_C9E8 + 48);
    if ( !strcmp(*v1, qword_C9E0) )
      return v1;
  }
  return 0;
}
__int64 __fastcall sub_7D25(const char *a1)
{
  return (unsigned int)a1[(int)strspn(a1, " \n\r\t")];
}
void __fastcall sub_7D63(void **a1)
{
  void **v1; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+10h] [rbp-10h]

  v1 = a1;
  for ( ptr = *a1; ptr; ptr = *v1 )
  {
    free(ptr);
    ++v1;
  }
  free(a1);
}
__int64 __fastcall sub_7DBA(void ***a1)
{
  int j; // [rsp+10h] [rbp-30h]
  int v3; // [rsp+10h] [rbp-30h]
  int v4; // [rsp+14h] [rbp-2Ch]
  _BYTE *i; // [rsp+18h] [rbp-28h]
  _BYTE *v6; // [rsp+18h] [rbp-28h]
  void **v7; // [rsp+20h] [rbp-20h]
  _BYTE *src; // [rsp+28h] [rbp-18h]

  v4 = 0;
  for ( i = (_BYTE *)qword_C588; *i; ++i )
  {
    if ( *i == 61 )
      ++v4;
  }
  v7 = (void **)malloc(8LL * (v4 + 1));
  if ( v7 )
  {
    for ( j = 0; j <= v4; ++j )
      v7[j] = 0;
    v3 = 0;
    v6 = (_BYTE *)qword_C588;
    while ( *v6 )
    {
      while ( *v6 && ((*__ctype_b_loc())[(char)*v6] & 0x2000) != 0 )
        ++v6;
      src = v6;
      while ( *v6 && *v6 != 61 )
        ++v6;
      if ( v6 != src )
      {
        v7[v3] = malloc(v6 - src + 1);
        if ( !v7[v3] )
        {
          sub_7D63(v7);
          *a1 = 0;
          return 7;
        }
        memcpy(v7[v3], src, v6 - src);
        *((_BYTE *)v7[v3++] + v6 - src) = 0;
      }
      while ( *v6 && *v6 != 59 )
        ++v6;
      if ( !*v6 )
        break;
      if ( *v6 == 59 )
        ++v6;
    }
    *a1 = v7;
    return 0;
  }
  else
  {
    *a1 = 0;
    return 7;
  }
}
__int64 __fastcall sub_800A(void ***a1)
{
  int k; // [rsp+18h] [rbp-38h]
  int v3; // [rsp+18h] [rbp-38h]
  int v4; // [rsp+1Ch] [rbp-34h]
  __int64 i; // [rsp+20h] [rbp-30h]
  __int64 v6; // [rsp+20h] [rbp-30h]
  __int64 j; // [rsp+28h] [rbp-28h]
  __int64 m; // [rsp+28h] [rbp-28h]
  void **v9; // [rsp+30h] [rbp-20h]
  size_t size; // [rsp+38h] [rbp-18h]

  v4 = 0;
  for ( i = qword_C5C8; i; i = *(_QWORD *)(i + 48) )
  {
    for ( j = qword_C5C8; j != i; j = *(_QWORD *)(j + 48) )
    {
      if ( !strcmp(*(const char **)i, *(const char **)j) )
        goto LABEL_7;
    }
    ++v4;
LABEL_7:
    ;
  }
  v9 = (void **)malloc(8LL * (v4 + 1));
  if ( v9 )
  {
    for ( k = 0; k <= v4; ++k )
      v9[k] = 0;
    v6 = qword_C5C8;
    v3 = 0;
    while ( v6 )
    {
      for ( m = qword_C5C8; m != v6; m = *(_QWORD *)(m + 48) )
      {
        if ( !strcmp(*(const char **)v6, *(const char **)m) )
          goto LABEL_22;
      }
      size = strlen(*(const char **)v6) + 1;
      v9[v3] = malloc(size);
      if ( !v9[v3] )
      {
        sub_7D63(v9);
        *a1 = 0;
        return 7;
      }
      strcpy((char *)v9[v3++], *(const char **)v6);
LABEL_22:
      v6 = *(_QWORD *)(v6 + 48);
    }
    *a1 = v9;
    return 0;
  }
  else
  {
    *a1 = 0;
    return 7;
  }
}
__int64 __fastcall sub_821A(_BYTE *a1, int a2)
{
  while ( a2-- )
  {
    switch ( *a1 )
    {
      case '<':
        if ( putc(38, s) == -1 )
          return 12;
        if ( putc(108, s) == -1 )
          return 12;
        if ( putc(116, s) == -1 )
          return 12;
        if ( putc(59, s) == -1 )
          return 12;
        break;
      case '&':
        if ( putc(38, s) == -1 )
          return 12;
        if ( putc(97, s) == -1 )
          return 12;
        if ( putc(109, s) == -1 )
          return 12;
        if ( putc(112, s) == -1 )
          return 12;
        if ( putc(59, s) == -1 )
          return 12;
        break;
      case '>':
        if ( putc(38, s) == -1 )
          return 12;
        if ( putc(103, s) == -1 )
          return 12;
        if ( putc(116, s) == -1 )
          return 12;
        if ( putc(59, s) == -1 )
          return 12;
        break;
      default:
        if ( putc((char)*a1, s) == -1 )
          return 12;
        break;
    }
    ++a1;
  }
  return 0;
}
__int64 __fastcall sub_846C(char *a1)
{
  int v1; // eax

  v1 = strlen(a1);
  return sub_821A(a1, v1);
}
__int64 __fastcall sub_849A(_BYTE *a1, int a2)
{
  while ( a2-- )
  {
    if ( *a1 == 34 )
    {
      if ( putc(38, s) == -1 )
        return 12;
      if ( putc(35, s) == -1 )
        return 12;
      if ( putc(51, s) == -1 )
        return 12;
      if ( putc(52, s) == -1 )
        return 12;
      if ( putc(59, s) == -1 )
        return 12;
    }
    else if ( putc((char)*a1, s) == -1 )
    {
      return 12;
    }
    ++a1;
  }
  return 0;
}
__int64 __fastcall sub_85AE(char *a1)
{
  int v1; // eax

  v1 = strlen(a1);
  return sub_849A(a1, v1);
}