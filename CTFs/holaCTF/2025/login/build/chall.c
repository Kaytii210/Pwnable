void *sub_4011F0()
{
  return &unk_404088;
}

void *sub_401260()
{
  void *result; // rax

  if ( !byte_4040C8 )
  {
    result = sub_4011F0();
    byte_4040C8 = 1;
  }
  return result;
}

__int64 sub_401290()
{
  return 0;
}

int sub_401296()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  return setvbuf(stderr, 0, 2, 0);
}

int sub_4012FB()
{
  puts("1. Login");
  puts("2. Change password");
  return puts("3. Exit");
}

__int64 __fastcall sub_401333(_BYTE *a1, _BYTE *a2)
{
  while ( *a1 && *a2 )
  {
    if ( *a1 != *a2 )
      return 0;
    ++a1;
    ++a2;
  }
  return 1;
}

__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+8h] [rbp-58h] BYREF
  int v5; // [rsp+Ch] [rbp-54h]
  _BYTE dest[16]; // [rsp+10h] [rbp-50h] BYREF
  char buf[56]; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v8; // [rsp+58h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  sub_401296(a1, a2, a3);
  qword_4040D8 = __readfsqword(0x28u);
  LOBYTE(qword_4040D8) = -1;
  memcpy(dest, &qword_4040D8, sizeof(dest));
  while ( 1 )
  {
    sub_4012FB();
    printf("Your choice: ");
    __isoc99_scanf("%d", &v4);
    getchar();
    if ( v4 == 3 )
      return 0;
    if ( v4 > 3 )
      goto LABEL_16;
    if ( v4 == 1 )
    {
      puts("Enter your password:");
      read(0, buf, 0x32u);
      if ( (unsigned int)sub_401333(buf, dest) )
      {
        dword_4040D0 = 1;
        puts("Login successfully!");
      }
      else
      {
        puts("Login failed!");
      }
    }
    else if ( v4 == 2 )
    {
      if ( dword_4040D0 )
      {
        fflush(stdin);
        puts("Enter your input:");
        gets(buf);
        v5 = strlen(buf);
        if ( v5 > 16 )
        {
          puts("BOF dectected!");
          exit(0);
        }
        memcpy(dest, buf, v5);
        puts("Changed password successfully!");
      }
      else
      {
        puts("This function is only for logged in users!");
      }
    }
    else
    {
LABEL_16:
      puts("Invalid choice!");
    }
  }
}