unsigned __int64 __fastcall std::random_device::random_device(std::random_device *this)
{
  char v2; // [rsp+17h] [rbp-49h] BYREF
  char *v3; // [rsp+18h] [rbp-48h]
  _BYTE v4[40]; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  v3 = &v2;
  std::string::basic_string<std::allocator<char>>(v4, "default", &v2);
  std::random_device::_M_init(this, v4);
  std::string::~string(v4);
  std::__new_allocator<char>::~__new_allocator(&v2);
  return v5 - __readfsqword(0x28u);
}

unsigned __int64 __fastcall generate_random_permutation(int *a1, int a2)
{
  unsigned int v2; // eax
  int i; // [rsp+1Ch] [rbp-2734h]
  _BYTE v5[1832]; // [rsp+20h] [rbp-2730h] BYREF
  _BYTE v6[920]; // [rsp+13B0h] [rbp-13A0h] BYREF
  unsigned __int64 v7; // [rsp+2738h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  for ( i = 0; i < a2; ++i )
    a1[i] = i + 1;
  std::random_device::random_device((std::random_device *)v5);
  v2 = std::random_device::operator()(v5);
  std::mersenne_twister_engine<unsigned long,32ul,624ul,397ul,31ul,2567483615ul,11ul,4294967295ul,7ul,2636928640ul,15ul,4022730752ul,18ul,1812433253ul>::mersenne_twister_engine(
    v6,
    v2);
  std::shuffle<int *,std::mersenne_twister_engine<unsigned long,32ul,624ul,397ul,31ul,2567483615ul,11ul,4294967295ul,7ul,2636928640ul,15ul,4022730752ul,18ul,1812433253ul> &>(
    a1,
    &a1[a2],
    v6);
  std::random_device::~random_device((std::random_device *)v5);
  return v7 - __readfsqword(0x28u);
}

__int64 __fastcall std::vector<int>::operator[](_QWORD *a1, __int64 a2)
{
  return 4 * a2 + *a1;
}

void __noreturn check_answer(void)
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  _DWORD *v4; // rax
  char v5; // [rsp+7h] [rbp-279h] BYREF
  int v6; // [rsp+8h] [rbp-278h] BYREF
  int i; // [rsp+Ch] [rbp-274h]
  int j; // [rsp+10h] [rbp-270h]
  int k; // [rsp+14h] [rbp-26Ch]
  char *v10; // [rsp+18h] [rbp-268h]
  _BYTE v11[32]; // [rsp+20h] [rbp-260h] BYREF
  _BYTE v12[32]; // [rsp+40h] [rbp-240h] BYREF
  _BYTE v13[256]; // [rsp+60h] [rbp-220h] BYREF
  _QWORD v14[36]; // [rsp+160h] [rbp-120h] BYREF

  v14[33] = __readfsqword(0x28u);
  v10 = &v5;
  v6 = 0;
  std::vector<int>::vector(v11, 100, &v6, &v5);
  std::__new_allocator<int>::~__new_allocator(&v5);
  for ( i = 0; i <= 99; ++i )
  {
    v0 = std::vector<int>::operator[](v11, i);
    std::istream::operator>>(&std::cin, v0);
  }
  std::operator<<<std::char_traits<char>>(&std::cout, "<index> <correct_answer> <your_answer>\n");
  for ( j = 0; j <= 99; ++j )
  {
    v1 = std::ostream::operator<<();
    std::operator<<<std::char_traits<char>>(v1, " ");
    v2 = std::ostream::operator<<();
    std::operator<<<std::char_traits<char>>(v2, " ");
    std::vector<int>::operator[](v11, j);
    v3 = std::ostream::operator<<();
    std::operator<<<std::char_traits<char>>(v3, "\n");
  }
  for ( k = 0; k <= 99; ++k )
  {
    v4 = (_DWORD *)std::vector<int>::operator[](v11, k);
    if ( *v4 != arr[k] )
    {
      std::operator<<<std::char_traits<char>>(&std::cout, "Wrong answer");
      std::ostream::operator<<();
      exit(1);
    }
  }
  std::ifstream::basic_ifstream(v13, "flag.txt", 8);
  if ( (unsigned __int8)std::ios::operator!(v14) )
  {
    std::operator<<<std::char_traits<char>>(
      &std::cout,
      "If you're running this locally, you should create a flag.txt file in the same folder.");
    std::ostream::operator<<();
    exit(1);
  }
  std::string::basic_string(v12);
  std::getline<char,std::char_traits<char>,std::allocator<char>>(v13, v12);
  std::operator<<<std::char_traits<char>>(&std::cout, "Congratulations! Here's your flag:");
  std::ostream::operator<<();
  std::operator<<<char>(&std::cout, v12);
  std::ostream::operator<<();
  exit(0);
}

unsigned __int64 question(void)
{
  int i; // [rsp+4h] [rbp-7Ch]
  int j; // [rsp+8h] [rbp-78h]
  _BYTE v3[104]; // [rsp+10h] [rbp-70h]
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(query, 0, 0x65u);
  fgets(query, 184, _bss_start);
  query[strcspn(query, "\n")] = 0;
  if ( (unsigned int)strlen(query) != 100 )
  {
    std::operator<<<std::char_traits<char>>();
    std::ostream::operator<<();
    std::operator<<<std::char_traits<char>>();
    exit(1);
  }
  for ( i = 0; i <= 99; ++i )
  {
    if ( query[i] != 48 && query[i] != 49 )
    {
      std::operator<<<std::char_traits<char>>();
      exit(1);
    }
  }
  for ( j = 0; j <= 99; ++j )
    v3[j] = query[arr[j] - 1];
  v3[100] = 0;
  std::operator<<<std::char_traits<char>>();
  std::ostream::operator<<();
  return v4 - __readfsqword(0x28u);
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+3h] [rbp-Dh] BYREF
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(40u);
  generate_random_permutation(arr, 100);
  std::ostream::operator<<(&std::cout, 100);
  std::ostream::operator<<();
  for ( i = 0; i <= 6; ++i )
  {
    std::operator>><char,std::char_traits<char>>(&std::cin, &v4);
    std::istream::ignore((std::istream *)&std::cin, 1);
    if ( v4 == 33 )
      check_answer();
    if ( v4 != 63 )
    {
      std::operator<<<std::char_traits<char>>(&std::cout, "Wrong choice");
      std::ostream::operator<<();
      exit(1);
    }
    question();
  }
  return 0;
}