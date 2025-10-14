unsigned __int64 menu()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("1. Add book");
  puts("2. Remove book");
  puts("3. Show book content");
  puts("4. Exit");
  printf("> ");
  return v1 - __readfsqword(0x28u);
}

int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // ebx
  int choice; // [rsp+Ch] [rbp-24h] BYREF
  int size; // [rsp+10h] [rbp-20h] BYREF
  unsigned int idx; // [rsp+14h] [rbp-1Ch] BYREF
  unsigned __int64 v7; // [rsp+18h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  puts("Welcome to book factory!");
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &choice);
    if ( choice == 4 )
    {
      puts("Goodbye!");
      exit(0);
    }
    if ( choice > 4 )
      goto LABEL_22;
    switch ( choice )
    {
      case 3:
        printf("Enter index of book: ");
        __isoc99_scanf("%d", &idx);
        if ( idx >= 10 )
          goto Invalid;
        if ( *((_QWORD *)&book + 3 * (int)idx) == 1 )
          puts("No book at this index!");
        else
          printf("Content: %s\n", *((const char **)&unk_4070 + 3 * (int)idx));
        break;
      case 1:
        printf("Enter index of book: ");
        __isoc99_scanf("%d", &idx);
        if ( idx > 10 )
          goto Invalid;
        printf("Enter size of book: ");
        __isoc99_scanf("%d", &size);
        if ( size > 0 )
        {
          *((_QWORD *)&unk_4068 + 3 * (int)idx) = size;
          v3 = idx;
          *((_QWORD *)&unk_4070 + 3 * (int)v3) = malloc(size);
          if ( *((_QWORD *)&unk_4070 + 3 * (int)idx) )
          {
            printf("Enter content of book: ");
            read(0, *((void **)&unk_4070 + 3 * (int)idx), size);
            *((_QWORD *)&book + 3 * (int)idx) = 0;
          }
          else
          {
            puts("Memory allocation failed!");
          }
        }
        else
        {
          puts("Invalid size!");
        }
        break;
      case 2:
        printf("Enter index of book: ");
        __isoc99_scanf("%d", &idx);
        if ( idx <= 0xA )
        {
          free(*((void **)&unk_4070 + 3 * (int)idx));
          *((_QWORD *)&book + 3 * (int)idx) = 1;
          break;
        }
Invalid:
        puts("Invalid index!");
        break;
      default:
LABEL_22:
        puts("Invalid choice!");
        break;
    }
    getchar();
    fflush(stdin);
  }
}