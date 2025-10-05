set pagination off
set disassemble-next-line on

# theo dõi fork/exec và giữ cả cha lẫn con
set follow-fork-mode child
set detach-on-fork off
set follow-exec-mode new

# đừng dừng vì SIGCHLD
handle SIGCHLD nostop noprint pass

# Bắt exec (glibc wrapper) và cả syscall execve
catch exec
catch syscall execve

# Khi bắt execve: chỉ dừng nếu filename là controller.cgi
commands
  silent
  # Trên x86_64 Linux: execve(filename=rdi, argv=rsi, envp=rdx)
  printf "\n[execve] filename=%s\n", (char*)$rdi
  if (strcmp((char*)$rdi, "/usr/local/apache2/cgi-bin/controller.cgi") != 0)
    continue
  end
end
