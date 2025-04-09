#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#ifdef __APPLE__
  #include <util.h>  // For macOS
#else
  #include <pty.h>   // For Linux
#endif

// cc -o ssh_pty_wrapper ssh_pty_wrapper.c -lutil

int main(int argc, char *argv[]) {
    pid_t pid;
    int master;
    char **ssh_args;
    int i, j;
    
    // Create space for SSH command and args
    ssh_args = malloc((argc + 1) * sizeof(char *));
    
    // First arg is path to ssh
    ssh_args[0] = "/usr/bin/ssh";
    
    // Copy remaining args
    for (i = 1; i < argc; i++) {
        ssh_args[i] = argv[i];
    }
    ssh_args[argc] = NULL;
    
    // Open a pseudo-terminal
    pid = forkpty(&master, NULL, NULL, NULL);
    
    if (pid < 0) {
        perror("forkpty failed");
        return 1;
    }
    
    if (pid == 0) {
        // Child process
        execv("/usr/bin/ssh", ssh_args);
        perror("execv failed");
        exit(1);
    }
    
    // Parent process - relay data between SSH and std I/O
    fd_set read_fds;
    char buffer[4096];
    int nread;
    
    // Set master fd to non-blocking
    fcntl(master, F_SETFL, fcntl(master, F_GETFL) | O_NONBLOCK);
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(master, &read_fds);
        
        if (select(master + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select failed");
            break;
        }
        
        // Data from SSH to stdout
        if (FD_ISSET(master, &read_fds)) {
            nread = read(master, buffer, sizeof(buffer));
            if (nread <= 0) break;
            write(STDOUT_FILENO, buffer, nread);
        }
        
        // Data from stdin to SSH
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            nread = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (nread <= 0) break;
            write(master, buffer, nread);
        }
    }
    
    free(ssh_args);
    return 0;
}