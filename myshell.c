/* my shell, Jinho Kim(sunder990@naver.com), */
/* Dankook Univ. System Programming HW#2 Nov. 20, 2023 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/errno.h>
#include <fcntl.h>

#define MAXARGS 512 /* max argument size in a command line */
#define MAXBYTE 1024 /* max byte size (the number of characters) per line */
#define MAXJOBS 16  /* max job number running at any point in time */

/* job states */
#define UNDEF 0 /* undefined state */
#define FG 1 /* run in foreground */
#define BG 2 /* run in background */
#define ST 3 /* stopped */

/* global variables */
char cwd[1024] = ""; /* current working directory */
sigset_t empty_mask; /* unblock all signals */
volatile int job_cnt = 0;
struct job_t {
    pid_t pid; /* job's PID */
    int jid; /* job ID */
    int state; /* job's state */
    char cmdline[MAXBYTE]; /* command line */
};
struct job_t jobs[MAXJOBS]; /* list of jobs */

/* functions for executing commands */
void eval(char* cmdline); /* evaluate the command line */
int isempty_cmd(char* buf); /* checks if the cmdline only consists of spaces */
int parseline(char* buf, char** argv); /* parsing and building argv */
int builtin_cmd(char** argv); /* checks builtin-command */
void cd(const char* path); /* execute the builtin command cd */
void do_bgfg(char** argv); /* execute the builtin commands bg and fg */
int redirection(char** argv); /* checks redirection symbol and redirect the output */
void Dupe2(int to_fd, int from_fd); /* wrapper function of dupe2() */
void unix_error(char* msg); /* error handling function */
pid_t Fork(); /* wrapper function of fork() */
void Execvp(const char* pathname, char* const argv[]); /* wrapper function of execvp() */
void waitfg(sigset_t* prev_mask); /* wait for foreground job -> wrapper function for sigsuspend() */

/* functions for job control */
void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid);
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid);
int pid2jid(pid_t pid);
int jid2pid(int jid);
void listjobs(struct job_t *jobs);
/* these functions take the global variable jobs as an argument to clarify its functionality and avoid race condition   *
 * by working with the copied local variable instead of the actual global variable itself                               */

/* functions for signal handling */
typedef void(handler_t)(int); /* handler_t is a type for handlers */
handler_t* Signal(int signum, handler_t* handler); /* wrapper function of sigaction() */
void sigchld_handler(int sig); /* signal handler for SIGCHLD */
void sigint_handler(int sig); /* signal handler for SIGINT(ctrl-c) */
void sigtstp_handler(int sig); /* signal handler for SIGTSTP(ctrl-z) */


int main(){
    char cmdline[MAXBYTE];

    /* empty_mask will be used to temporarily unblock all signals */
    sigemptyset(&empty_mask);

    /* install signal handlers */
    Signal(SIGCHLD, sigchld_handler);
    Signal(SIGINT, sigint_handler);
    Signal(SIGTSTP, sigtstp_handler);

    /* initialize the job list */
    initjobs(jobs);

    while(1){
        printf("myshell:~%s$ ", cwd); /* print shell prompt including current working directory */
        fflush(stdout);
        fgets(cmdline, MAXBYTE, stdin); /* fgets also stores \n character at the end! */
        if(feof(stdin)) /* checking end of file of stdin */
            exit(0);
        /* evaluate command line */
        eval(cmdline);
    }
}

/* evaluate command line based on the conditions given; foreground/background, builtin/external */
void eval(char* cmdline){
    char* argv[MAXARGS]; /* argument vector */
    char buf[MAXBYTE]; /* we need buffer b/c strtok() in parseline function modifies original string */
    int isbg; /* background flag */
    pid_t pid;
    sigset_t mask, prev_mask; /* signal masks */

    strcpy(buf, cmdline);

    /* ignore blank command line input */
    if(isempty_cmd(buf))
        return;
    /* parse command line and build argument vector */
    isbg = parseline(buf, argv);

    if(!builtin_cmd(argv)){ /* If it's a builtin command, execute it. If not, create a child process */
        /* block SIGCHLD signal before fork */
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);

        /* if the job list is full, don't create a new job */
        if(job_cnt >= MAXJOBS){
            printf("trying to create too many jobs %d/%d", job_cnt, MAXJOBS);
            return;
        }

        /* child process */
        if((pid = Fork()) == 0){
            /* unblock SIGCHLD signal before execvp b/c child process inherits its parent's signal mask */
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            /* sets process group id to child's pid (shell creates separate process group for each job)*/
            setpgid(0, 0); /* a job's process group id is one of its parent processes' pid */
            redirection(argv);
            Execvp(argv[0], argv);
        }

        /* parent process */
        if(!isbg){/* foreground */
            if(addjob(jobs, pid, FG, cmdline)) /* if succeeded to add a job */
                waitfg(&prev_mask);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        }
        else{/* background */
            if(addjob(jobs, pid, BG, cmdline)) /* if succeeded to add a job */
                printf("[%d] (%d)\n", pid2jid(pid), pid);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        }
    }
}

/* return 1 if buf is a blank cmdline, 0 if not */
int isempty_cmd(char* buf){
    while(*buf == ' ' || *buf == '\t') ++buf; /* ignore leading spaces */
    if(*buf == '\n') /* if remaining character is \n after erasing all the blank characters, it's blank command line */
        return 1;
    return 0;
}

/* tokenize the command line and build argument vector, return background flag(1 -> background, 0 -> foreground) */
int parseline(char* buf, char** argv){
    int isbg = 0, argc = 0;
    buf[strlen(buf) - 1] = ' '; /* replace \n with a space, which helps simpler condition checking when tokenizing */

    /* tokenize buf string using strtok and build arguments vector */
    while((argv[argc] = strtok(buf, " "))){ /* mark the end of argument with NULL */
        buf = (buf + strlen(buf) + 1); /* updates the pointer to the starting character of the next token */
        while(*buf == ' ' || *buf == '\t') ++buf; /* ignore spaces */

        argc += 1;

        /* change ~ to home directory */
        if(*buf == '~') buf = strcat(getenv("HOME"), buf+1);
    }
    if((isbg = (*(argv[argc - 1]) == '&')))
        argv[--argc] = NULL; /* sets the background flag and replace '&' with NULL */

    return isbg;
}

/* return 1 for builtin commands, 0 for not-builtin */
int builtin_cmd(char** argv){
    char *cmd = argv[0];

    /* quit builtin command terminate this shell */
    if (!strcmp(cmd, "quit"))
        exit(0);
    /* cd builtin command change current working directory */
    else if (!strcmp(cmd, "cd")) {
        cd(argv[1]);
    }
    /* jobs builtin command print current job list */
    else if (!strcmp(cmd, "jobs")){
        listjobs(jobs);
    }
    /* bg %jid: change a stopped bg job to a running bg job
     * fg %jid: change a stopped or running bg job to a running fg job*/
    else if(!strcmp(cmd, "bg") || !strcmp(cmd, "fg")){
        do_bgfg(argv);
    }
    /* kill %jid: terminate a job */
    else if(!strcmp(cmd, "kill") && argv[1][0] == '%'){
        int jid = (int)strtol(argv[1] + 1, NULL, 10); /* convert %jid(str) to jid(int) */
        kill(-jid2pid(jid), 9); /* send kill signal to the job */
    }

    /* not a builtin command */
    else
        return 0;

    /* builtin command */
    return 1;
}

/* cd builtin command */
void cd(const char* path){
    int prev_errno = errno;

    /* if no directory argument, change to home directory */
    if(path == NULL) path = getenv("HOME");

    /* if chdir returns non-zero, it means an error occured */
    if(chdir(path)){
        if(errno == ENOENT)
            printf("cd: no such directory\n");
        else if(errno == ENOTDIR)
            printf("cd: argument is not in directory format\n");
        else if(errno == EACCES)
            printf("cd: failed to access the directory\n");
        else if(errno == EFAULT)
            printf("cd: directory is outside the allocated address space\n");
        return;
    }
    if(getcwd(cwd, sizeof(cwd)) == NULL){
        printf("cd: failed to get current working directory\n");
    }
    errno = prev_errno;
}

/* execute bg or fg builtin command */
void do_bgfg(char **argv){
    struct job_t *job;
    int jid, jid_flag = 0;
    pid_t pid;
    char* cmd = argv[0];

    /* ignore command that has no argument */
    if (argv[1] == NULL) {
        printf("%s command requires PID or %%jid argument\n", argv[0]);
        return;
    }

    /* parse the required PID or %jid arg */
    if (isdigit(argv[1][0])) { /* if first argument for the command is PID */
        pid = (pid_t)strtol(argv[1], NULL, 10);
        if (!(job = getjobpid(jobs, pid))) {
            printf("(%d): no such process\n", pid);
            return;
        }
    }
    else if (argv[1][0] == '%') { /* if first argument for the command is jid */
        jid = (int)strtol(argv[1] + 1, NULL, 10);
        jid_flag = 1; /* set the jid flag */
        if (!(job = getjobjid(jobs, jid))) {
            printf("%s: no such job\n", argv[1]);
            return;
        }
    }
    else { /* if first argument is neither PId nor jid */
        printf("%s: argument must be a PID or %%jid\n", argv[0]);
        return;
    }

    if(jid_flag) pid = job->pid; /* if the argument was jid, initialize pid */
    else jid = job->jid; /* if the argument was pid, initialize jid */

    /* bg command rerun the stopped background job as a background job */
    if (!strcmp(cmd, "bg")){
        if(kill(-pid , SIGCONT) < 0){
            printf("error: failed to send SIGCONT to (%d)", pid);
        }
        job->state = BG;
        printf("[%d] (%d) %s" , jid, pid, job->cmdline);
    }
    /* fg command changes a stopped or running background job to a running foreground job */
    else if(!strcmp(cmd, "fg")){
        if(kill(-pid , SIGCONT) < 0){
            printf("error: failed to send SIGCONT to [%d]", jid);
        }
        job->state = FG;
        waitfg(&empty_mask);
    }
}

/* redirect the output of a command */
/* return the number of redirections */
int redirection(char** argv){
    int redirect_cnt = 0; /* redirection count */
    int i;

    for(i = 0; argv[i] != NULL; i++){
        if(!strcmp(argv[i], ">")){ /* redirect stdout, overwriting */
            int out_fd = open(argv[i + 1], O_WRONLY | O_TRUNC | O_CREAT, 0644);
            Dupe2(out_fd, STDOUT_FILENO);
            close(out_fd);
            argv[i] = NULL;
            redirect_cnt++;
        }
        else if(!strcmp(argv[i], ">>")){ /* redirect stdout, appending */
            int out_fd = open(argv[i + 1], O_WRONLY | O_APPEND | O_CREAT, 0644);
            Dupe2(out_fd, STDOUT_FILENO);
            close(out_fd);
            argv[i] = NULL;
            redirect_cnt++;
        }
        else if(!strcmp(argv[i], "<")){ /* redirect stdin */
            int in_fd = open(argv[i + 1], O_RDONLY | O_CREAT, 0644);
            Dupe2(in_fd, STDIN_FILENO);
            close(in_fd);
            argv[i] = NULL;
            redirect_cnt++;
        }
    }
    return redirect_cnt;
}

void Dupe2(int to_fd, int from_fd){
    if(dup2(to_fd, from_fd) < 0){
        unix_error("dupe2: redirection failed\n");
    }
}

void unix_error(char* msg){
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(0);
}

pid_t Fork(){
    pid_t pid;
    if((pid = fork()) < 0)
        unix_error("fork error");
    return pid;
}

void Execvp(const char* pathname, char* const argv[]){
    if(execvp(pathname, argv) < 0){
        unix_error("command not found");
        exit(0);
    }
}

void waitfg(sigset_t* prev_mask){
    /* at any point in time, there is at most one foreground job */
    while(fgpid(jobs))
        sigsuspend(prev_mask);
}


/*************************
 * job control functions *
 *************************/

/* clear the entries in a job struct */
void clearjob(struct job_t *job){
    job->pid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initialize the job list */
void initjobs(struct job_t *jobs){
    int i = 0;
    while (i < MAXJOBS){
        clearjob(&jobs[i]);
        jobs[i].jid = i + 1; /* jobs are in increasing order */
        i++;
    }
}

/* add a job to the job list                           *
 * return 1 on success of adding the job, 0 on failure */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline){
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid == 0) {
            jobs[i].pid = pid;
            jobs[i].state = state;
            strcpy(jobs[i].cmdline, cmdline);
            job_cnt += 1;
            return 1;
        }
    }
    return 0;
}

/* delete a job whose PID=pid from the job list          *
 * return 1 on success of deleting the job, 0 on failure */
int deletejob(struct job_t *jobs, pid_t pid){
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++){
        if (jobs[i].pid == pid) {
            clearjob(&jobs[i]);
            job_cnt -= 1;
            return 1;
        }
    }
    return 0;
}

/* return PID of current foreground job, return 0 if no such job */
pid_t fgpid(struct job_t *jobs){
    int i;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].state == FG)
            return jobs[i].pid;
    return 0;
}

/* find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid){
    int i;

    if (pid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid)
            return &jobs[i];
    return NULL;
}

/* find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid){
    if (1 <= jid && jid <= MAXJOBS)
        return &jobs[jid - 1];
    else
        return NULL;
}

/* map process ID to job ID */
int pid2jid(pid_t pid){
    int i;

    if (pid < 1)
        return 0;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid) {
            return jobs[i].jid;
        }
    return 0;
}

/* map job ID to process ID */
int jid2pid(int jid){
    if (1 <= jid && jid <= MAXJOBS)
        return jobs[jid -1].pid; /* jobs are stored in increasing order */
    else
        return 0; /* no such job */
}

/* print the job list */
void listjobs(struct job_t *jobs){
    int i, job_cnt = 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid != 0) {
            job_cnt++;
            printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
            switch (jobs[i].state) {
                case BG:
                    printf("Running ");
                    break;
                case FG:
                    printf("Foreground ");
                    break;
                case ST:
                    printf("Stopped ");
                    break;
                default:
                    printf("error: job[%d].state=%d ", i, jobs[i].state);
            }
            printf("%s", jobs[i].cmdline);
        }
    }
    if(job_cnt == 0) printf("there is no job at this point\n");
}


/*****************************
 * signal handling functions *
 *****************************/

handler_t* Signal(int signum, handler_t* handler){
    struct sigaction action, old_action;
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask); //initialize signal set
    action.sa_flags = SA_RESTART; //restart syscalls if possible

    if(sigaction(signum, &action, &old_action) < 0) //set the handler
        unix_error("Signal error");

    return (old_action.sa_handler);
}


void sigchld_handler(int sig){
    int olderrno = errno; /* this handler can change errno */
    sigset_t mask_all, prev_all;
    pid_t pid;
    int status;

    sigfillset(&mask_all); /* add all the supported signals to mask_all */

    /* waiting for any child process to stop or terminate */
    /* return immediately if no child process has existed or changed state */
    while((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0){
        /* if the child process terminated normally */
        if(WIFEXITED(status)){
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all); //block all signals in case this handler to be interrupted before delete the job
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_all, NULL); //unblock all signals
        }
        /* if the child process stopped ex) by SIGTSTP */
        else if(WIFSTOPPED(status)){
            fprintf(stdout,"\nmysh: Job [%d] (%d) stopped by signal %d\n", pid2jid(pid),pid, WSTOPSIG(status));
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            getjobpid(jobs, pid)->state = ST;
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        }
        /* if the child process got terminated by the signal that is not caught in this handler ex) sig 9, SIGINT */
        else if(WIFSIGNALED(status)){
            fprintf(stdout,"\nmysh: Job [%d] (%d) terminated by signal %d\n",pid2jid(pid),pid, WTERMSIG(status));
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        }
    }
    errno = olderrno; /* restore the previous errno value */
}

/* send SIGINT to the foreground job (terminate the foreground job processes)*/
void sigint_handler(int sig){
    pid_t pid = fgpid(jobs);

    if(pid == 0){
        unix_error("\nno foreground job\n");
        return;
    }
    if(kill(-pid, SIGINT) < 0){
        unix_error("\nfailed to terminate foreground process\n");
        return;
    }
}

/* send SIGTSTP to the foreground job (suspend the foreground job processes) */
void sigtstp_handler(int sig){
    pid_t pid = fgpid(jobs);

    if(pid == 0){
        unix_error("\nno foreground job\n");
        return;
    }
    if(kill(-pid, SIGTSTP) < 0){
        unix_error("\nfailed to stop foreground process\n");
        return;
    }
}
