/* futex_demo.c

  Usage: futex_demo [nloops]
                   (Default: 5)

  Demonstrate the use of futexes in a program where parent and child
  use a pair of futexes located inside a shared anonymous mapping to
  synchronize access to a shared resource: the terminal. The two
  processes each write 'num-loops' messages to the terminal and employ
  a synchronization protocol that ensures that they alternate in
  writing messages.
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/time.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                       } while (0)

static int *futex1, *futex2, *iaddr;

static int
futex(int *uaddr, int futex_op, int val,
     const struct timespec *timeout, int *uaddr2, int val3)
{
   return syscall(SYS_futex, uaddr, futex_op, val,
                  timeout, uaddr, val3);
}

/* Acquire the futex pointed to by 'futexp': wait for its value to
  become 1, and then set the value to 0. */

static void
fwait(int *futexp)
{
   int s;

   /* atomic_compare_exchange_strong(ptr, oldval, newval)
      atomically performs the equivalent of:

          if (*ptr == *oldval)
              *ptr = newval;

      It returns true if the test yielded true and *ptr was updated. */

   while (1) {

       /* Is the futex available? */
       const int one = 1;
       if (atomic_compare_exchange_strong(futexp, &one, 0))
           break;      /* Yes */

       /* Futex is not available; wait */
        printf("%d\n", (*futexp));
       s = futex(futexp, FUTEX_WAIT, 0, NULL, NULL, 0);
       if (s == -1 && errno != EAGAIN)
           errExit("futex-FUTEX_WAIT");
   }
}

/* Release the futex pointed to by 'futexp': if the futex currently
  has the value 0, set its value to 1 and the wake any futex waiters,
  so that if the peer is blocked in fpost(), it can proceed. */

static void
fpost(int *futexp)
{
   int s;

   /* atomic_compare_exchange_strong() was described in comments above */

   const int zero = 0;
   if (atomic_compare_exchange_strong(futexp, &zero, 1)) {
       s = futex(futexp, FUTEX_WAKE, 1, NULL, NULL, 0);
       if (s  == -1)
           errExit("futex-FUTEX_WAKE");
   }
}

int
main(int argc, char *argv[])
{
   pid_t childPid;
   int j, nloops;

   setbuf(stdout, NULL);

   nloops = (argc > 1) ? atoi(argv[1]) : 5;

   /* Create a shared anonymous mapping that will hold the futexes.
      Since the futexes are being shared between processes, we
      subsequently use the "shared" futex operations (i.e., not the
      ones suffixed "_PRIVATE") */

   iaddr = mmap(NULL, sizeof(int) * 2, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_SHARED, -1, 0);
   if (iaddr == MAP_FAILED)
       errExit("mmap");

   futex1 = &iaddr[0];
   futex2 = &iaddr[1];

   *futex1 = 0;        /* State: unavailable */
   *futex2 = 1;        /* State: available */

   /* Create a child process that inherits the shared anonymous
      mapping */

   childPid = fork();
   if (childPid == -1)
       errExit("fork");

   if (childPid == 0) {        /* Child */
       for (j = 0; j < 2; j++) {
           fwait(futex1);
           printf("Child  (%ld) %d\n", (long) getpid(), j);
           fpost(futex2);
       }

       exit(EXIT_SUCCESS);
   }

   /* Parent falls through to here */

   for (j = 0; j < nloops; j++) {
       fwait(futex2);
       printf("Parent (%ld) %d\n", (long) getpid(), j);
       fpost(futex1);
   }

   wait(NULL);

   exit(EXIT_SUCCESS);
}