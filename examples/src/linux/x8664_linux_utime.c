#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <fcntl.h>            /* Definition of AT_* constants */
#include <sys/stat.h>
#include <utime.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>

int main(int argc, char **argv){
	/*
	   struct utimbuf {
	   time_t atime;       	
	   time_t modtime;   
	 */
	srand(0x1337);
	struct timespec utimensat_times[2];
	struct timespec atime; 
	struct timespec mtime;
	atime.tv_sec = rand();
	atime.tv_nsec = rand();
	mtime.tv_sec = rand();
	mtime.tv_nsec = rand() & 0xffff; // avoid illegal arg error
	utimensat_times[0] = atime;
	utimensat_times[1] = mtime;
	int res = utimensat(AT_FDCWD, "./utimensat-test", utimensat_times,0);
	if (!res){
		perror("utimensat");
	}


	struct utimbuf utime_time[1];
	struct utimbuf actime; 
	actime.actime = rand();
	actime.modtime = rand();
	utime_time[0] = actime;

	res = syscall(SYS_utime,"./utime-test", utime_time);
	if (!res){
		perror("utime failed");
	}

	struct timeval utimes_times[2];
	struct timeval utimes_actime; 
	struct timeval utimes_modtime;
	utimes_actime.tv_sec = rand() & 0xff;
	utimes_actime.tv_usec = rand() & 0xff;
	utimes_modtime.tv_sec = rand() & 0xff;
	utimes_modtime.tv_usec = rand() & 0xffff;
	utimes_times[0] = utimes_actime;
	utimes_times[1] = utimes_modtime;
	res = syscall(SYS_utimes,"./utimes-test", utimes_times);
	if (!res){
		perror("utimes");
	}

	utimes_actime.tv_sec = rand() & 0xff;
	utimes_actime.tv_usec = rand() & 0xff;
	utimes_modtime.tv_sec = rand() & 0xff;
	utimes_modtime.tv_usec = rand() & 0xffff;
	utimes_times[0] = utimes_actime;
	utimes_times[1] = utimes_modtime;
	res = syscall(SYS_futimesat,AT_FDCWD, "./futimesat-test", utimes_times);
	if (!res){
		perror("futimesat");
	}


	




}

