#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <dlfcn.h>

/* Remember, remember the fifth of November! 2005-11-05 00:00 UTC. */
#define TIMESTAMP 1131148800

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
  if(tv) {
    tv->tv_sec  = TIMESTAMP;
    tv->tv_usec = 0;
  }

  if(tz) {
    tz->tz_minuteswest = 0;
    tz->tz_dsttime     = 0;
  }

  return 0;
}

time_t time(time_t *t)
{
  if(t) {
    *t = TIMESTAMP;
  }

  return TIMESTAMP;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
  static int (*original)(clockid_t clk_id, struct timespec *tp);

  if(original == NULL) {
    void *hndl = dlopen("librt.so.1", RTLD_LAZY);
    assert(hndl);
    original = dlsym(hndl, "clock_gettime");
  }

  switch(clk_id) {
    case CLOCK_REALTIME:
      tp->tv_sec  = TIMESTAMP;
      tp->tv_nsec = 0;

      return 0;

    default:
      return original(clk_id, tp);
  }
}
