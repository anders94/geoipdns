#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "alloc.h"
#include "uint16.h"
#include "uint32.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "ip4.h"
#include "exit.h"
#include "case.h"
#include "scan.h"
#include "buffer.h"
#include "ipdb.h"
#include "strerr.h"
#include "getln.h"
#include "cdb_make.h"
#include "stralloc.h"
#include "open.h"
#include "dns.h"

#define TTL_NS 259200
#define TTL_POSITIVE 86400
#define TTL_NEGATIVE 2560


