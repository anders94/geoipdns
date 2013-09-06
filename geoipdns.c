#include "dns.h"

const char *fatal = "geoipdns: fatal: ";
const char *starting = "starting geoipdns\n";

static char seed[128];

void initialize(void)
{
  dns_random_init(seed);
}
