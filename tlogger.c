#include "logger.h"

int main (int argc, char **argv)
{
	wrner("this is a warning on pid %d, message %s",24,"the_message");
	dbger("debug message: %s", "the_debug_message");
	infrmer("to inform you that: %s,%d", "cacaisshit",666);
}
