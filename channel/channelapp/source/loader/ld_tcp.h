#ifndef LD_TCP_H
#define LD_TCP_H

#include <unistd.h>
#include <gctypes.h>
#include "../tcp.h"
#include "../loader.h"

#include <ogcsys.h>
#include <ogc/mutex.h>
#include <ogc/lwp_watchdog.h>
#include <network.h>

void loader_tcp_init (void);
bool loader_tcp_initializing (void);
bool loader_tcp_initialized (void);

#endif
