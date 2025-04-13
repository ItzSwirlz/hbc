#include "ld_tcp.h"

static lwp_t ld_tcp_thread;
static u8 ld_tcp_stack[LD_THREAD_STACKSIZE] ATTRIBUTE_ALIGN (32);

typedef enum {
	LDTCPCMD_IDLE = 0,
	LDTCPCMD_EXIT,
	LDTCPCMD_INIT,
	LDTCPCMD_ACCEPT
} ld_tcp_cmd;

typedef enum {
	LDTCPS_UNINITIALIZED = 0,
	LDTCPS_INITIALIZING,
	LDTCPS_INITIALIZED
} ld_tcp_state;

typedef struct {
	bool running;
	ld_tcp_cmd cmd;
	ld_tcp_state state;
	bool handshaked;
	u16 args_len;
	u32 data_len;
	u32 data_len_un;
	int s;
	char *client;
	mutex_t cmutex;
	cond_t cond;
} ld_tcp_arg;

static void * ld_tcp_func (void *arg) {
	ld_tcp_arg *ta = (ld_tcp_arg *) arg;
	int s = -1, sn;
	struct sockaddr_in sa;
	u32 mask, len_sa;
	s32 res;
	u8 buf[16];
	u16 wiiload_version;
	u8 retries;

	mask = 0;

	ta->running = true;
	LWP_MutexLock (ta->cmutex);

	ta->cmd = LDTCPCMD_INIT;
	ta->state = LDTCPS_UNINITIALIZED;
	ta->handshaked = false;

	while (true) {
		while (ta->cmd == LDTCPCMD_IDLE)
			LWP_CondWait(ta->cond, ta->cmutex);

		ta->handshaked = false;

		if (ta->cmd == LDTCPCMD_EXIT) {
			break;
		}

		if (ta->cmd == LDTCPCMD_INIT) {
			ta->cmd = LDTCPCMD_IDLE;

			if (ta->state == LDTCPS_INITIALIZED) {
				gprintf ("reinit net\n");
				net_close (s);
			}

			retries = 32;
			ta->state = LDTCPS_INITIALIZING;

			while (retries) {
				res = net_init_async(NULL, NULL);

				if (res) {
					gprintf("net_init_async failed: %d\n", res);
					break;
				}

				res = net_get_status();
				while (res == -EBUSY) {
					if (ta->cmd == LDTCPCMD_EXIT) {
						gprintf("exit while net_init_async still busy\n");
						res = -1;
						break;
					}

					usleep(50 * 1000);
					res = net_get_status();
				}

				if ((res == -EAGAIN) || (res == -ETIMEDOUT)) {
					gprintf ("net_init failed: %d, trying again...\n", res);
					retries--;
					usleep(50 * 1000);
					continue;
				}

				break;
			}

			if (res < 0) {
				gprintf ("net_init failed: %d\n", res);
				ta->state = LDTCPS_UNINITIALIZED;
				continue;
			}

			gprintf ("net_init success: %d\n", res);

			mask = net_gethostip () & 0xffff0000;

			s = tcp_listen (LD_TCP_PORT, 3);

			if ((s == -ENETRESET) && retries) {
				gprintf("ENETRESET, reiniting\n");
				net_deinit();
				ta->cmd = LDTCPCMD_INIT;
				continue;
			}

			if (s < 0) {
				gprintf ("tcp_listen failed: %d\n",s);
				ta->state = LDTCPS_UNINITIALIZED;
				continue;
			}

			ta->state = LDTCPS_INITIALIZED;

			continue;
		}

		if (ta->cmd == LDTCPCMD_ACCEPT) {
			ta->cmd = LDTCPCMD_IDLE;
			memset (&sa, 0, sizeof (struct sockaddr_in));
			sa.sin_family = AF_INET;
			sa.sin_len = sizeof (struct sockaddr_in);

			len_sa = sizeof (struct sockaddr_in);

			sn = net_accept (s, (struct sockaddr *) &sa, &len_sa);
			if (sn == -EAGAIN)
				continue;

			if (sn == -ENETRESET) {
				gprintf("ENETRESET, reiniting\n");
				net_deinit();
				ta->cmd = LDTCPCMD_INIT;
				continue;
			}

			if (sn < 0) {
				gprintf ("net_accept failed: %d\n", sn);

				net_close (s);
				ta->state = LDTCPS_UNINITIALIZED;

				continue;
			}

			if ((sa.sin_addr.s_addr & 0xffff0000) != mask) {
				gprintf ("non local ip (%x)\n", sa.sin_addr.s_addr);
				net_close (sn);
				continue;
			}

			if (!tcp_read (sn, buf, 16, NULL, NULL)) {
				net_close (sn);
				continue;
			}

			wiiload_version = buf_u16(buf, 4);
			ta->args_len = buf_u16(buf, 6);
			ta->data_len = buf_u32(buf, 8);
			ta->data_len_un = buf_u32(buf, 12);

			if (strncmp((char *) buf, "HAXX", 4) ||
					(wiiload_version < WIILOAD_MIN_VERSION) ||
					(ta->args_len > ARGS_MAX_LEN) ||
					(!ta->data_len || ta->data_len > LD_MAX_SIZE) ||
					(ta->data_len_un > LD_MAX_SIZE)) {
				gprintf ("invalid upload request\n");
				net_close (sn);
				continue;
			}

			ta->s = sn;
			ta->client = inet_ntoa (sa.sin_addr);
			ta->handshaked = true;

			continue;
		}
	}

	if (ta->state == LDTCPS_INITIALIZED) {
		gprintf ("net_shutdown\n");
		res = net_shutdown (s, 2);
		if (res)
			gprintf ("net_shutdown failed: %d\n", res);

		gprintf ("net_close\n");
		res = net_close (s);
		if (res)
			gprintf ("net_close failed: %d\n", res);
	}

	gprintf ("tcp thread deiniting\n");
	net_deinit();
	gprintf ("tcp thread exiting\n");
	ta->state = LDTCPS_UNINITIALIZED;

	ta->running = false;
	LWP_MutexUnlock (ta->cmutex);

	return NULL;
}
