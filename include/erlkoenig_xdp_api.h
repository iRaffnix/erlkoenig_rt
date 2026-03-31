/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * erlkoenig_xdp_api.h — Public API for XDP packet steering.
 */

#ifndef ERLKOENIG_XDP_API_H
#define ERLKOENIG_XDP_API_H

#include <stdint.h>

int ek_xdp_init(const char *ifname);
int ek_xdp_add_route(uint32_t ip_net_order, uint32_t ifindex);
int ek_xdp_del_route(uint32_t ip_net_order);
int ek_xdp_is_active(void);
void ek_xdp_cleanup(void);

#endif /* ERLKOENIG_XDP_API_H */
