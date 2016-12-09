//
//  tun2tor.h
//  tun2tor
//
//  Created by Conrad Kramer on 10/1/15.
//

#ifdef __cplusplus
#define T2T_EXTERN      extern "C" __attribute__((visibility ("default")))
#else
#define T2T_EXTERN      extern __attribute__((visibility ("default")))
#endif

#include <stdint.h>

T2T_EXTERN void tun2tor_run(int fd);
