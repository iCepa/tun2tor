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

struct _tunif;
typedef struct _tunif tunif;

T2T_EXTERN tunif *tunif_new();
T2T_EXTERN void *tunif_free(tunif *iface);

T2T_EXTERN void tunif_input_packet(tunif *iface, const void *buffer, size_t len);
T2T_EXTERN void tunif_set_packet_callback(tunif *iface, void *context, void (*packet_callback)(tunif *iface, void *context, const void *buffer, size_t len, char proto));

