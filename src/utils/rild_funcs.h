#ifndef RILD_PORTING_H
#define RILD_PORTING_H

#define SCARDCONTEXT  	void*
#define SCARDHANDLE	void*
#define DWORD 		long
#define uint8 unsigned char
#define uint32 unsigned int
#define SIM_RAND_LEN 	16
#define SIM_SRES_LEN	4
#define SIM_KC_LEN	8
#define AKA_RAND_LEN 16
#define AKA_AUTN_LEN 16
#define AKA_AUTS_LEN 14
#define RES_MAX_LEN 16
#define IK_LEN 16
#define CK_LEN 16

typedef enum scard_sim_type{
	SCARD_GSM_SIM_ONLY,
	SCARD_USIM_ONLY,
	SCARD_TRY_BOTH
} scard_sim_type;
/* some codes to call scard_deinit are not enclosed by PCSC_FUNCS by default */
#define scard_init(s, r) NULL
#define scard_deinit(s) do { } while (0)
int scard_gsm_auth(int slotId, const unsigned char *_rand,
		   unsigned char *sres, unsigned char *kc);
int scard_umts_auth(int slotId, const unsigned char *_rand,
		    const unsigned char *autn,
		    unsigned char *res, size_t *res_len,
		    unsigned char *ik, unsigned char *ck, unsigned char *auts);

#endif
