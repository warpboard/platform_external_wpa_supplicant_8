#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cutils/sockets.h>
#include "includes.h"
#include "rild_funcs.h"
#include <assert.h>

#include "common.h"
#include "config.h"

#define RILD_SOCKET_NAME "rild-oem"
#define RILD_SOCKET_MD2_NAME "rild-oem-md2"

typedef enum { SCARD_GSM_SIM, SCARD_USIM } sim_types;

struct scard_data {
	SCARDCONTEXT ctx;
	SCARDHANDLE card;
	DWORD protocol;
	sim_types sim_type;
	int pin1_required;
};

static uint8  atou8(const char *a)
{
	uint8 ret = 0;
	
	if(*a <= '9' && *a >= '0')
		ret = *a - '0';
	else if(*a >= 'a' && *a <= 'f')
		ret = *a - 'a' + 10;
	else if(*a >= 'A' && *a <= 'F')
		ret = *a - 'A' + 10;

	return ret;
}


//char to uint_8
static  void atohex(const char *a, uint8 *hex)
{
	uint8 tmp = atou8(a);

	tmp <<= 4;
	tmp += atou8(a + 1);

	*hex = tmp;
	
}

static  void strtohex(const char *a, uint32 len, uint8 *hex)
{
	uint32 i = 0;
	
	for (i = 0; i < len/2; i++)
		atohex(a + i * 2, hex + i);
}


//uint8 to char
static void hextoa(uint8 *hex, char *a)
{
	sprintf(a, "%2x", *hex);
	
	if(*hex < 0x10){
		*a = '0';
	}
}

static void hextostr(uint8 *hex, uint32 len,
			char *a)
{
	uint32 i = 0;
	
	for(i = 0; i < len; i++)
		hextoa(hex + i, a + i * 2);
}


/**
 *  using socket to connect with rild, then supplicant can pass auth parameters to rild
 *  and then get result from rild
 *  @ slot_id: if rild support multiple sim card, according this param to decide which 
 * 	 		sim card is using to do authentication 
 *  Returns: the socket fd if success, for fails, return -1 
 */
int connectToRild(int *slotId)
{
	int sock = -1;
#if CONFIG_RILD_FUNCS_MULTI_SIM /* multi sim support in rild */
	char telephony_mode[] = "0", first_md[] = "0";

	property_get("ril.telephony.mode", telephony_mode, NULL);
	property_get("ril.first.md", first_md, NULL);
	wpa_printf(MSG_DEBUG, "RIL: slot=%d, ril.telephony.mode=%s, ril.first.md=%s",*slotId , telephony_mode, first_md);
	if(telephony_mode[0]=='1' || telephony_mode[0]=='3')/* only use modem 1 */
	{
		sock = socket_local_client(RILD_SOCKET_NAME, 
			ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
		wpa_printf(MSG_DEBUG, "RIL: try to connect to "RILD_SOCKET_NAME);
	}
	else if(telephony_mode[0]=='2' || telephony_mode[0]=='4')/* only use modem 2 */
	{
		sock = socket_local_client(RILD_SOCKET_MD2_NAME, 
			ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
		wpa_printf(MSG_DEBUG, "RIL: try to connect to "RILD_SOCKET_MD2_NAME);
	}	
	else if(telephony_mode[0]>='5' && telephony_mode[0]<='8')/* using modem 1 and modem 2*/
	{
		if(first_md[0]-'1' == *slotId) //ril.first.md==1 indicate MD1 connect to SIM1, ==2 indicate MD1 connect to SIM2
		{
			sock = socket_local_client(RILD_SOCKET_NAME,
				ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
			wpa_printf(MSG_DEBUG, "RIL: try to connect to "RILD_SOCKET_NAME);
		}
		else
		{
			sock = socket_local_client(RILD_SOCKET_MD2_NAME,
				ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
			wpa_printf(MSG_DEBUG, "RIL: try to connect to "RILD_SOCKET_MD2_NAME);
		}
		*slotId = 0;
		wpa_printf(MSG_DEBUG, "RIL: Reset slot to slot0");
	}
	else if (telephony_mode[0] == NULL || telephony_mode[0] == '0') /* no telephony_mode set, should be single sim slot project*/
	{
		sock = socket_local_client(RILD_SOCKET_NAME,ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
		wpa_printf(MSG_DEBUG, "RIL: try to connect to "RILD_SOCKET_NAME);
	}
	else {
		wpa_printf(MSG_DEBUG, "RIL: unsupport ril.telephony.mode");
		return -1;
	}
#else /* only single sim support in rild */
	sock = socket_local_client(RILD_SOCKET_NAME,ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
	wpa_printf(MSG_DEBUG, "RIL: try to connect to "RILD_SOCKET_NAME);
#endif
	if(sock < 0)
		wpa_printf(MSG_ERROR, "connectToRild %s", strerror(errno));
	
	return sock;
}


/** 
 *  send "rand" which is from hlr to rild for gsm authentication
 *  @ sock: the socket fd returns by connectToRild
 *  @ slotId: if rild support multiple sim card, according this param to decide which 
 * 	 		sim card is using to do authentication 
 *  @ rand: the random number received from hlr
 *  Returns: success case, return 0, other case return negative 
 */
static int  eapSimSetParam(int sock, int slotId, uint8 *rand)
{
	int ret = -1, strLen = 0, count = 1;
	char *strParm = NULL, *pTmp = NULL;
		
	assert(sock > 0);
	
	wpa_printf(MSG_DEBUG, "%s sock %d slotId %d\n", __FUNCTION__, sock, slotId);
	wpa_hexdump(MSG_DEBUG, "rand: ", rand, SIM_RAND_LEN);

	strLen = strlen("EAP_SIM") + 2 + SIM_RAND_LEN * 2 + 1 + 1;
	strParm	= (char *)malloc(strLen); 
	strParm[strLen - 1] = '\0';
	strcpy(strParm, "EAP_SIM");
	strcat(strParm, ",");
#if CONFIG_RILD_FUNCS_MULTI_SIM
	sprintf(strParm + strlen(strParm), "%d", slotId);
	strcat(strParm, ",");
#endif
	//strncpy(strParm + strlen(strParm), rand, SIM_RAND_LEN);
	hextostr(rand, SIM_RAND_LEN, strParm + strlen(strParm));
	wpa_printf(MSG_DEBUG, "%d %s will sent to rild\n", strLen, strParm);

	ret = send(sock, &count, sizeof(int), 0);
	if(sizeof(int) == ret)
		ret = send(sock, &strLen, sizeof(strLen), 0);
	else{	
		ret = -4;
		goto failed;
	}

	if(sizeof(strLen) == ret){
		ret = send(sock, strParm, strLen, 0);
		if(strLen == ret){
			ret = 0;
			wpa_printf(MSG_DEBUG, "%s ok\n", __FUNCTION__);
		}else{
			ret = -5;
			goto failed;	
		}	
	}
	else{
		ret = -3;	
	}

failed:	
	free(strParm);
	wpa_printf(MSG_DEBUG, "oh, %s (%d)%s\n", __FUNCTION__, ret, strerror(errno));

	return ret;
}



/** 
 *  send "rand" which is from hlr to rild for umts authentication
 *  @ sock: the socket fd returns by connectToRild
 *  @ slotId: if rild support multiple sim card, according this param to decide which 
 * 	 		sim card is using to do authentication 
 *  @ rand: the random number received from hlr
 *  @ autn: 
 *  Returns: success case, return 0, other case return negative 
 */
static int eapAkaSetParam(int sock, int slotId, uint8 *rand, uint8 *autn)
{
	int ret = -1, strLen = 0, count = 1;
	char *strParm = NULL, *pTmp = NULL;
		
	assert(sock > 0);
	
	wpa_printf(MSG_DEBUG, "%s slotId %d\n", __FUNCTION__, slotId);
	wpa_hexdump(MSG_DEBUG, "rand: ", rand, AKA_RAND_LEN);
	wpa_hexdump(MSG_DEBUG, "autn: ", autn, AKA_AUTN_LEN);

	strLen = strlen("EAP_AKA") + 3 + AKA_RAND_LEN * 2 + 1 + AKA_AUTN_LEN * 2 + 1;
	strParm	= (char *)malloc(strLen); 
	strParm[strLen - 1] = '\0';
	strcpy(strParm, "EAP_AKA");
	strcat(strParm, ",");
#if CONFIG_RILD_FUNCS_MULTI_SIM
	sprintf(strParm + strlen(strParm), "%d", slotId);
	strcat(strParm, ",");
#endif
	hextostr(rand, AKA_RAND_LEN, strParm + strlen(strParm));
	strcat(strParm, ",");
	hextostr(autn, AKA_AUTN_LEN, strParm + strlen(strParm));
	wpa_printf(MSG_DEBUG, "%d %s will sent to rild\n", strLen, strParm);

	ret = send(sock, &count, sizeof(int), 0);
	if(sizeof(int) == ret )
		ret = send(sock, &strLen, sizeof(strLen), 0);
	else
		goto failed;

	if(sizeof(strLen) == ret)
		ret = send(sock, strParm, strLen, 0);

	if(strLen == ret){
		ret = 0;
		wpa_printf(MSG_DEBUG, "%s ok\n", __FUNCTION__);
	}else{
		ret = -1;
		wpa_printf(MSG_DEBUG, "%s failed\n", __FUNCTION__);
	}
	

failed:	
	free(strParm);
	wpa_printf(MSG_DEBUG, "oh, %s (%d)%s\n", __FUNCTION__, ret, strerror(errno));

	return ret;
}

static int parseSimResult(const char *strParm, int strLen, uint8 *sres, uint8 *kc)
{
	int ret = -1;
	
	wpa_printf(MSG_DEBUG, "%s (%d) %s\n", __FUNCTION__, strLen, (char *)strParm);
	
	if(0 == strncmp(strParm, "ERROR", strlen("ERROR")))
		wpa_printf(MSG_DEBUG, "%s\n", strParm);
	else{
		strtohex(strParm, SIM_SRES_LEN * 2, sres);
		strtohex(strParm + SIM_SRES_LEN * 2, SIM_KC_LEN * 2, kc);
		wpa_printf(MSG_DEBUG, "parseSimResult ok\n");
		wpa_hexdump(MSG_DEBUG, "parseSimResult kc", kc, SIM_KC_LEN);
		wpa_hexdump(MSG_DEBUG, "parseSimResult sres", sres, SIM_SRES_LEN);
		ret = 0;
	}
		
	return ret;	
}


static void parseAkaSuccess(const char* str, uint8 *res, size_t *res_len,
			uint8 *ck, uint8 *ik)
{
	uint8 tmpLen = 0;
	uint32 index = 0;
	uint8 kc[16];	

	atohex(str, &tmpLen);
	index += 2;
	*res_len = tmpLen;
	strtohex(str + index, tmpLen * 2, res);
	wpa_hexdump(MSG_DEBUG, "parseAkaSuccess res", res, tmpLen);

	index += tmpLen * 2;
	atohex(str + index, &tmpLen);
	index += 2;
	strtohex(str + index, tmpLen * 2, ck);
	wpa_hexdump(MSG_DEBUG, "parseAkaSuccess ck", ck, tmpLen);
	
	index += tmpLen * 2;
	atohex(str + index, &tmpLen);
	index += 2;
	strtohex(str + index, tmpLen * 2, ik);
	wpa_hexdump(MSG_DEBUG, "parseAkaSuccess ik", ik, tmpLen);

	index += tmpLen * 2;
	atohex(str + index, &tmpLen);
	index += 2;
	strtohex(str + index, tmpLen * 2, kc);
	wpa_hexdump(MSG_DEBUG, "parseAkaSuccess kc", kc, tmpLen);

}

static void parseAkaFailure(const char* str, uint8 *auts)
{
	uint8 tmpLen = 0;
	uint32 index = 0;

	atohex(str, &tmpLen);
	index += 2;
	strtohex(str + index, tmpLen * 2, auts);
	
	wpa_hexdump(MSG_DEBUG, "parseAkaFailure auts ", auts, tmpLen);
}


static int parseAkaResult(const char *strParm, int strLen,
			uint8 *res, size_t *res_len,
		     	uint8 *ik, uint8 *ck, uint8 *auts)
{
	int ret = -1;

	wpa_printf(MSG_DEBUG, "%s %s\n", __FUNCTION__, strParm);	
	
	if(0 == strncmp(strParm, "DB", strlen("DB"))){
		parseAkaSuccess(strParm + 2, res, res_len, ck, ik);		
		return 0;
	}else if(0 == strncmp(strParm, "DC", strlen("DC"))){
		parseAkaFailure(strParm + 2, auts);
		
	}else{
		wpa_printf(MSG_DEBUG, "%s unknow string. %s\n", 
			__FUNCTION__, strParm);
	}

	return -1;	

}


//output function

//1 3G security_parameters context
static int eapSimQueryResult(int sock, uint8 *sres, uint8 *kc)
{
	int ret = -1, strLen = 0;
	char *strParm = NULL;

	assert(sres);
	assert(kc);
	assert(sock > 0);

	wpa_printf(MSG_DEBUG,"%s\n", __FUNCTION__);	
	ret = recv(sock, &strLen, sizeof(strLen), 0);
	
	if(sizeof(strLen) == ret){
		strParm = (char *)malloc(strLen + 1);
		memset(strParm, 0xcc, strLen + 1);
		strParm[strLen] = '\0';
		ret = recv(sock, strParm, strLen, 0);
		if(strLen == ret){
			ret = parseSimResult((const char*)strParm, strLen, sres, kc);
		}
		free(strParm);		
	}

	return ret;
}




//2 GSM security_parameters context
static int eapAkaQueryResult(int sock, uint8 *res, size_t *res_len,
		     uint8 *ik, uint8 *ck, uint8 *auts)
{
	int ret = -1, strLen = 0;
	char *strParm = NULL;

	assert(sres);
	assert(kc);
	assert(sock > 0);

	wpa_printf(MSG_DEBUG,"%s ret %d  strLen %d\n", __FUNCTION__, ret, strLen);	
	ret = recv(sock, &strLen, sizeof(strLen), 0);
		
	if(sizeof(strLen) == ret){
		strParm = (char *)malloc(strLen + 1);
		memset(strParm, 0xcc, strLen + 1);
		strParm[strLen] = '\0';
		ret = recv(sock, strParm, strLen, 0);
		if(strLen == ret){
			ret = parseAkaResult((const char*)strParm, strLen,
						res, res_len,
						ik, ck, auts);
		}
		free(strParm);		
	}

	return ret;
}


int disconnectWithRild(int sock)
{
	int ret;
	
	assert(sock > 0);
	ret = close(sock);
	
	return ret;
}

/**
 * scard_gsm_auth - Run GSM authentication command on SIM card
 * @slotId: the sim slot id
 * @_rand: 16-byte RAND value from HLR/AuC
 * @sres: 4-byte buffer for SRES
 * @kc: 8-byte buffer for Kc
 * Returns: 0 on success, negative number indicates error
 *
 * This function performs GSM authentication using SIM/USIM card and the
 * provided RAND value from HLR/AuC. If authentication command can be completed
 * successfully, SRES and Kc values will be written into sres and kc buffers.
 */
int scard_gsm_auth(int slotId, const unsigned char *_rand,
		   unsigned char *sres, unsigned char *kc)
{
	size_t len;
	int sock = -1;
	int ret = 0;

	wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - RAND", _rand, 16);

	//communicate with rild
	wpa_printf(MSG_DEBUG, "%s++\n", __FUNCTION__);
	sock = connectToRild(&slotId);
	if (sock < 0)
		return -1;
	if(!eapSimSetParam(sock, slotId, _rand))
		ret = eapSimQueryResult(sock, sres, kc); 
	disconnectWithRild(sock);
	
	if (!ret){
		wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - SRES", sres, 4);
		wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - Kc", kc, 8);
	}
	return ret;
}


/**
 * scard_umts_auth - Run UMTS authentication command on USIM card
 * @slotId: the sim slot id
 * @_rand: 16-byte RAND value from HLR/AuC
 * @autn: 16-byte AUTN value from HLR/AuC
 * @res: 16-byte buffer for RES
 * @res_len: Variable that will be set to RES length
 * @ik: 16-byte buffer for IK
 * @ck: 16-byte buffer for CK
 * @auts: 14-byte buffer for AUTS
 * Returns: 0 on success, negative number means failure
 *
 * This function performs AKA authentication using USIM card and the provided
 * RAND and AUTN values from HLR/AuC. If authentication command can be
 * completed successfully, RES, IK, and CK values will be written into provided
 * buffers and res_len is set to length of received RES value. If USIM reports
 * synchronization failure, the received AUTS value will be written into auts
 * buffer. In this case, RES, IK, and CK are not valid.
 */
int scard_umts_auth(int slotId, const unsigned char *_rand,
		    const unsigned char *autn,
		    unsigned char *res, size_t *res_len,
		    unsigned char *ik, unsigned char *ck, unsigned char *auts)
{
	size_t len;
	int sock = -1;
	int ret = -1;

	wpa_hexdump(MSG_DEBUG, "SCARD: UMTS auth - RAND", _rand, AKA_RAND_LEN);
	wpa_hexdump(MSG_DEBUG, "SCARD: UMTS auth - AUTN", autn, AKA_AUTN_LEN);

	wpa_printf(MSG_DEBUG, "%s++", __FUNCTION__);
						
				
	sock = connectToRild(&slotId);
	if (sock < 0)
		return -1;
	if(!eapAkaSetParam(sock, slotId, _rand, autn))
		ret = eapAkaQueryResult(sock, res, res_len, ik, ck, auts);
	disconnectWithRild(sock);
	return ret;		
}

