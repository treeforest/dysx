#ifndef __SDF_FUNC_H__
#define __SDF_FUNC_H__

#include <base_type.h>
#include <sdf_type.h>

#ifdef __cplusplus
extern "C" {
#endif


/*device manage*/
int SDF_OpenDevice(void **phDeviceHandle);
int SDF_CloseDevice(void *hDeviceHandle);

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
int SDF_CloseSession(void *hSessionHandle);
int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);
int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char * pucRandom);
int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength);
int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex);

/*key manage*/
int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
int SDF_GenerateKeyPair_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
								unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
								unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
int SDF_ImportKeyWithISK_RSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey,
								unsigned int puiKeyLength, void **phKeyHandle);
int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey,
					unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *puiDELength);
int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,
							ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
									ECCCipher *pucKey, void **phKeyHandle);
int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID,
					ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle);
int SDF_ImportKeyWithISK_ECC(void *hSessionHandle, unsigned int uiISKIndex,  ECCCipher *pucKey, void **phKeyHandle);
int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,
			unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle);
int SDF_GenerateKeyWithECC(void *hSessionHandle, unsigned char *pucResponseID, unsigned int uiResponseIDLength,
			ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle, void **phKeyHandle);
int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID,
			unsigned int uiResponseIDLength, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
			ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle);
int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
										ECCrefPublicKey*pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut);
int SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
										unsigned char * pucKey, unsigned int * puiKeyLength, void * *phKeyHandle);
int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char * pucKey, unsigned int puiKeyLength, void * *phKeyHandle);
int SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);


/*asym*/
int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle, RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,
												unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle, RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
										unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput,
								unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,  unsigned int uiKeyIndex, unsigned char *pucDataInput,
								unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
int SDFE_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiAlgSignFlag,unsigned int uiKeyIndex, unsigned char *pucDataInput,
								unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
int SDFE_InternalPrivateKeyOperation_RSA(void *hSessionHandle,  unsigned int uiAlgSignFlag, unsigned int uiKeyIndex, unsigned char *pucDataInput,
								unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
int SDF_ExternalSign_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
								unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
int SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
					unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
int SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,
								unsigned int uiDataLength, ECCSignature *pucSignature);
int SDF_InternalVerify_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned char *pucData,
								unsigned int uiDataLength, ECCSignature *pucSignature);
int SDFE_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiAlgID, unsigned char *pucData,
								unsigned int uiDataLength, ECCSignature *pucSignature);
int SDFE_InternalVerify_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiAlgID, unsigned char *pucData,
								unsigned int uiDataLength, ECCSignature *pucSignature);
int SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
									unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData);
int SDF_ExternalDecrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
									ECCCipher *pucEncData , unsigned char *pucData, unsigned int *puiDataLength);
int SDF_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiIPKIndex,unsigned char *pucData,
											unsigned int uiDataLength, ECCCipher *pucEncData);
int SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucEncData ,
											unsigned char *pucData, unsigned int *puiDataLength);
int SDFE_InternalECCEncrypt(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
								unsigned char *pucData, unsigned int uiDataLength,ECCCipher *pucEncData);
int SDFE_InternalECCDecrypt(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
								ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength);
/*symm*/
int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
					unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
					unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
					unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucMAC, unsigned int *puiMACLength);

/* hash */
int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
						unsigned char *pucID, unsigned int uiIDLength);
int SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
int SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength);
int SDFE_HMACInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength);
int SDFE_HMACUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
int SDFE_HMACUpdate2(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
int SDFE_HMACFinal(void *hSessionHandle, unsigned char *pucHMAC, unsigned int *puiHMACLength);
int SDFE_HMAC_Mult(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char pucCtx[512], unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucHMAC, unsigned int *puiHMACLength);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* sm9 */
/* generate keypair*/
int SDF_GenerateSignMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, SM9SignMasterPublicKey *pPuclicKey);
int SDF_GenerateEncMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, SM9EncMasterPublicKey *pPuclicKey);
int SDFE_GenerateUserSignKey_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserSignPrivateKey *vk);
int SDFE_GenerateUserEncKey_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserEncPrivateKey *vk);
int SDF_GenerateUserSignKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserSignPrivateKey *vk);
int SDF_GenerateUserEncKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserEncPrivateKey *vk);


/* key management*/
int SDF_ExportSignMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, SM9SignMasterPublicKey *pSignMasterPubKey);
int SDF_ExportEncMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, SM9EncMasterPublicKey *pEncMastPubKey);
int SDFE_CreateSignMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, SM9SignMasterPublicKey *pPuclicKey);
int SDFE_CreateEncMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, SM9EncMasterPublicKey *pPuclicKey);
int SDFE_CreateUserSignKey_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, unsigned int uiUserKeyindex,
									unsigned char *pucUserID, unsigned int uiUserIDLen);
int SDFE_CreateUserEncKey_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, unsigned int uiUserKeyindex,
									unsigned char *pucUserID, unsigned int uiUserIDLen);
int SDFE_DeleteInternalKeyPair_SM9(void *hSessionHandle, unsigned int uiMastFlag, unsigned int uiSignFlag, unsigned int uiKeyIndex, char *AdminPIN);
int SDF_GenerateUserSignKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int indexGen, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned char *pucEncID, unsigned int uiEncIDLen, SM9EncMasterPublicKey *pk, SM9PairSignEnvelopedKey *vk);
int SDF_GenerateUserEncKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int indexGen, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned char *pucEncID, unsigned int uiEncIDLen, SM9EncMasterPublicKey *pk, SM9PairEncEnvelopedKey *vk);
int SDF_ImportUserSignKeyWithMasterISK_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9PairSignEnvelopedKey *pEnvelpoedKey, unsigned int *puiUserKeyIndex);
int SDF_ImportUserEncKeyWithMasterISK_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9PairEncEnvelopedKey *pEnvelpoedKey, unsigned int *puiUserKeyIndex);



/* key encap */
int SDFE_GenerateKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int uiKeyLen, SM9EncMasterPublicKey *pPublicKey, unsigned char *pucUserID,
	unsigned int uiUserIDLen, SM9KeyPackage *pucKey, void **phKeyHandle);
int SDFE_ImportKeyWithEncKey_SM9(void *hSessionHandle, unsigned int uiKeyLen, SM9UserEncPrivateKey *vk, unsigned char *pucUserID,
	unsigned int uiUserIDLen,  SM9KeyPackage *pucKey, void **phKeyHandle);
int SDF_GenerateKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int ulKeyLen, SM9EncMasterPublicKey *pPublicKey, unsigned char *pUserID,
	unsigned int UserIDLen, SM9KeyPackage *pucKey, void **phKeyHandle);
int SDF_GenerateKeyWithMasterIPK_SM9(void *hSessionHandle, unsigned int ulKeyLen, unsigned int uiMasterKeyIndex, unsigned char *pUserID,
	unsigned int UserIDLen, SM9KeyPackage *pucKey, void **phKeyHandle);
int SDF_ImportKeyWithISK_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiKeyLen, SM9KeyPackage *pucKey, void **phKeyHandle);


/* key exchange */
int SDFE_GenerateAgreementDataWithSM9(void *hSessionHandle, SM9EncMasterPublicKey *pSponsorEncMastPubKey, SM9UserEncPrivateKey *pSponsorPrivateKey, unsigned int uiKeyBits,
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen,
	SM9EncMasterPublicKey *pSponsorTempPublicKey, void **phAgreementHandle);
int SDFE_GenerateKeyWithSM9(void *hSessionHandle, void *hAgreementHandle, SM9EncMasterPublicKey *pResponseTempPublicKey, void **phKeyHandle);
int SDFE_GenerateAgreementDataAndKeyWithSM9(void *hSessionHandle, SM9EncMasterPublicKey *pResponsorEncMastPubKey, SM9UserEncPrivateKey *pResponsorPrivateKey, unsigned int uiKeyBits,
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen,
	SM9EncMasterPublicKey *pSponsorTempPublicKey, SM9EncMasterPublicKey *pResponseTempPublicKey,void **phKeyHandle);
int SDF_GenerateAgreementDataWithSM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned int uiISKIndex, unsigned int uiKeyBits,
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen,
	SM9EncMasterPublicKey *pSponsorTempPublicKey, void **phAgreementHandle);
int SDF_GenerateKeyWithSM9(void *hSessionHandle, void *hAgreementHandle, SM9EncMasterPublicKey *pResponseTempPublicKey, void **phKeyHandle);
int SDF_GenerateAgreementDataAndKeyWithSM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned int uiISKIndex, unsigned int uiKeyBits,
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen,
	SM9EncMasterPublicKey *pSponsorTempPublicKey, SM9EncMasterPublicKey *pResponseTempPublicKey,void **phKeyHandle);


/* key calc*/
int SDFE_SignWithMasterEPK_SM9(void *hSessionHandle, SM9SignMasterPublicKey *pPublicKey, SM9UserSignPrivateKey *vk, unsigned char *pucData,
	unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_InternalSignWithMasterEPK_SM9(void *hSessionHandle, SM9SignMasterPublicKey *pPublicKey, unsigned int uiISKIndex, unsigned char *pucData,
	unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_InternalSignWithMasterIPK_SM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned int uiISKIndex, unsigned char *pucData,
	unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_VerifyWithMasterEPK_SM9(void *hSessionHandle, SM9SignMasterPublicKey *pPublicKey, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_VerifyWithMasterIPK_SM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned char *pucData, unsigned int uiDataLength, SM9Signature  *pSignature);
int SDF_EncryptWithMasterEPK_SM9(void *hSessionHandle, SM9EncMasterPublicKey *pPublicKey, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned int ulAlgID, unsigned char *pIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData);
int SDF_EncryptWithMasterIPK_SM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned int ulAlgID, unsigned char *pIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData);
int SDFE_DecryptWithUserEncKey_SM9(void *hSessionHandle, SM9UserEncPrivateKey *vk, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned char *pIV, SM9Cipher *pEncData, unsigned char *pucData, unsigned int *puiDataLength);
int SDF_DecryptWithInternalKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pIV, SM9Cipher *pEncData,
									unsigned char *pucData, unsigned int *puiDataLength);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



/* file */
int SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);
int SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
						unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer);
int SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
						unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer);
int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen);

int EVDF_BackupKey(void *hSessionHandle, char *passwd, BackupKey *pBackupKey);
int EVDF_RecoverKey(void *hDeviceHandle, char *passwd, RecoverKey *pRecoverKey);

int SDFE_ExportPublicKey_DSA(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiKeyIndex, DSArefPublicKey *pucPublicKey);
int SDFM_DeleteInternalKeyPair_DSA (void *hSessionHandle, unsigned int uiKeyIndex, char *AdminPIN);
int SDFE_InternalSign_DSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,unsigned int uiDataLength, DSASignature *pucSignature,unsigned int uiIndexKeylen);
int SDFE_InternalVerify_DSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned char *pucData,unsigned int uiDataLength, DSASignature *pucSignature,unsigned int uiIndexKeylen);
int SDFE_ExternalSign_DSA(void *hSessionHandle, DSArefPrivateKey *pucPrivateKey,unsigned char *pucData, unsigned int uiDataLength, DSASignature *pucSignature);
int SDFE_ExternalVerify_DSA(void *hSessionHandle, DSArefPublicKey *pucPublicKey,unsigned char *pucDataInput, unsigned int uiInputLength, DSASignature *pucSignature);
int SDFM_GenerateKeyPair_ECC_ECDSA(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,ECCrefPublicKey_ECDSA *pucPublicKey, ECCrefPrivateKey_ECDSA *pucPrivateKey);
int SDFM_CreateKeyPair_ECC_ECDSA(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyBits, unsigned int uiKeyIndex, ECCrefPublicKey_ECDSA *pucPublicKey);
int SDFM_ImportKeyPair_ECC_ECDSA(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyBits, unsigned int uiKeyIndex,  ECCrefPublicKey_ECDSA *pucPublicKey, ECCrefPrivateKey_ECDSA *pucPrivateKey);
int SDFE_ExportPublicKey_ECC_ECDSA(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiKeyIndex, ECCrefPublicKey_ECDSA *pucPublicKey);
int SDFM_DeleteInternalKeyPair_ECC_ECDSA(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, char *AdminPIN);
int SDFE_InternalSign_ECC_ECDSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiAlgID, unsigned char *pucData,unsigned int uiDataLength, ECCSignature_ECDSA *pucSignature,unsigned int uiIndexKeylen);
int SDFE_InternalVerify_ECC_ECDSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiAlgID, unsigned char *pucData,unsigned int uiDataLength, ECCSignature_ECDSA *pucSignature,unsigned int uiIndexKeylen);
int SDFE_ExternalSign_ECC_ECDSA(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey_ECDSA *pucPrivateKey,unsigned char *pucData, unsigned int uiDataLength, ECCSignature_ECDSA *pucSignature);
int SDFE_ExternalVerify_ECC_ECDSA(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey_ECDSA *pucPublicKey,unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature_ECDSA *pucSignature);
int SDFM_GenerateKeyPair_ECC_EDDSA(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,ECCrefPublicKey_EDDSA *pucPublicKey, ECCrefPrivateKey_EDDSA *pucPrivateKey);
int SDFM_CreateKeyPair_ECC_EDDSA(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyBits, unsigned int uiKeyIndex, ECCrefPublicKey_EDDSA *pucPublicKey);
int SDFM_ImportKeyPair_ECC_EDDSA(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyBits, unsigned int uiKeyIndex,  ECCrefPublicKey_EDDSA *pucPublicKey, ECCrefPrivateKey_EDDSA *pucPrivateKey);
int SDFE_ExportPublicKey_ECC_EDDSA(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiKeyIndex, ECCrefPublicKey_EDDSA *pucPublicKey);
int SDFM_DeleteInternalKeyPair_ECC_EDDSA (void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, char *AdminPIN);
int SDFE_InternalSign_ECC_EDDSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiAlgID, unsigned char *pucData,unsigned int uiDataLength, ECCSignature_EDDSA *pucSignature);
int SDFE_InternalVerify_ECC_EDDSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiAlgID, unsigned char *pucData,unsigned int uiDataLength, ECCSignature_EDDSA *pucSignature);
int SDFE_ExternalSign_ECC_EDDSA(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey_EDDSA *pucPrivateKey,unsigned char *pucData, unsigned int uiDataLength, ECCSignature_EDDSA *pucSignature);
int SDFE_ExternalVerify_ECC_EDDSA(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey_EDDSA *pucPublicKey,unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature_EDDSA *pucSignature);
int SDFE_AES_GCM_Crypto(void *hSessionHandle, void *hKeyHandle, unsigned int uiCryptoType, unsigned char *pucIV,unsigned int uiIVLen, unsigned char *pucHDR,unsigned int uiHDRLen,unsigned char *pucSrcData,unsigned int uiSrcLen,unsigned char *pucDstData,unsigned int *puiDstLen);
int SDFE_AES_CCM_Crypto(void *hSessionHandle, void *hKeyHandle, unsigned int uiCryptoType, unsigned char *pucNone,unsigned int uiNoneLen, unsigned char *pucAdata,unsigned int uiAdataLen,unsigned char *pucSrcData,unsigned int uiSrcLen,unsigned char *pucDstData,unsigned int *puiDstLen);
int SDFE_ZUC_Enc(void *hSessionHandle, unsigned char pucKey[16], unsigned char pucIV[16],unsigned char *pucSrcData,unsigned int uiSrcBytes, unsigned char *pucDstData, unsigned int *puiDstBytes);
int SDFE_ZUC_Mac(void *hSessionHandle, unsigned char pucKey[16], unsigned char pucIV[16],unsigned char *pucSrcData,unsigned int uiSrcBytes, unsigned char *pucDstData, unsigned int *puiDstBytes);
int SDFE_ZUC_Mac_Mult(void *hSessionHandle, unsigned char pucKey[16], unsigned char pucIV[16], unsigned char pucCtx[88], unsigned char *pucSrcData, unsigned int uiSrcBits, unsigned char *mac);
int SDFE_ZUC_Mac_Init(void *hSessionHandle, unsigned char pucKey[16], unsigned char pucIV[16]);
int SDFE_ZUC_Mac_Update(void *hSessionHandle, unsigned char *pucSrcData,unsigned int uiSrcBytes);
int SDFE_ZUC_Mac_Final(void *hSessionHandle, unsigned char *pucSrcData,unsigned int uiSrcBytes, unsigned char *pucDstData,unsigned int *puiDstBytes);

int EVDF_ZUC_Enc(void *hSessionHandle, void *hKeyHandle, unsigned char pucIV[16], unsigned char *pucSrcData,unsigned int uiSrcLen, unsigned char *pucDstData,unsigned int *puiDstLen);
int EVDF_ZUC_Mac(void *hSessionHandle, void *hKeyHandle, unsigned char pucIV[16], unsigned char *pucSrcData,unsigned int uiSrcLen, unsigned char *pucDstData,unsigned int *puiDstLen);
int EVDF_GenerateKeyPair_ECC_ECDSA(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,ECCrefPublicKey_ECDSA *pucPublicKey, ECCrefPrivateKey_ECDSA *pucPrivateKey);
int EVDF_ExternalSign_ECC_ECDSA(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey_ECDSA *pucPrivateKey,unsigned char *pucData, unsigned int uiDataLength, ECCSignature_ECDSA *pucSignature);
int EVDF_ExternalVerify_ECC_ECDSA(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey_ECDSA *pucPublicKey,unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature_ECDSA *pucSignature);


int SDFE_SM7_Crypto(void *hSessionHandle, void *hKeyHandle, unsigned int uiEncMode,unsigned int uiAlgMode,unsigned char* IV, unsigned int uiIVLen,unsigned char *pucSrcData,unsigned int uiSrcLen, unsigned char *pucDstData,unsigned int *puiDstLen);

/****************************************************************************************************/
int SDFM_CreateDeviceHandlePool(unsigned int uiCount);
int SDFM_FreeDeviceHandlePool(void);
int SDFM_ExportKeyWithEPK_ECC(void *hSessionHandle, void *hKeyHandle, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey);
int SDFM_CreateKeyFromKEK(void *hSessionHandle, unsigned int uiKEKIndex, void **phKeyHandle);
int SDFM_ImportKeyWithSessionKey(void *hSessionHandle, unsigned int uiAlgID, void *hSessionKeyHandle, unsigned char * pucKey, unsigned int puiKeyLength, void * *phKeyHandle);
int SDFM_SetKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
int SDFM_HashUpdateWithKey(void *hSessionHandle, void *hKeyHandle, unsigned int uiKeyFormat);
int SDFM_Encrypt_Hash_Snoop(void *hSessionHandle, void *hKeyHandle, PCIPHERHASHPARAM pParam, unsigned char *pucEncData,
								unsigned int *puiEncDataLength, unsigned char *pucHMAC, unsigned int *puiHMACLength);
int SDFM_Decrypt_Hash_Snoop(void *hSessionHandle, void *hKeyHandle, PCIPHERHASHPARAM pParam, unsigned char *pucDecData,
								unsigned int *puiDecDataLength, unsigned char *pucHMAC, unsigned int *puiHMACLength);
int SDFM_EnumFiles(void *hSessionHandle, char *szFileList, unsigned int *puiSize);
int SDFM_ImportKeyPair_DSA(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiKeyIndex,  DSArefPublicKey *pucPublicKey, DSArefPrivateKey *pucPrivateKey);

int SDFE_Encrypt_Exp(void *hSessionHandle,unsigned char *pucKey, unsigned int uiKeyLength, unsigned int uiAlgID, unsigned char *pucIV,
					unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
int SDFE_Decrypt_Exp(void *hSessionHandle,unsigned char *pucKey, unsigned int uiKeyLength, unsigned int uiAlgID, unsigned char *pucIV,
					unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
int SDFM_GenerateKeyPair_DSA(void *hSessionHandle,unsigned int uiKeyBits,DSArefPublicKey *pucPublicKey, DSArefPrivateKey *pucPrivateKey);
int SDFM_GetCardInit(void *hDeviceHandle,unsigned int *initstatus);

/* control */
#define V_CTL_ADD_USER                0
#define V_CTL_DEL_USER                1
#define V_CTL_USER_LOGIN              2
#define V_CTL_USER_LOGOUT             3
#define V_CTL_GET_USER_STATE          4
#define V_CTL_GET_BACKUPKEY           5
#define V_CTL_SET_BACKUPKEY           6
#define V_CTL_GET_BACKUPDATAHASH      7
#define V_CTL_SET_BACKUPDATAHASH      8
#define V_CTL_GET_BACKUPDATA          9
#define V_CTL_SET_BACKUPDATA          10
#define V_CTL_DEVINIT                 11
#define V_CTL_GEN_GRANDOM             12
#define V_CTL_WRITEPUBKEY             13
#define V_CTL_ERASEUMG                14
#define V_CTL_ERASEALL                15
#define V_CTL_GPIO                    16
#define V_CTL_ERASEUMGEFLASHROOTKEY   17
#define V_CTL_BACKUPKEYDISPARAM       18
#define V_CTL_GETDEVINFOTLV           19

#define V_CTL_ADD_USER_EXUK           0x100
#define V_CTL_DEL_USER_EXUK           0x101
#define V_CTL_USER_LOGIN_EXUK         0x102
#define V_CTL_USER_LOGOUT_EXUK        0x103
#define V_CTL_UMG_INIT_EXUK           0x104
#define V_CTL_GET_USER_STATE_EXUK     0x105
#define V_CTL_GET_BACKUPKEY_EXUK      0x106
#define V_CTL_GET_BACKUPDATAHASH_EXUK 0x107
#define V_CTL_GET_BACKUPDATA_EXUK     0x108
#define V_CTL_SET_BACKUPKEY_EXUK      0x109
#define V_CTL_SET_BACKUPDATA_EXUK     0x10A
#define V_CTL_SET_BACKUPDATAHASH_EXUK 0x10B

#define V_CTL_DEVREBOOT               0x200
#define V_CTL_DEVREBOOTSIGN           0x201
#define V_CTL_OEM2BOOT                0x202
#define V_CTL_DEVPUBKEYCHECK          0x203

#define V_CTL_CHECK_CERT              0x1001
#define V_CTL_GET_CERT_PUBKEY         0x1002
#define V_CTL_DEVINIT_FORCE           0xE001
int PCI_V_Control(void *hDeviceHandle, int request, ...);

#ifdef __cplusplus
};
#endif

#endif  /*__SDF_FUNC_H__*/
