/*
 * Public Domain / Unlicense
 * 
 * Description:
 * Generates or Loads an SSL Certificate Authority (CA) key pair.
 * Generates a User key pair signed by the CA, injecting a Subject Alternative 
 * Name (SAN) extension for an IP address so modern browsers will trust it.
 * Reads configuration from 'certs.ini'.
 *
 * Compilation (MinGW / GCC):
 * gcc -O2 -s -o make_certs.exe make_certs.c -lcrypt32 -ladvapi32
 */

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef szOID_RSA_SHA256RSA
#define szOID_RSA_SHA256RSA "1.2.840.113549.1.1.11"
#endif
#ifndef szOID_SUBJECT_ALT_NAME2
#define szOID_SUBJECT_ALT_NAME2 "2.5.29.17"
#endif
// Fallback for older MinGW headers
#ifndef HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
typedef ULONG_PTR HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
#endif
#define CA_CONTAINER_A   "LocalCA_Container"
#define CA_CONTAINER_W  L"LocalCA_Container"
#define USER_CONTAINER_A   "LocalUser_Container"
#define USER_CONTAINER_W  L"LocalUser_Container"
#define szOID_RSA_MD5RSA "1.2.840.113549.1.1.4"
#define szOID_RSA_SHA1RSA "1.2.840.113549.1.1.5"
#define szOID_RSA_SHA384RSA "1.2.840.113549.1.1.12"
#define szOID_RSA_SHA512RSA "1.2.840.113549.1.1.13"
void PrintError(const char* msg) {
    printf("[ERROR] %s failed with code 0x%08lX\n", msg, GetLastError());
}

BOOL CreateNameBlob(LPCSTR szName, PCERT_NAME_BLOB pBlob) {
    DWORD cbEncoded = 0;
    if (!CertStrToNameA(X509_ASN_ENCODING, szName, CERT_OID_NAME_STR, NULL, NULL, &cbEncoded, NULL))
        return FALSE;
    pBlob->pbData = (BYTE*)malloc(cbEncoded);
    pBlob->cbData = cbEncoded;
    return CertStrToNameA(X509_ASN_ENCODING, szName, CERT_OID_NAME_STR, NULL, pBlob->pbData, &pBlob->cbData, NULL);
}

void ExportToPFX(PCCERT_CONTEXT pCert, LPCWSTR pwszPassword, LPCSTR filename) {
    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!hStore) { PrintError("CertOpenStore"); return; }

    if (!CertAddCertificateContextToStore(hStore, pCert, CERT_STORE_ADD_NEW, NULL)) {
        PrintError("CertAddCertificateContextToStore");
        CertCloseStore(hStore, 0);
        return;
    }

    CRYPT_DATA_BLOB pfxBlob = {0};
    if (PFXExportCertStore(hStore, &pfxBlob, pwszPassword, EXPORT_PRIVATE_KEYS)) {
        pfxBlob.pbData = (BYTE*)malloc(pfxBlob.cbData);
        if (PFXExportCertStore(hStore, &pfxBlob, pwszPassword, EXPORT_PRIVATE_KEYS)) {
            FILE* f = fopen(filename, "wb");
            if (f) {
                fwrite(pfxBlob.pbData, 1, pfxBlob.cbData, f);
                fclose(f);
                printf("[OK] Exported %s successfully.\n", filename);
            } else {
                printf("[ERROR] Could not write to %s\n", filename);
            }
        }
        free(pfxBlob.pbData);
    } else {
        PrintError("PFXExportCertStore");
    }
    CertCloseStore(hStore, 0);
}

BOOL LoadExistingCA(LPCSTR caFile, LPCWSTR caPassW, PCCERT_CONTEXT* ppCACert, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE* phCAProv, DWORD* pdwKeySpec, BOOL* pfCallerFreeProv) {
    FILE* f = fopen(caFile, "rb");
    if (!f) return FALSE;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buf = (BYTE*)malloc(size);
    fread(buf, 1, size, f);
    fclose(f);

    CRYPT_DATA_BLOB pfxBlob = { (DWORD)size, buf };
    HCERTSTORE hStore = PFXImportCertStore(&pfxBlob, caPassW, CRYPT_EXPORTABLE);
    free(buf);

    if (!hStore) {
        PrintError("PFXImportCertStore");
        return FALSE;
    }

    *ppCACert = CertEnumCertificatesInStore(hStore, NULL);
    if (!*ppCACert) {
        printf("[ERROR] No certificate found in CA PFX.\n");
        CertCloseStore(hStore, 0);
        return FALSE;
    }

    if (!CryptAcquireCertificatePrivateKey(*ppCACert, 0, NULL, phCAProv, pdwKeySpec, pfCallerFreeProv)) {
        PrintError("CryptAcquireCertificatePrivateKey");
        CertFreeCertificateContext(*ppCACert);
        *ppCACert = NULL;
        CertCloseStore(hStore, 0);
        return FALSE;
    }

    CertCloseStore(hStore, 0);
    return TRUE;
}

int main() {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCAProv = 0;
    DWORD dwCAKeySpec = AT_SIGNATURE;
    BOOL fCallerFreeCAProv = FALSE;
    BOOL bGenerateCA = TRUE;

    HCRYPTPROV hUserProv = 0;
    HCRYPTKEY hCAKey = 0, hUserKey = 0;
    CERT_NAME_BLOB caNameBlob = {0};
    CERT_NAME_BLOB userNameBlob = {0};
    PCCERT_CONTEXT pCACert = NULL;
    PCCERT_CONTEXT pUserCert = NULL;
    PCERT_PUBLIC_KEY_INFO pUserPubKey = NULL;
    BYTE* pbUserCert = NULL;
    BYTE* pbEncodedSAN = NULL;

    // 1. Resolve INI Path and Create Default if Missing
    char iniPath[MAX_PATH];
    GetFullPathNameA(".\\make_certs.ini", MAX_PATH, iniPath, NULL);

    if (GetFileAttributesA(iniPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[INFO] Configuration file missing. Creating default '%s'...\n", iniPath);
        FILE* f = fopen(iniPath, "w");
        if (f) {
            fprintf(f, 
                "[CA]\n"
                "Subject=CN=Local Corporate Root CA, O=My Company, C=CA\n"
                "OutputFile=root_ca.pfx\n"
                "Password=secretpassword\n\n"
                "[User]\n"
                "Subject=CN=192.168.1.50, O=My Company, C=CA\n"
                "DNSName=myserver.local\n"
                "IPAddress=192.168.1.50\n"
                "OutputFile=dev_server.pfx\n"
                "Password=secretpassword\n\n"
                "[Settings]\n"
                "KeySizeBits=2048\n"
                "ValidityYears=5\n"
                "; Supported hashes: MD5, SHA1, SHA256, SHA384, SHA512\n"
                "HashAlgorithm=SHA256\n"
            );
            fclose(f);
        } else {
            printf("[ERROR] Failed to create default INI file.\n");
            return 1;
        }
    }

    // 2. Parse INI File
    char caSubject[256], userSubject[256], userIP[64], userDNS[256], hashAlgStr[32];
    char caFile[MAX_PATH], userFile[MAX_PATH];
    char caPassA[256], userPassA[256];
    WCHAR caPassW[256] = {0}, userPassW[256] = {0}, userDNSW[256] = {0};

    GetPrivateProfileStringA("CA", "Subject", "CN=Win32 Native CA", caSubject, sizeof(caSubject), iniPath);
    GetPrivateProfileStringA("CA", "OutputFile", "ca.pfx", caFile, sizeof(caFile), iniPath);
    GetPrivateProfileStringA("CA", "Password", "", caPassA, sizeof(caPassA), iniPath);
    
    GetPrivateProfileStringA("User", "Subject", "CN=Win32 Native User", userSubject, sizeof(userSubject), iniPath);
    GetPrivateProfileStringA("User", "DNSName", "", userDNS, sizeof(userDNS), iniPath);
    GetPrivateProfileStringA("User", "IPAddress", "", userIP, sizeof(userIP), iniPath);
    GetPrivateProfileStringA("User", "OutputFile", "user.pfx", userFile, sizeof(userFile), iniPath);
    GetPrivateProfileStringA("User", "Password", "", userPassA, sizeof(userPassA), iniPath);
    
    DWORD keyBits = GetPrivateProfileIntA("Settings", "KeySizeBits", 2048, iniPath);
    DWORD valYears = GetPrivateProfileIntA("Settings", "ValidityYears", 5, iniPath);
    GetPrivateProfileStringA("Settings", "HashAlgorithm", "SHA256", hashAlgStr, sizeof(hashAlgStr), iniPath);

    if (keyBits < 512 || keyBits > 16384) keyBits = 2048;

    MultiByteToWideChar(CP_ACP, 0, caPassA, -1, caPassW, 256);
    MultiByteToWideChar(CP_ACP, 0, userPassA, -1, userPassW, 256);
    if (strlen(userDNS) > 0) {
        MultiByteToWideChar(CP_ACP, 0, userDNS, -1, userDNSW, 256);
    }

    // Map INI string to CryptoAPI OID
    LPCSTR pszHashOID = szOID_RSA_SHA256RSA;
    if (_stricmp(hashAlgStr, "MD5") == 0) pszHashOID = szOID_RSA_MD5RSA;
    else if (_stricmp(hashAlgStr, "SHA1") == 0) pszHashOID = szOID_RSA_SHA1RSA;
    else if (_stricmp(hashAlgStr, "SHA256") == 0) pszHashOID = szOID_RSA_SHA256RSA;
    else if (_stricmp(hashAlgStr, "SHA384") == 0) pszHashOID = szOID_RSA_SHA384RSA;
    else if (_stricmp(hashAlgStr, "SHA512") == 0) pszHashOID = szOID_RSA_SHA512RSA;
    else printf("[WARN] Unknown hash '%s', defaulting to SHA256.\n", hashAlgStr);

    printf("User Subject: %s\n", userSubject);
    if (strlen(userDNS) > 0) printf("User DNS SAN: %s\n", userDNS);
    if (strlen(userIP) > 0) printf("User IP SAN:  %s\n", userIP);
    printf("Signature Alg: %s\n\n", hashAlgStr);

    CRYPT_ALGORITHM_IDENTIFIER sigAlg = {0};
    sigAlg.pszObjId = (LPSTR)pszHashOID;

    // 3. Check for existing CA File
    if (GetFileAttributesA(caFile) != INVALID_FILE_ATTRIBUTES) {
        printf("[INFO] Found existing CA at '%s', loading...\n", caFile);
        if (LoadExistingCA(caFile, caPassW, &pCACert, &hCAProv, &dwCAKeySpec, &fCallerFreeCAProv)) {
            bGenerateCA = FALSE;
        } else {
            printf("[WARN] Failed to load existing CA. Generating new...\n");
        }
    }

    // 4. Generate CA if needed
    if (bGenerateCA) {
        printf("[INFO] Generating NEW CA (%u-bit)...\n", (unsigned int)keyBits);
        if (!CreateNameBlob(caSubject, &caNameBlob)) return 1;

        CryptAcquireContextA((HCRYPTPROV*)&hCAProv, CA_CONTAINER_A, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        if (!CryptAcquireContextA((HCRYPTPROV*)&hCAProv, CA_CONTAINER_A, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_NEWKEYSET)) return 1;
        if (!CryptGenKey((HCRYPTPROV)hCAProv, AT_SIGNATURE, (keyBits << 16) | CRYPT_EXPORTABLE, &hCAKey)) return 1;

        CRYPT_KEY_PROV_INFO caKeyInfo = {0};
        caKeyInfo.pwszContainerName = CA_CONTAINER_W;
        caKeyInfo.pwszProvName = MS_ENH_RSA_AES_PROV_W;
        caKeyInfo.dwProvType = PROV_RSA_AES;
        caKeyInfo.dwKeySpec = AT_SIGNATURE;

        pCACert = CertCreateSelfSignCertificate((HCRYPTPROV)hCAProv, &caNameBlob, 0, &caKeyInfo, &sigAlg, NULL, NULL, NULL);
        if (!pCACert) return 1;

        ExportToPFX(pCACert, caPassW, caFile);
        dwCAKeySpec = AT_SIGNATURE;
        fCallerFreeCAProv = TRUE;
    }

    // 5. Generate User Keys
    printf("[INFO] Generating NEW User keys...\n");
    if (!CreateNameBlob(userSubject, &userNameBlob)) return 1;

    CryptAcquireContextA(&hUserProv, USER_CONTAINER_A, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_DELETEKEYSET);
    if (!CryptAcquireContextA(&hUserProv, USER_CONTAINER_A, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_NEWKEYSET)) return 1;
    if (!CryptGenKey(hUserProv, AT_SIGNATURE, (keyBits << 16) | CRYPT_EXPORTABLE, &hUserKey)) return 1;

    DWORD cbPubKey = 0;
    CryptExportPublicKeyInfo(hUserProv, AT_SIGNATURE, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &cbPubKey);
    pUserPubKey = (PCERT_PUBLIC_KEY_INFO)malloc(cbPubKey);
    CryptExportPublicKeyInfo(hUserProv, AT_SIGNATURE, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pUserPubKey, &cbPubKey);

    // 6. Configure User Certificate Properties
    CERT_INFO userInfo = {0};
    userInfo.dwVersion = CERT_V3;
    
    BYTE sn[4];
    CryptGenRandom(hUserProv, sizeof(sn), sn);
    sn[0] &= 0x7F;
    userInfo.SerialNumber.cbData = sizeof(sn);
    userInfo.SerialNumber.pbData = sn;
    
    userInfo.SignatureAlgorithm = sigAlg;
    userInfo.Issuer = pCACert->pCertInfo->Subject;
    userInfo.Subject = userNameBlob;
    userInfo.SubjectPublicKeyInfo = *pUserPubKey;

    SYSTEMTIME st;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &userInfo.NotBefore);
    st.wYear += (WORD)valYears; 
    SystemTimeToFileTime(&st, &userInfo.NotAfter);

    // 7. Construct the Subject Alternative Name (SAN) Extension (DNS and/or IP)
    CERT_EXTENSION extArray[1] = {0};
    CERT_ALT_NAME_ENTRY altNameEntries[2] = {0};
    CERT_ALT_NAME_INFO altNameInfo = {0};
    int altNameCount = 0;
    BYTE ipBytes[4] = {0};
    DWORD cbEncodedSAN = 0;
    unsigned int p1, p2, p3, p4;

    if (strlen(userDNS) > 0) {
        altNameEntries[altNameCount].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
        altNameEntries[altNameCount].pwszDNSName = userDNSW;
        altNameCount++;
    }

    if (strlen(userIP) > 0 && sscanf(userIP, "%u.%u.%u.%u", &p1, &p2, &p3, &p4) == 4) {
        ipBytes[0] = (BYTE)p1;
        ipBytes[1] = (BYTE)p2;
        ipBytes[2] = (BYTE)p3;
        ipBytes[3] = (BYTE)p4;

        altNameEntries[altNameCount].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
        altNameEntries[altNameCount].IPAddress.cbData = sizeof(ipBytes);
        altNameEntries[altNameCount].IPAddress.pbData = ipBytes;
        altNameCount++;
    }

    if (altNameCount > 0) {
        altNameInfo.cAltEntry = altNameCount;
        altNameInfo.rgAltEntry = altNameEntries;

        if (CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
            X509_ALTERNATE_NAME, &altNameInfo, 0, NULL, NULL, &cbEncodedSAN)) {
            
            pbEncodedSAN = (BYTE*)malloc(cbEncodedSAN);
            if (CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
                X509_ALTERNATE_NAME, &altNameInfo, 0, NULL, pbEncodedSAN, &cbEncodedSAN)) {
                
                extArray[0].pszObjId = szOID_SUBJECT_ALT_NAME2;
                extArray[0].fCritical = FALSE;
                extArray[0].Value.cbData = cbEncodedSAN;
                extArray[0].Value.pbData = pbEncodedSAN;
                
                userInfo.cExtension = 1;
                userInfo.rgExtension = extArray;
                printf("[INFO] Attached SAN Extension (%d entries)\n", altNameCount);
            }
        }
    }

    // 8. Sign User Certificate with CA
    DWORD cbUserCert = 0;
    if (!CryptSignAndEncodeCertificate(hCAProv, dwCAKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
        X509_CERT_TO_BE_SIGNED, &userInfo, &sigAlg, NULL, NULL, &cbUserCert)) return 1;
    
    pbUserCert = (BYTE*)malloc(cbUserCert);
    if (!CryptSignAndEncodeCertificate(hCAProv, dwCAKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
        X509_CERT_TO_BE_SIGNED, &userInfo, &sigAlg, NULL, pbUserCert, &cbUserCert)) return 1;

    pUserCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbUserCert, cbUserCert);

    // Bind User private key
    CRYPT_KEY_PROV_INFO userKeyInfo = {0};
    userKeyInfo.pwszContainerName = USER_CONTAINER_W;
    userKeyInfo.pwszProvName = MS_ENH_RSA_AES_PROV_W;
    userKeyInfo.dwProvType = PROV_RSA_AES;
    userKeyInfo.dwKeySpec = AT_SIGNATURE;
    CertSetCertificateContextProperty(pUserCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &userKeyInfo);

    ExportToPFX(pUserCert, userPassW, userFile);

    // 9. Cleanup
    if (pCACert) CertFreeCertificateContext(pCACert);
    if (pUserCert) CertFreeCertificateContext(pUserCert);
    if (pbUserCert) free(pbUserCert);
    if (pbEncodedSAN) free(pbEncodedSAN);
    if (pUserPubKey) free(pUserPubKey);
    if (caNameBlob.pbData) free(caNameBlob.pbData);
    if (userNameBlob.pbData) free(userNameBlob.pbData);
    if (hCAKey) CryptDestroyKey(hCAKey);
    if (hUserKey) CryptDestroyKey(hUserKey);
    if (fCallerFreeCAProv && hCAProv) CryptReleaseContext((HCRYPTPROV)hCAProv, 0);
    if (hUserProv) CryptReleaseContext(hUserProv, 0);

    return 0;
}
