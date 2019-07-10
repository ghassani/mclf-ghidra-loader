/**
-D__STDC__
-D_POSIX_C_SOURCE
-D_BSD_SOURCE
-D__WORDSIZE=32
*/
typedef unsigned long int uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef long int int64_t;
typedef int int32_t;
typedef short int16_t;
typedef char int8_t;
typedef unsigned int tlApiResult_t;
typedef unsigned int tlApiResult_t;
typedef uint32_t tlApiCrSession_t;
typedef uint32_t mcSpid_t;
typedef uint32_t mcRootid_t;
typedef uint64_t timestamp_t, *timestamp_ptr;
typedef uint32_t size_t;
typedef void    *addr_t;

typedef enum {
    TLAPI_RSA       = 0x00000001   /**< RSA public and RSA normal / crt private key. */
} tlApiKeyPairType_t;

typedef struct {
    uint8_t *key;   /**< Pointer to the key. */
    uint32_t len;   /**< Byte length of the key. */
} tlApiSymKey_t;

typedef struct {
    uint8_t *value;         /**< Pointer to value. Byte array in big endian format */
    uint32_t len;           /**< Byte length of value. */
} tlApiLongInt_t;

/** List of Message Digest algorithms. */
typedef enum {
    TLAPI_ALG_MD2       = (AF_MD | 1),   /**< Message Digest algorithm MD2. */
    TLAPI_ALG_MD5       = (AF_MD | 2),   /**< Message Digest algorithm MD5. */
    TLAPI_ALG_SHA1      = (AF_MD | 3),   /**< Message Digest algorithm SHA-1. */
    TLAPI_ALG_SHA256    = (AF_MD | 4),   /**< Message Digest algorithm SHA-256. */
	// Level 3+
    TLAPI_ALG_SHA384    = (AF_MD | 5),   /**< Message Digest algorithm SHA-384. */
    TLAPI_ALG_SHA512    = (AF_MD | 6)   /**< Message Digest algorithm SHA-512. */
} tlApiMdAlg_t;

typedef struct {
    tlApiLongInt_t  exponent;           /**< Pointer to public exponent . */

    tlApiLongInt_t  modulus;            /**< Modulus (if public key present) . */

    tlApiLongInt_t  privateExponent;    /**< Private exponent (if private key present) . */

    struct {
        tlApiLongInt_t Q;         /**< Pointer to prime q (if private crt key present). */
        tlApiLongInt_t P;         /**< Pointer to prime p (if private crt key present). */
        tlApiLongInt_t DQ;        /**< Pointer to DQ := D mod(Q-1) (if private crt key present). */
        tlApiLongInt_t DP;        /**< Pointer to DP := D mod(P-1) (if private crt key present). */
        tlApiLongInt_t Qinv;      /**< Pointer to Q inverse (Qinv) := 1/Q mod P  (if private crt key present). */
    } privateCrtKey;

} tlApiRsaKey_t;

typedef union {
    tlApiSymKey_t *symKey;              /**< Pointer to symmetric key. */
    tlApiRsaKey_t *rsaKey;              /**< Pointer to RSA key. */
} tlApiKey_t;

typedef union {
    tlApiRsaKey_t *rsaKeyPair;       /**< Pointer to RSA key structure. */
} tlApiKeyPair_t;

/** Main operation modes for cipher. */
typedef enum {
    TLAPI_MODE_ENCRYPT = 0x00000000,    /**< Encryption mode. */
    TLAPI_MODE_DECRYPT = 0x00000001     /**< Decryption mode. */
} tlApiCipherMode_t;

typedef enum {
    TLAPI_ALG_SECURE_RANDOM = (AF_RNG | 1),   /**< Random data which is considered to be cryptographically secure. */
    TLAPI_ALG_PSEUDO_RANDOM = (AF_RNG | 2)    /**< Pseudo random data, most likely a returning pattern. */
} tlApiRngAlg_t;

/** Main operation modes for signature. */
typedef enum {
    TLAPI_MODE_SIGN = 0x00000000,   /**< Signature generation mode. */
    TLAPI_MODE_VERIFY = 0x00000001  /**< Message and signature verification mode. */
} tlApiSigMode_t;

/** Invalid crypto session id returned in case of an error. */
#define CR_SID_INVALID      0xffffffff

/**
 * Algorithm ID is composed of group flags and a consecutive number.
 * The upper 16bit are used for grouping, whereas the lower 16bit
 * are available to distinguish algorithms within each group.
 */

/** Algorithm type flags. */
#define AF_CIPHER           (1U << 24)
#define AF_SIG              (2U << 24)
#define AF_MD               (4U << 24)
#define AF_RNG              (8U << 24)


/** Subgroups of cipher algorithms. */
#define AF_CIPHER_AES       (1U << 16)
#define AF_CIPHER_3DES      (2U << 16)
#define AF_CIPHER_DES       (4U << 16)
#define AF_CIPHER_RSA       (8U << 16)

/** List of Cipher algorithms.
 * An algorithm in this list is to be interpreted as a combination of cryptographic algorithm,
 * paddings, block sizes and other information.
 */
typedef enum {
    /*------- AES ciphers start here -------*/
    TLAPI_ALG_AES_128_CBC_NOPAD         = (AF_CIPHER | AF_CIPHER_AES | 1),      /**< AES (block length 128) with key size 128 in CBC mode, no padding. */
    TLAPI_ALG_AES_128_CBC_ISO9797_M1    = (AF_CIPHER | AF_CIPHER_AES | 2),      /**< AES (block length 128) with key size 128 in CBC mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_AES_128_CBC_ISO9797_M2    = (AF_CIPHER | AF_CIPHER_AES | 3),      /**< AES (block length 128) with key size 128 in CBC mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_AES_128_CBC_PKCS5         = (AF_CIPHER | AF_CIPHER_AES | 4),      /**< AES (block length 128) with key size 128 in CBC mode, padding according to the PKCS#5 scheme. */
    TLAPI_ALG_AES_128_CBC_PKCS7         = (AF_CIPHER | AF_CIPHER_AES | 6),      /**< AES (block length 128) with key size 128 in CBC mode, padding according to the PKCS#7 scheme. */
    TLAPI_ALG_AES_128_ECB_NOPAD         = (AF_CIPHER | AF_CIPHER_AES | 7),      /**< AES (block length 128) with key size 128 in ECB mode, no padding. */
    TLAPI_ALG_AES_128_ECB_ISO9797_M1    = (AF_CIPHER | AF_CIPHER_AES | 8),      /**< AES (block length 128) with key size 128 in ECB mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_AES_128_ECB_ISO9797_M2    = (AF_CIPHER | AF_CIPHER_AES | 9),      /**< AES (block length 128) with key size 128 in ECB mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_AES_128_ECB_PKCS5         = (AF_CIPHER | AF_CIPHER_AES | 0xa),    /**< AES (block length 128) with key size 128 in ECB mode, padding according to the PKCS#5 scheme. */
    TLAPI_ALG_AES_128_ECB_PKCS7         = (AF_CIPHER | AF_CIPHER_AES | 0xc),    /**< AES (block length 128) with key size 128 in ECB mode, padding according to the PKCS#7 scheme. */
    TLAPI_ALG_AES_128_CTR_NOPAD         = (AF_CIPHER | AF_CIPHER_AES | 0xd),    /**< AES (block length 128) with key size 128 in CTR mode, no padding. */
    TLAPI_ALG_AES_256_CBC_NOPAD         = (AF_CIPHER | AF_CIPHER_AES | 0x10),   /**< AES (block length 128) with key size 256 in CBC mode, no padding. */
    TLAPI_ALG_AES_256_CBC_ISO9797_M1    = (AF_CIPHER | AF_CIPHER_AES | 0x11),   /**< AES (block length 128) with key size 256 in CBC mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_AES_256_CBC_ISO9797_M2    = (AF_CIPHER | AF_CIPHER_AES | 0x12),   /**< AES (block length 128) with key size 256 in CBC mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_AES_256_CBC_PKCS5         = (AF_CIPHER | AF_CIPHER_AES | 0x13),   /**< AES (block length 128) with key size 256 in CBC mode, padding according to the PKCS#5 scheme. */
    TLAPI_ALG_AES_256_CBC_PKCS7         = (AF_CIPHER | AF_CIPHER_AES | 0x15),   /**< AES (block length 128) with key size 256 in CBC mode, padding according to the PKCS#7 scheme. */
    TLAPI_ALG_AES_256_ECB_NOPAD         = (AF_CIPHER | AF_CIPHER_AES | 0x16),   /**< AES (block length 128) with key size 256 in ECB mode, no padding. */
    TLAPI_ALG_AES_256_ECB_ISO9797_M1    = (AF_CIPHER | AF_CIPHER_AES | 0x17),   /**< AES (block length 128) with key size 256 in ECB mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_AES_256_ECB_ISO9797_M2    = (AF_CIPHER | AF_CIPHER_AES | 0x18),   /**< AES (block length 128) with key size 256 in ECB mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_AES_256_ECB_PKCS5         = (AF_CIPHER | AF_CIPHER_AES | 0x19),   /**< AES (block length 128) with key size 256 in ECB mode, padding according to the PKCS#5 scheme. */
    TLAPI_ALG_AES_256_ECB_PKCS7         = (AF_CIPHER | AF_CIPHER_AES | 0x1b),   /**< AES (block length 128) with key size 256 in ECB mode, padding according to the PKCS#7 scheme. */
    TLAPI_ALG_AES_256_CTR_NOPAD         = (AF_CIPHER | AF_CIPHER_AES | 0x1c),   /**< AES (block length 128) with key size 256 in CTR mode, no padding. */

    /*------- Triple-DES ciphers start here -------*/
    TLAPI_ALG_3DES_CBC_ISO9797_M1       = (AF_CIPHER | AF_CIPHER_3DES | 1),  /**< Triple DES with key size 16 byte in outer CBC mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_3DES_CBC_ISO9797_M2       = (AF_CIPHER | AF_CIPHER_3DES | 2),  /**< Triple DES with key size 16 byte in outer CBC mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_3DES_CBC_NOPAD            = (AF_CIPHER | AF_CIPHER_3DES | 3),  /**< Triple DES with key size 16 byte in outer CBC mode, no padding. */
    TLAPI_ALG_3DES_CBC_PKCS5            = (AF_CIPHER | AF_CIPHER_3DES | 4),  /**< Triple DES with key size 16 byte in outer CBC mode, padding according to the PKCS#5 scheme. */
#if TBASE_API_LEVEL >= 3
    TLAPI_ALG_3DES_2KEY_CBC_ISO9797_M1   =  TLAPI_ALG_3DES_CBC_ISO9797_M1,
    TLAPI_ALG_3DES_2KEY_CBC_ISO9797_M2   =  TLAPI_ALG_3DES_CBC_ISO9797_M2,
    TLAPI_ALG_3DES_2KEY_CBC_NOPAD        =  TLAPI_ALG_3DES_CBC_NOPAD,
    TLAPI_ALG_3DES_2KEY_CBC_PKCS5        =  TLAPI_ALG_3DES_CBC_PKCS5,
    TLAPI_ALG_3DES_3KEY_CBC_ISO9797_M1   = (AF_CIPHER | AF_CIPHER_3DES | 5),  /**< Triple DES with key size 24 byte in outer CBC mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_3DES_3KEY_CBC_ISO9797_M2   = (AF_CIPHER | AF_CIPHER_3DES | 6),  /**< Triple DES with key size 24 byte in outer CBC mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_3DES_3KEY_CBC_NOPAD        = (AF_CIPHER | AF_CIPHER_3DES | 7),  /**< Triple DES with key size 24 byte in outer CBC mode, no padding. */
    TLAPI_ALG_3DES_3KEY_CBC_PKCS5        = (AF_CIPHER | AF_CIPHER_3DES | 8),  /**< Triple DES with key size 24 byte in outer CBC mode, padding according to the PKCS#5 scheme. */
#endif /* TBASE_API_LEVEL */

    /*------- DES ciphers start here -------*/
    TLAPI_ALG_DES_CBC_ISO9797_M1        = (AF_CIPHER | AF_CIPHER_DES | 1),   /**< DES in CBC mode or triple DES in outer CBC mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_DES_CBC_ISO9797_M2        = (AF_CIPHER | AF_CIPHER_DES | 2),   /**< DES in CBC mode or triple DES in outer CBC mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_DES_CBC_NOPAD             = (AF_CIPHER | AF_CIPHER_DES | 3),   /**< DES in CBC mode or triple DES in outer CBC mode, no padding. */
    TLAPI_ALG_DES_CBC_PKCS5             = (AF_CIPHER | AF_CIPHER_DES | 4),   /**< DES in CBC mode or triple DES in outer CBC mode, padding according to the PKCS#5 scheme. */
    TLAPI_ALG_DES_ECB_ISO9797_M1        = (AF_CIPHER | AF_CIPHER_DES | 5),   /**< DES in ECB mode, padding according to the ISO 9797 method 1 scheme. */
    TLAPI_ALG_DES_ECB_ISO9797_M2        = (AF_CIPHER | AF_CIPHER_DES | 6),   /**< DES in ECB mode, padding according to the ISO 9797 method 2 (ISO 7816-4, EMV'96) scheme. */
    TLAPI_ALG_DES_ECB_NOPAD             = (AF_CIPHER | AF_CIPHER_DES | 7),   /**< DES in ECB mode, no padding. */
    TLAPI_ALG_DES_ECB_PKCS5             = (AF_CIPHER | AF_CIPHER_DES | 8),   /**< DES in ECB mode, padding according to the PKCS#5 scheme. */

    /*------- RSA ciphers start here -------*/
    TLAPI_ALG_RSA_ISO14888              = (AF_CIPHER | AF_CIPHER_RSA | 1),   /**< RSA, padding according to the ISO 14888 scheme. */
    TLAPI_ALG_RSA_NOPAD                 = (AF_CIPHER | AF_CIPHER_RSA | 2),   /**< RSA, no padding. */
    TLAPI_ALG_RSA_PKCS1                 = (AF_CIPHER | AF_CIPHER_RSA | 3),   /**< RSA, padding according to the PKCS#1 (v1.5) scheme. */

    /*------- RSA CRT ciphers start here -------*/
    TLAPI_ALG_RSACRT_ISO14888           = TLAPI_ALG_RSA_ISO14888,
    TLAPI_ALG_RSACRT_NOPAD              = TLAPI_ALG_RSA_NOPAD,
    TLAPI_ALG_RSACRT_PKCS1              = TLAPI_ALG_RSA_PKCS1
} tlApiCipherAlg_t;

#define MC_PRODUCT_ID_LEN 64

typedef struct {
    char productId[MC_PRODUCT_ID_LEN]; /** < Product ID of Mobicore; zero-terminated */
    uint32_t versionMci;               /** < Version of Mobicore Control Interface */
    uint32_t versionSo;                /** < Version of Secure Objects */
    uint32_t versionMclf;              /** < Version of MobiCore Load Format */
    uint32_t versionContainer;         /** < Version of MobiCore Container Format */
    uint32_t versionMcConfig;          /** < Version of MobiCore Configuration Block Format */
    uint32_t versionTlApi;             /** < Version of MobiCore Trustlet API Implementation */
    uint32_t versionDrApi;             /** < Version of MobiCore Driver API Implementation */
    uint32_t versionCmp;               /** < Version of Content Management Protocol */
} mcVersionInfo_t;

/** Length of SUID. */
#define MC_SUID_LEN    16

/** Platform specific device identifier (serial number of the chip). */
typedef struct {
    uint8_t data[MC_SUID_LEN - sizeof(uint32_t)];
} suidData_t;

/** Soc unique identifier type. */
typedef struct {
    uint32_t    sipId;  /**< Silicon Provider ID to be set during build. */
    suidData_t  suidData;
} mcSuid_t;

/** List of Signature algorithms.
 * An algorithm in this list is to be interpreted as a combination of cryptographic algorithm,
 * paddings, block sizes and other information.
 */
typedef enum {
    /*------- Retail MAC's start here -------*/
    TLAPI_ALG_DES_MAC4_NOPAD                = (AF_SIG | AF_SIG_DES | 1),   /**< 4-byte MAC (most significant 4 bytes of encrypted block) using DES in CBC mode or triple DES in outer CBC mode. */
    TLAPI_ALG_DES_MAC4_PKCS5                = (AF_SIG | AF_SIG_DES | 2),   /**< 4-byte MAC (most significant 4 bytes of encrypted block) using DES in CBC mode or triple DES in outer CBC mode. */
    TLAPI_ALG_DES_MAC8_ISO9797_1_M2_ALG3    = (AF_SIG | AF_SIG_DES | 3),   /**< 8-byte MAC using a 2-key DES3 key according to ISO9797-1 MAC algorithm 3
                                                                            with method 2 (also EMV'96, EMV'2000), where input data is padded
                                                                            using method 2 and the data is processed as described
                                                                            in MAC Algorithm 3 of the ISO 9797-1 specification. */
    TLAPI_ALG_DES_MAC8_ISO9797_M1           = (AF_SIG | AF_SIG_DES | 4),   /**< 8-byte MAC using DES in CBC mode or triple DES in outer CBC mode. */
    TLAPI_ALG_DES_MAC8_ISO9797_M2           = (AF_SIG | AF_SIG_DES | 5),   /**< 8-byte MAC using DES in CBC mode or triple DES in outer CBC mode. */
    TLAPI_ALG_DES_MAC8_NOPAD                = (AF_SIG | AF_SIG_DES | 6),   /**< 8-byte MAC using DES in CBC mode or triple DES in outer CBC mode. */
    TLAPI_ALG_DES_MAC8_PKCS5                = (AF_SIG | AF_SIG_DES | 7),   /**< 8-byte MAC using DES in CBC mode or triple DES in outer CBC mode. */

    /*------- SHA MAC's start here -------*/
    TLAPI_ALG_HMAC_SHA_256                  = (AF_SIG | AF_SIG_HMAC | 1),  /**< HMAC following the steps found in RFC: 2104 using SHA-256 as the hashing algorithm. */
    TLAPI_ALG_HMAC_SHA1                     = (AF_SIG | AF_SIG_HMAC | 2),  /**< HMAC following the steps found in RFC: 2104 using SHA1 as the hashing algorithm. */

    /*------- RSA starts here -------*/
    TLAPI_SIG_RSA_SHA_ISO9796               = (AF_SIG | AF_SIG_RSA | 1),   /**< 20-byte SHA-1 digest, padded according to the ISO 9796-2 scheme as specified in EMV '96 and EMV 2000, encrypted using RSA. */
    TLAPI_SIG_RSA_SHA_ISO9796_MR            = (AF_SIG | AF_SIG_RSA | 2),   /**< 20-byte SHA-1 digest, padded according to the ISO9796-2 specification and encrypted using RSA. */
    TLAPI_SIG_RSA_SHA_PKCS1                 = (AF_SIG | AF_SIG_RSA | 3),   /**< 20-byte SHA-1 digest, padded according to the PKCS#1 (v1.5) scheme, and encrypted using RSA. */
    TLAPI_SIG_RSA_SHA256_PSS                = (AF_SIG | AF_SIG_RSA | 4),   /**< RSASSA-PSS-VERIFY, ContenDigest-SHA256, MfgDigest-SHA256. */
    TLAPI_SIG_RSA_SHA1_PSS                  = (AF_SIG | AF_SIG_RSA | 5),   /**< RSASSA-PSS-VERIFY, ContenDigest-SHA1, MfgDigest-SHA1. */

    /*------- RSA CRT ciphers start here -------*/
    TLAPI_SIG_RSACRT_SHA_ISO9796            = TLAPI_SIG_RSA_SHA_ISO9796,
    TLAPI_SIG_RSACRT_SHA_ISO9796_MR         = TLAPI_SIG_RSA_SHA_ISO9796_MR,
    TLAPI_SIG_RSACRT_SHA_PKCS1              = TLAPI_SIG_RSA_SHA_PKCS1,
    TLAPI_SIG_RSACRT_SHA256_PSS             = TLAPI_SIG_RSA_SHA256_PSS,
    TLAPI_SIG_RSACRT_SHA1_PSS               = TLAPI_SIG_RSA_SHA1_PSS

} tlApiSigAlg_t;

/** Secure object type. */
typedef enum {
    /** Regular secure object. */
    MC_SO_TYPE_REGULAR = 0x00000001,
    /** Dummy to ensure that enum is 32 bit wide. */
    MC_SO_TYPE_DUMMY = MC_ENUM_32BIT_SPACER,
} mcSoType_t;

#define UUID_LENGTH 16

typedef struct {
    uint8_t value[UUID_LENGTH]; /**< Value of the UUID. */
} mcUuid_t, *mcUuid_ptr;

/** Secure object context.
 * A context defines which key to use to encrypt/decrypt a secure object.
 */
typedef enum {
    /** Trustlet context. */
    MC_SO_CONTEXT_TLT = 0x00000001,
     /** Service provider context. */
    MC_SO_CONTEXT_SP = 0x00000002,
     /** Device context. */
    MC_SO_CONTEXT_DEVICE = 0x00000003,
    /** Dummy to ensure that enum is 32 bit wide. */
    MC_SO_CONTEXT_DUMMY = MC_ENUM_32BIT_SPACER,
} mcSoContext_t;

/** Secure object lifetime.
 * A lifetime defines how long a secure object is valid.
 */
typedef enum {
    /** SO does not expire. */
    MC_SO_LIFETIME_PERMANENT = 0x00000000,
    /** SO expires on reboot (coldboot). */
    MC_SO_LIFETIME_POWERCYCLE = 0x00000001,
    /** SO expires when Trustlet is closed. */
    MC_SO_LIFETIME_SESSION = 0x00000002,
    /** Dummy to ensure that enum is 32 bit wide. */
    MC_SO_LIFETIME_DUMMY = MC_ENUM_32BIT_SPACER,
} mcSoLifeTime_t;

/** Success */
#define TLAPI_DRM_OK                            TLAPI_OK

/** Invalid parameter for cipher operation */
#define E_TLAPI_DRM_INVALID_PARAMS              0x00000601

/** Internal error in the driver */
#define E_TLAPI_DRM_INTERNAL                    0x00000602

/** Driver mapping error */
#define E_TLAPI_DRM_MAP                         0x00000603

/** Permission denied */
#define E_TLAPI_DRM_PERMISSION_DENIED           0x00000604

/** If the output address is not protected. */
#define E_TLAPI_DRM_REGION_NOT_SECURE           0x00000605

/** If a single session implementation is already active, or a multi session implementation has no free sessions. */
#define E_TLAPI_DRM_SESSION_NOT_AVAILABLE       0x00000606

/** Invalid Command ID. */
#define E_TLAPI_DRM_INVALID_COMMAND             0x00000607

/** If algorithm is not supported by the driver. */
#define E_TLAPI_DRM_ALGORITHM_NOT_SUPPORTED     0x00000608

/** If the functions have not been implemented. */
#define E_TLAPI_DRM_DRIVER_NOT_IMPLEMENTED      0x00000609
/** DRM 128 bits key size */
#define TLAPI_DRM_KEY_SIZE_128            16
/** DRM 192 bits key size */
#define TLAPI_DRM_KEY_SIZE_192            24
/** DRM 256 bits key size */
#define TLAPI_DRM_KEY_SIZE_256            32
/** DRM data given to driver is encrypted, the driver shall decrypt. */
#define TLAPI_DRM_PROCESS_ENCRYPTED_DATA   1
/** DRM data given to driver is decrypted, the driver shall only decode. */
#define TLAPI_DRM_PROCESS_DECRYPTED_DATA   2
/** Number of offset/size pair in input descriptor */
#define TLAPI_DRM_INPUT_PAIR_NUMBER     10

/** DRM Encryption Algoritms */
typedef enum {
    TLAPI_DRM_ALG_NONE,
    TLAPI_DRM_ALG_AES_ECB,
    TLAPI_DRM_ALG_AES_CBC,
    TLAPI_DRM_ALG_AES_CTR32,
    TLAPI_DRM_ALG_AES_CTR64,
    TLAPI_DRM_ALG_AES_CTR96,
    TLAPI_DRM_ALG_AES_CTR128,
    TLAPI_DRM_ALG_AES_XTS,
    TLAPI_DRM_ALG_AES_CBCCTS
} tlApiDrmAlg_t;

/** DRM External Links */
typedef enum {
    TLAPI_DRM_LINK_HDCP_1,
    TLAPI_DRM_LINK_HDCP_2,
    TLAPI_DRM_LINK_AIRPLAY,
    TLAPI_DRM_LINK_DTCP
} tlApiDrmLink_t;

/** DRM frame/block definition */
typedef struct {
    /** size of encrypted block */
    uint32_t nSize;
    /** offset from start of buffer to start of encrypted block */
    uint32_t nOffset;
} tlApiDrmOffsetSizePair_t;

/** DRM Input data */
typedef struct {
    /** size of whole data (plain + encrypted) */
    uint32_t                    nTotalSize;
    /** number of blocks of encrypted data within the buffer */
    uint32_t                    nNumBlocks;
    /** Encrypted blocks */
    tlApiDrmOffsetSizePair_t    aPairs[TLAPI_DRM_INPUT_PAIR_NUMBER];
} tlApiDrmInputSegmentDescriptor_t;


/**
 * For DRM cipher/copy operations
 *
 * Parameters
 * @param  key          [in]  content key
 * @param  key_len      [in]  key length in bytes (16,24,32)
 * @param  iv           [in]  initialization vector. Always 16 bytes.
 * @param  ivlen        [in]  length initialization vector.
 * @param  alg          [in]  algorithm
 * @param  outputoffset [in]  output data offset
 *
 */
typedef struct {
    uint8_t                *key;
    int32_t                keylen;
    uint8_t                *iv;
    uint32_t          	   ivlen;
    tlApiDrmAlg_t          alg;
    uint32_t               outputoffet;
} tlApiDrmDecryptContext_t;


/******************************************************************************
 *                            INPUT / OUTPUT                                  *
 ******************************************************************************/

/** Coordinates
 * These are related to the top-left corner of the screen. */
typedef struct {
    uint32_t    xOffset;   /**< x coordinate. */
    uint32_t    yOffset;   /**< y coordinate. */
} tlApiTuiCoordinates_t, *tlApiTuiCoordinates_ptr;

/** Type of touch event */
typedef enum {
    TUI_TOUCH_EVENT_RELEASED = 0,   /**< A pressed gesture has finished. */
    TUI_TOUCH_EVENT_PRESSED  = 1,   /**< A pressed gesture has occurred. */
} tlApiTuiTouchEventType_t;

/** Touch event */
typedef struct {
    tlApiTuiTouchEventType_t   type;        /**< Type of touch event. */
    tlApiTuiCoordinates_t      coordinates; /**< Coordinates of the touch event
                                             *   in the screen. */
} tlApiTuiTouchEvent_t, *tlApiTuiTouchEvent_ptr;

/** Image file */
typedef struct {
    void*       imageFile;         /**< a buffer containing the image file. */
    uint32_t    imageFileLength;   /**< size of the buffer. */
} tlApiTuiImage_t, *tlApiTuiImage_ptr;

typedef struct {
    /** Service provider id. */
    mcSpid_t spid;
    /** Trustlet UUID. */
    mcUuid_t uuid;
} tlApiSpTrustletId_t;

typedef struct {
    /** Type of secure object. */
    uint32_t type;
    /** Secure object version. */
    uint32_t version;
    /** Secure object context. */
    mcSoContext_t context;
    /** Secure object lifetime. */
    mcSoLifeTime_t lifetime;
    /** Producer Trustlet id. */
    tlApiSpTrustletId_t producer;
    /** Length of unencrypted user data (after the header). */
    uint32_t plainLen;
    /** Length of encrypted user data (after unencrypted data, excl. checksum
     * and excl. padding bytes). */
    uint32_t encryptedLen;
} mcSoHeader_t;

/** Maximum size of the payload (plain length + encrypted length) of a secure object. */
#define MC_SO_PAYLOAD_MAX_SIZE      1000000

/** Block size of encryption algorithm used for secure objects. */
#define MC_SO_ENCRYPT_BLOCK_SIZE    16

/** Maximum number of ISO padding bytes. */
#define MC_SO_MAX_PADDING_SIZE (MC_SO_ENCRYPT_BLOCK_SIZE)

/** Size of hash used for secure objects v2. */
#define MC_SO_HASH_SIZE             32

/** Size of hash used for secure object v2.1. */
#define MC_SO21_HASH_SIZE            24
/** Size of random used for secure objects v2.1. */
#define MC_SO21_RND_SIZE             9

/** Size of hash used for secure object v2.2. */
#define MC_SO22_HASH_SIZE            32
/** Size of random used for secure objects v2.2. */
#define MC_SO22_RND_SIZE             16

/** Hash size for current generated wrapping */
#define MC_SO2X_HASH_SIZE MC_SO22_HASH_SIZE
/** Random size for current generated wrapping */
#define MC_SO2X_RND_SIZE MC_SO22_RND_SIZE

#define MC_SO_ENCRYPT_PADDED_SIZE_F21(netsize) ( (netsize) + \
    MC_SO_MAX_PADDING_SIZE - (netsize) % MC_SO_MAX_PADDING_SIZE )
    #define MC_SO_ENCRYPT_PADDED_SIZE(netsize) MC_SO_ENCRYPT_PADDED_SIZE_F21(netsize)

/** Calculates the total size of a secure object.
 * @param plainLen Length of plain text part within secure object.
 * @param encryptedLen Length of encrypted part within secure object (excl.
 * hash, padding).
 * @return Total (gross) size of the secure object or 0 if given parameters are
 * illegal or would lead to a secure object of invalid size.
 */
#define MC_SO_SIZE_F22(plainLen, encryptedLen) ( \
    ((plainLen) + (encryptedLen) < (encryptedLen) || (plainLen) + (encryptedLen) > MC_SO_PAYLOAD_MAX_SIZE) ? 0 : \
            sizeof(mcSoHeader_t) + (plainLen) + (encryptedLen) +MC_SO22_HASH_SIZE +MC_SO22_RND_SIZE \
    )
#define MC_SO_SIZE_F21(plainLen, encryptedLen) ( \
    ((plainLen) + (encryptedLen) < (encryptedLen) || (plainLen) + (encryptedLen) > MC_SO_PAYLOAD_MAX_SIZE) ? 0 : \
            sizeof(mcSoHeader_t) +(plainLen) +MC_SO_ENCRYPT_PADDED_SIZE_F21((encryptedLen) +MC_SO_HASH_SIZE) \
)

#define MC_SO_SIZE(plainLen, encryptedLen) MC_SO_SIZE_F22(plainLen, encryptedLen)

typedef enum {
    MC_SCOPE_TRUSTED_APPLICATION = 1,
    MC_SCOPE_CONTAINER,
    MC_SCOPE_INVALID,
} mcScope_t;

// Entry Point Signature
void tlMain(const addr_t tciBuffer, const uint32_t  tciBufferLen);

// Function Signatures
tlApiResult_t tlApiWaitNotification(uint32_t timeout);
tlApiResult_t tlApiNotify(void);
tlApiResult_t tlApiCrAbort(tlApiCrSession_t sessionHandle);
tlApiResult_t tlApiGenerateKeyPair(tlApiKeyPair_t * keyPair, tlApiKeyPairType_t keyPairType, size_t len);
tlApiResult_t tlApiCipherInit(tlApiCrSession_t *pSessionHandle, tlApiCipherAlg_t alg, tlApiCipherMode_t mode, const tlApiKey_t *key);
tlApiResult_t tlApiCipherInitWithData(tlApiCrSession_t *pSessionHandle, tlApiCipherAlg_t alg, tlApiCipherMode_t mode, const tlApiKey_t *key, const uint8_t *buffer, size_t bufferLen);
tlApiResult_t tlApiCipherUpdate(tlApiCrSession_t sessionHandle, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);
tlApiResult_t tlApiSignatureInit(tlApiCrSession_t *pSessionHandle, const tlApiKey_t *key, tlApiSigMode_t mode, tlApiSigAlg_t alg);
tlApiResult_t tlApiSignatureInitWithData(tlApiCrSession_t *pSessionHandle, const tlApiKey_t *key, tlApiSigMode_t mode, tlApiSigAlg_t alg, const uint8_t *buffer, size_t bufferLen);
tlApiResult_t tlApiCipherDoFinal(tlApiCrSession_t sessionHandle, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);
tlApiResult_t tlApiSignatureUpdate(tlApiCrSession_t sessionHandle, const uint8_t *message, size_t messageLen);
tlApiResult_t tlApiSignatureSign(tlApiCrSession_t sessionHandle, const uint8_t *message, size_t messageLen, uint8_t *signature, size_t *signatureLen);
tlApiResult_t tlApiSignatureVerify(tlApiCrSession_t sessionHandle, const uint8_t *message, size_t messageLen, const uint8_t *signature, size_t signatureLen, bool *validity);
tlApiResult_t tlApiMessageDigestInit(tlApiCrSession_t *pSessionHandle, tlApiMdAlg_t algorithm);
tlApiResult_t tlApiMessageDigestInitWithData( tlApiCrSession_t *pSessionHandle, tlApiMdAlg_t alg, const uint8_t *buffer, const uint8_t lengthOfDataHashedPreviously[8]);
tlApiResult_t tlApiMessageDigestUpdate(tlApiCrSession_t sessionHandle, const uint8_t *message, size_t messageLen);
tlApiResult_t tlApiMessageDigestDoFinal(tlApiCrSession_t sessionHandle, const uint8_t *message, size_t messageLen, uint8_t *hash, size_t *hashLen);
tlApiResult_t tlApiRandomGenerateData(tlApiRngAlg_t alg, uint8_t *randomBuffer, size_t *randomLen);
void * tlApiMalloc(uint32_t size, uint32_t hint);
void * tlApiRealloc(void* buffer, uint32_t newSize);
void tlApiFree(void *buffer);
//void tlApiLogvPrintf(const char *fmt, va_list args);
void tlApiLogPrintf(const char *fmt, ...);
tlApiResult_t tlApiGetVersion(uint32_t *tlApiVersion);
tlApiResult_t tlApiGetMobicoreVersion(mcVersionInfo_t * mcVersionInfo);
void tlApiExit(uint32_t exitCode);
tlApiResult_t tlApiGetSuid(mcSuid_t *suid);
tlApiResult_t tlApiGetVirtMemType( uint32_t *type, addr_t addr, uint32_t size);
tlApiResult_t tlApiWrapObjectExt(const void *src, size_t plainLen, size_t encryptedLen, void *dest, size_t *destLen, mcSoContext_t context, mcSoLifeTime_t lifetime, const tlApiSpTrustletId_t *consumer, uint32_t flags);
tlApiResult_t tlApiUnwrapObjectExt(void *src, size_t srcLen, void *dest, size_t *destLen, uint32_t flags );
tlApiResult_t tlApiDeriveKey(const void *salt, size_t saltLen, void *dest, size_t destLen, mcSoContext_t context, mcSoLifeTime_t lifetime);
tlApiResult_t tlApiEndorse(const void *msg, size_t msgLen, void *dst, size_t *dstLen, mcScope_t scope);
tlApiResult_t tlApiGetSecureTimestamp(timestamp_ptr pTimestamp);
tlApiResult_t tlApiDrmProcessContent(uint8_t sHandle, tlApiDrmDecryptContext_t decryptCtx, uint8_t *input, tlApiDrmInputSegmentDescriptor_t inputDesc, uint16_t processMode, uint8_t *output);
tlApiResult_t tlApiDrmOpenSession(uint8_t *sHandle);
tlApiResult_t tlApiDrmCloseSession(uint8_t sHandle);
tlApiResult_t tlApiDrmCheckLink(uint8_t sHandle, tlApiDrmLink_t link);
tlApiResult_t tlApiTuiSetImage(tlApiTuiImage_ptr image, tlApiTuiCoordinates_t coordinates);
tlApiResult_t tlApiTuiGetTouchEvent(tlApiTuiTouchEvent_ptr touchEvent);