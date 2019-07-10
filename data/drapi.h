typedef unsigned long int uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef long int int64_t;
typedef int int32_t;
typedef short int16_t;
typedef char int8_t;

typedef unsigned int	u32_t;
typedef unsigned short	u16_t;
typedef unsigned char	u08_t;
typedef u32_t		word_t;
typedef void    *addr_t;
typedef uint64_t timestamp_t, *timestamp_ptr;

//Common result type
typedef word_t drApiResult_t;

//MTK types
typedef word_t  taskid_t,   *taskid_ptr;     /**< task id data type. */
typedef word_t  threadno_t, *threadno_ptr;   /**< thread no. data type. */
typedef word_t  threadid_t, *threadid_ptr;   /**< thread id data type. */

//Stack types
typedef uint32_t        stackEntry_t;
typedef stackEntry_t    *stackEntry_ptr;
typedef stackEntry_ptr  stackTop_ptr;


// interrupt mode flags. The design of the bits is that most common setting
// RISING, EDGE, PERIODIC maps to the value the value 0. Not all mode
// combinations may be available for each interrupt.
#define INTR_MODE_MASK_TRIGGER          	(1U<<0)
#define INTR_MODE_TRIGGER_LEVEL           	INTR_MODE_MASK_TRIGGER
#define INTR_MODE_TRIGGER_EDGE            	0
#define INTR_MODE_MASK_CONDITION        	(1U<<1)
#define INTR_MODE_CONDITION_FALLING       	INTR_MODE_MASK_CONDITION
#define INTR_MODE_CONDITION_LOW           	INTR_MODE_MASK_CONDITION
#define INTR_MODE_CONDITION_RISING        	0
#define INTR_MODE_CONDITION_HIGH          	0
#define INTR_MODE_MASK_OCCURANCE        	(1U<<2)
#define INTR_MODE_OCCURANCE_ONESHOT       	INTR_MODE_MASK_OCCURANCE
#define INTR_MODE_OCCURANCE_PERIODIC      	0

// convenience constants
#define INTR_MODE_RAISING_EDGE              (INTR_MODE_TRIGGER_EDGE | INTR_MODE_CONDITION_RISING)
#define INTR_MODE_FALLING_EDGE              (INTR_MODE_TRIGGER_EDGE | INTR_MODE_CONDITION_FALLING)
#define INTR_MODE_LOW_LEVEL                 (INTR_MODE_TRIGGER_LEVEL | INTR_MODE_CONDITION_LOW)
#define INTR_MODE_HIGH_LEVEL                (INTR_MODE_TRIGGER_LEVEL | INTR_MODE_CONDITION_HIGH)

//Interrupt types
typedef word_t  intrNo_t, *intrNo_ptr;      /**< interrupt number. */
typedef word_t  intrMode_t, *intrMode_ptr;  /**< interrupt mode. */

/** Memory mapping attributes. */
#define MAP_READABLE            (1U << 0)               /**< mapping gives  have the ability to do read access. */
#define MAP_WRITABLE            (1U << 1)               /**< mapping gives  have the ability to do write access. */
#define MAP_EXECUTABLE          (1U << 2)               /**< mapping gives  have the ability to do program execution. */
#define MAP_UNCACHED            (1U << 3)               /**< mapping gives  have uncached memory access. */
#define MAP_IO                  (1U << 4)               /**< mapping gives  have memory mapped I/O access. Will ignore MAP_UNCACHED, as this would be implied anyway. */

//------------------------------------------------------------------------------
/** Maximum number of parameter . */
#define MAX_MAR_LIST_LENGTH 	8                      /**< Maximum list of possible marshaling parameters. */
/** Marshaled union. */
typedef struct {
    uint32_t     functionId;                       /**< Function identifier. */
    union {
        uint32_t                            parameter[MAX_MAR_LIST_LENGTH];   /* untyped parameter list (expands union to 8 entries) */
    } payload;
} drApiMarshalingParam_t, *drApiMarshalingParam_ptr;

//------------------------------------------------------------------------------
/** Possible message types/event types of the system. */
typedef enum {
    MSG_NULL = 0,  // Used for initializing state machines
    MSG_RQ                          = 1,
        // Client Request, blocks until MSG_RS is received
        // Client -> Server
    MSG_RS                          = 2,
        // Driver Response, answer to MSG_RQ
        // Server -> Client
    MSG_RD                          = 3,
        // Driver becomes ready
        // Server -> IPCH
    MSG_NOT                         = 4,
        // Notification to NWd for a session, send-only message with no
        // response
        // client/server -> IPCH;
    MSG_CLOSE_TRUSTLET              = 5,
        // Close Trustlet, must be answered by MSG_CLOSE_TRUSTLET_ACK
        // MSH -> IPCH, IPCH -> Server
    MSG_CLOSE_TRUSTLET_ACK          = 6,
        // Close Trustlet Ack, in response to MSG_CLOSE_TRUSTLET
        // Server -> IPCH
    MSG_MAP                         = 7,
        // Map Client into Server, send-only message with no reponse
        //Server -> IPCH;
    MSG_ERR_NOT                     = 8,
        // Error Notification
        // EXCH/SIQH -> IPCH
    MSG_CLOSE_DRIVER                = 9,
        // Close Driver, must be answered with MSG_CLOSE_DRIVER_ACK
        // MSH -> IPCH, IPCH -> Driver/Server
    MSG_CLOSE_DRIVER_ACK            = 10,
        // Close Driver Ack, response to MSG_CLOSE_DRIVER
        // Driver/Server -> IPCH, IPCH -> MSH
    MSG_GET_DRIVER_VERSION          = 11,
        // Get driver version, used for response also
        // Client <-> IPCH
    MSG_GET_DRAPI_VERSION           = 12,
        // Get DrApi version, used for response also
        // Driver <-> IPCH */
    MSG_SET_NOTIFICATION_HANDLER    = 13,
        // Set (change) the SIQ handler thread, used for response also
        // Driver <-> IPCH
    MSG_GET_REGISTRY_ENTRY          = 14,
        // Get registry entry, available only if MC_FEATURE_DEBUG_SUPPORT is
        //   set, used for response also
        // Driver <-> IPCH
    MSG_DRV_NOT                     = 15,
        // Notification to a Trustlet, looks like a notification from NWd for
        //   the Trustlet, send-only message with no response
        // Driver -> Trustlet
    MSG_SET_FASTCALL_HANDLER        = 16,
        // install a FastCall handler, used for response also
        // Driver <-> IPCH
    MSG_GET_CLIENT_ROOT_AND_SP_ID   = 17,
        // get Root DI and SP ID, used for response also
        // Driver <-> IPCH
    MSG_SUSPEND                     = 18,
        // Suspend, requires MSG_SUSPEND_ACK as response
        // MSH -> IPCH, IPCH -> driver
    MSG_SUSPEND_ACK                 = 19,
        // Suspend Ack, response to MSG_SUSPEND
        // driver -> IPCH, IPCH -> MSH
    MSG_RESUME                      = 20,
        // resume, , requires MSG_RESUME_ACK as response
        // MSH -> IPCH, IPCH -> driver
    MSG_RESUME_ACK                  = 21,
        // resume, , response to MSG_RESUME
        // driver ->  IPCH, IPCH -> MSH
    MSG_GET_ENDORSEMENT_SO          = 22,
        // get SO from RTM for the Endorsement functionality
        // Driver <-> IPCH
    MSG_GET_SERVICE_VERSION         = 23,
        // get version of service (TA)
        // Driver <-> IPCH
    MSG_ERROR                       = 24,
        // IPCH returns error to Driver
        // IPCH <-> DRIVER
    MSG_CALL_FASTCALL               = 25,
        // Call fastcall from driver
        // DRIVER -> IPCH -> MTK -> FASTCALL -> return
} message_t;

// Entry Point Signature
void drMain(const addr_t dciBuffer, const uint32_t  dciBufferLen);

// Function signatures
void* drApiMalloc(uint32_t size, uint32_t hint);
void* drApiRealloc(void* buffer, uint32_t newSize);
void drApiFree(void* buffer);
drApiResult_t drApiIpcWaitForMessage(threadid_t *pIpcPartner, uint32_t *pMr0, uint32_t *pMr1, uint32_t *pMr2);
drApiResult_t drApiIpcCallToIPCH(threadid_t *pIpcPeer, message_t *pIpcMsg, uint32_t *pIpcData);
drApiResult_t drApiIpcSignal(const threadid_t receiver);
drApiResult_t drApiIpcSigWait(void);
drApiResult_t drApiNotify(void);
drApiResult_t drApiSyscallControl(uint32_t controlid, uint32_t param1, uint32_t param2, uint32_t param3, uint32_t param4, uint32_t *data);
drApiResult_t drApiReadOemData(const uint32_t offset, uint32_t *data);
drApiResult_t drApiNotifyClient(const threadid_t client);
drApiResult_t drApiGetClientRootAndSpId(uint32_t *rootId, uint32_t *spId, const threadid_t client);
drApiResult_t drApiIpcUnknownMessage(threadid_t *pIpcPeer, message_t *pIpcMsg, uint32_t *pIpcData);
drApiResult_t drApiUpdateNotificationThread(threadno_t threadno);