/* Windows XP entropy is supplied explicitly via CryptGenRandom. */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#undef MBEDTLS_SSL_PROTO_TLS1_3
/* Use MinGW's statically linked ISO C99 formatting, not Vista-era *_s CRT. */
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO snprintf
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO vsnprintf
