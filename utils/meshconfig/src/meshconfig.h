#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <termios.h>
#include <inttypes.h>

#include "crc.h"
#include "uci.h"


#define EPOLL_RUN_TIMEOUT		-1
#define EPOLL_MAX_EVENTS		1   // inotifyFD

#define INOTIFY_MAX_BUF_SIZE	1024
#define ESP_CONFIG_FILE_PATH	"/etc/config/meshconfig"
#define ESP_CONFIG_DEV_PATH		"/dev/esp8266_config"
#define ESP_CONTROL_PATH		"/dev/esp8266_ctrl"
#define ESP_CONFIG_READ_RETRIES	10
#define ESP_CONFIG_READ_WAIT	10000
#define ESP_CONFIG_STR_LEN		128
#define DELIM					' '
#define END_SYMB				'\n'

#define SSID_MAX_LEN			32
#define PASS_MAX_LEN			64

typedef struct 
{
	int length;
	char * data;
} data_transfer_t;

typedef struct {
	uint8_t address[6];
} esp_mac_t;

typedef enum {
	AUTH_OPEN = 0,
	AUTH_WEP = 1,
	AUTH_WPA_PSK = 2,
	AUTH_WPA2_PSK = 3,
	AUTH_WPA_WPA2_PSK = 4,
	AUTH_MAX = 5
} AUTH_MODE;

typedef struct {
	uint8_t ssid[SSID_MAX_LEN];
	uint8_t password[PASS_MAX_LEN];
	uint8_t bssid_set;		// Note: If bssid_set is 1, station will just connect to the router
							// with both ssid[] and bssid[] matched. Please check about this.
	uint8_t bssid[6];
} station_config_t;

typedef struct {
	uint8_t ssid[SSID_MAX_LEN];
	uint8_t password[PASS_MAX_LEN];
	uint8_t ssid_len;			// Note: Recommend to set it according to your ssid
	uint8_t channel;			// Note: support 1 ~ 13
	AUTH_MODE authmode;			// Note: Don't support AUTH_WEP in softAP mode.
	uint8_t ssid_hidden;		// Note: default 0
	uint8_t max_connection;		// Note: default 4, max 4
	uint16_t beacon_interval;	// Note: support 100 ~ 60000 ms, default 100
} softap_config_t;

#pragma pack(push, 1)
typedef struct {
	uint32_t crc32;
	softap_config_t ap_config;
	station_config_t sta_config;
	esp_mac_t ap_mac;
	esp_mac_t sta_mac;
	uint16_t ap_flags;
	uint16_t sta_flags;
} esp_config_t;
#pragma pack(pop)
