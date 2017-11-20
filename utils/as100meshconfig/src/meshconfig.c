#include "meshconfig.h"
#include "crc.h"


static int read_config_from_esp(esp_config_t * esp_config)
{
    int conf_dev, i;
    ssize_t size;
    uint8_t read_cmd[] = { 0x54, 0x02, 0x00, 0x00 };
    conf_dev = open(ESP_CONFIG_DEV_PATH, O_RDWR);
    if(conf_dev < 0)
    {
        printf("Failed to open config device: %d\n", conf_dev);
        return conf_dev;
    }

    write(conf_dev, read_cmd, sizeof(read_cmd));

    i = 0;
    while(1)
    {
        size = read(conf_dev, esp_config, sizeof(esp_config_t));

        if(size == sizeof(esp_config_t)) break;

        i++;

        usleep(ESP_CONFIG_READ_WAIT);

        if(i > ESP_CONFIG_READ_RETRIES)
        {
            printf("Reading config from ESP failed. Retries %d\n", i);
            return -ETIME;
        }
    }
    return 0;
}


static int write_config_to_esp(esp_config_t * esp_config)
{
    int conf_dev, res;
    uint8_t write_cmd[] = { 0x54, 0x01, 0x00, 0x00 };
    uint8_t write_buf[sizeof(esp_config_t) + sizeof(write_cmd)];

    conf_dev = open(ESP_CONFIG_DEV_PATH, O_RDWR);
    if(conf_dev < 0)
    {
        printf("Failed to open config device: %d\n", conf_dev);
        return conf_dev;
    }

    memcpy(write_buf, write_cmd, sizeof(write_cmd));
    memcpy(write_buf+sizeof(write_cmd), esp_config, sizeof(esp_config_t));


    res = write(conf_dev, write_buf, sizeof(write_buf));
    if(res != sizeof(write_buf))
    {
        printf("Failed to write to config device: %d\n", res);
        return res;        
    }

    return 0;
}


static int cmd_esp(char * cmd)
{
    int ctrl_dev, res;

    ctrl_dev = open(ESP_CONTROL_PATH, O_RDWR);
    if(ctrl_dev < 0)
    {
        printf("Failed to open control cmd interface: %d\n", ctrl_dev);
        return ctrl_dev;
    }

    res = write(ctrl_dev, cmd, strlen(cmd));

    return 0;
}


static void print_config(esp_config_t * esp_config)
{
    printf("softap_ssid = %s  ", esp_config->ap_config.ssid);
    printf("(len = %d)\n", esp_config->ap_config.ssid_len);
    printf("softap_password = %s\n", esp_config->ap_config.password);
    printf("softap_channel = %d\n", esp_config->ap_config.channel);
    printf("softap_authmode = %d\n", esp_config->ap_config.authmode);
    printf("softap_ssid_hidden = %d\n", esp_config->ap_config.ssid_hidden);
    printf("softap_max_conn = %d\n", esp_config->ap_config.max_connection);
    printf("softap_beacon_interval = %d\n", esp_config->ap_config.beacon_interval);
    printf("softap_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",                          
        esp_config->ap_mac.address[0], 
        esp_config->ap_mac.address[1], 
        esp_config->ap_mac.address[2], 
        esp_config->ap_mac.address[3], 
        esp_config->ap_mac.address[4], 
        esp_config->ap_mac.address[5]);
    printf("softap_flags = 0x%04x\n\n", esp_config->ap_flags);
    printf("station_ssid = %s\n", esp_config->sta_config.ssid);
    printf("station_password = %s\n", esp_config->sta_config.password);
    printf("station_bssid_set = %d\n", esp_config->sta_config.bssid_set);
    printf("station_bssid = %02x:%02x:%02x:%02x:%02x:%02x\n",                          
        esp_config->sta_config.bssid[0], 
        esp_config->sta_config.bssid[1], 
        esp_config->sta_config.bssid[2], 
        esp_config->sta_config.bssid[3], 
        esp_config->sta_config.bssid[4], 
        esp_config->sta_config.bssid[5]);
    printf("station_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",                          
        esp_config->sta_mac.address[0], 
        esp_config->sta_mac.address[1], 
        esp_config->sta_mac.address[2], 
        esp_config->sta_mac.address[3], 
        esp_config->sta_mac.address[4], 
        esp_config->sta_mac.address[5]);
    printf("station_flags = 0x%04x\n", esp_config->sta_flags);
}

char *get_uci_value(char *uci_path)
{
   char path[128]= {0};
   char buffer[80] = { 0 };
   struct  uci_ptr ptr;
   struct  uci_context *c = uci_alloc_context();

   if(!c) return NULL;

   strcpy(path, uci_path);

  // fprintf(stderr,"%s\n",path);

   if ((uci_lookup_ptr(c, &ptr, path, true) != UCI_OK) ||
         (ptr.o==NULL || ptr.o->v.string==NULL)) 
   { 
     uci_free_context(c);
     return NULL;
   }

   if(ptr.flags & UCI_LOOKUP_COMPLETE)
      strcpy(buffer, ptr.o->v.string);

   uci_free_context(c);

   return strdup(buffer);
}

static int get_config_from_file(char *filename, esp_config_t * esp_config_ret) 
{
    char * p, path[128];
    esp_config_t esp_config;
    memset(&esp_config, '\0', sizeof(esp_config_t));
    int j,k,tmp;


    /////////// SOFTAP BLOCK ///////////
    if ((p = get_uci_value("meshconfig.softap.ssid")) == NULL)
    {
        printf("Error at meshconfig.softap.ssid\n");
        return -EFAULT;
    }
    memcpy(&(esp_config.ap_config.ssid), p, sizeof(esp_config.ap_config.ssid));

    if ((p = get_uci_value("meshconfig.softap.password")) == NULL)
    {
        printf("Error at meshconfig.softap.password\n");
        return -EFAULT;
    }
    memcpy(&(esp_config.ap_config.password), p, sizeof(esp_config.ap_config.password));

    if ((p = get_uci_value("meshconfig.softap.channel")) == NULL)
    {
        printf("Error at meshconfig.softap.channel\n");
        return -EFAULT;
    }
    esp_config.ap_config.channel = atoi(p);

    if ((p = get_uci_value("meshconfig.softap.authmode")) == NULL)
    {
        printf("Error at meshconfig.softap.authmode\n");
        return -EFAULT;
    }
    if(!strcmp(p, "AUTH_OPEN")) esp_config.ap_config.authmode = AUTH_OPEN;
    else if(!strcmp(p, "AUTH_WEP")) esp_config.ap_config.authmode = AUTH_WEP;
    else if(!strcmp(p, "AUTH_WPA_PSK")) esp_config.ap_config.authmode = AUTH_WPA_PSK;
    else if(!strcmp(p, "AUTH_WPA2_PSK")) esp_config.ap_config.authmode = AUTH_WPA2_PSK;
    else if(!strcmp(p, "AUTH_WPA_WPA2_PSK")) esp_config.ap_config.authmode = AUTH_WPA_WPA2_PSK;
    else if(!strcmp(p, "AUTH_MAX")) esp_config.ap_config.authmode = AUTH_MAX;
    else
    {
        printf("softap_authmode is inappropriate\n");
        return -EINVAL;
    }

    if ((p = get_uci_value("meshconfig.softap.ssid_hidden")) == NULL)
    {
        printf("Error at meshconfig.softap.ssid_hidden\n");
        return -EFAULT;
    }
    esp_config.ap_config.ssid_hidden = atoi(p);

    esp_config.ap_config.max_connection = 2;
    esp_config.ap_config.beacon_interval = 100;
    esp_config.ap_flags = 0;

    // TODO: WE MUST CHECK WRONG CONFIG!!!
    if ((p = get_uci_value("meshconfig.softap.mac")) == NULL)
    {
        printf("Error at meshconfig.softap.mac\n");
        return -EFAULT;
    }
    esp_config.ap_mac.address[0] = (uint8_t)strtol(p,    NULL, 16);
    esp_config.ap_mac.address[1] = (uint8_t)strtol(p+3,  NULL, 16); 
    esp_config.ap_mac.address[2] = (uint8_t)strtol(p+6,  NULL, 16); 
    esp_config.ap_mac.address[3] = (uint8_t)strtol(p+9,  NULL, 16); 
    esp_config.ap_mac.address[4] = (uint8_t)strtol(p+12, NULL, 16); 
    esp_config.ap_mac.address[5] = (uint8_t)strtol(p+15, NULL, 16); 
    printf("ap_mac = %02x:%02x:%02x:%02x:%02x:%02x \n", esp_config.ap_mac.address[0],
        esp_config.ap_mac.address[1],
        esp_config.ap_mac.address[2],
        esp_config.ap_mac.address[3],
        esp_config.ap_mac.address[4],
        esp_config.ap_mac.address[5]
        );



    /////////// STATION BLOCK ///////////
    if ((p = get_uci_value("meshconfig.station.ssid")) == NULL)
    {
        printf("Error at meshconfig.station.ssid\n");
        return -EFAULT;
    }
    memcpy(&(esp_config.sta_config.ssid), p, sizeof(esp_config.sta_config.ssid));

    if ((p = get_uci_value("meshconfig.station.password")) == NULL)
    {
        printf("Error at meshconfig.station.password\n");
        return -EFAULT;
    }
    memcpy(&(esp_config.sta_config.password), p, sizeof(esp_config.sta_config.password));

    if ((p = get_uci_value("meshconfig.station.bssid_set")) == NULL)
    {
        printf("Error at meshconfig.station.bssid_set\n");
        return -EFAULT;
    }
    esp_config.sta_config.bssid_set = atoi(p);

    if ((p = get_uci_value("meshconfig.station.bssid")) == NULL)
    {
        printf("Error at meshconfig.station.bssid\n");
        return -EFAULT;
    }
    esp_config.sta_config.bssid[0] = (uint8_t)strtol(p,    NULL, 16);
    esp_config.sta_config.bssid[1] = (uint8_t)strtol(p+3,  NULL, 16); 
    esp_config.sta_config.bssid[2] = (uint8_t)strtol(p+6,  NULL, 16); 
    esp_config.sta_config.bssid[3] = (uint8_t)strtol(p+9,  NULL, 16); 
    esp_config.sta_config.bssid[4] = (uint8_t)strtol(p+12, NULL, 16); 
    esp_config.sta_config.bssid[5] = (uint8_t)strtol(p+15, NULL, 16);

    // TODO: WE MUST CHECK WRONG CONFIG!!!
    if ((p = get_uci_value("meshconfig.station.mac")) == NULL)
    {
        printf("Error at meshconfig.station.mac\n");
        return -EFAULT;
    }
    esp_config.sta_mac.address[0] = (uint8_t)strtol(p,    NULL, 16);
    esp_config.sta_mac.address[1] = (uint8_t)strtol(p+3,  NULL, 16); 
    esp_config.sta_mac.address[2] = (uint8_t)strtol(p+6,  NULL, 16); 
    esp_config.sta_mac.address[3] = (uint8_t)strtol(p+9,  NULL, 16); 
    esp_config.sta_mac.address[4] = (uint8_t)strtol(p+12, NULL, 16); 
    esp_config.sta_mac.address[5] = (uint8_t)strtol(p+15, NULL, 16);

    if ((p = get_uci_value("meshconfig.station.flags")) == NULL)
    {
        printf("Error at meshconfig.station.flags\n");
        return -EFAULT;
    }
    esp_config.sta_flags = atoi(p);



    /////////// IP BLOCK ///////////
    if ((p = get_uci_value("meshconfig.ip.ipaddr")) == NULL)
    {
        printf("Error at meshconfig.ip.ipaddr\n");
        return -EFAULT;
    }
    inet_pton(AF_INET, p, &(esp_config.ip_info.ip));

    if ((p = get_uci_value("meshconfig.ip.ipmask")) == NULL)
    {
        printf("Error at meshconfig.ip.ipmask\n");
        return -EFAULT;
    }
    inet_pton(AF_INET, p, &(esp_config.ip_info.netmask));

    if ((p = get_uci_value("meshconfig.ip.")) == NULL)
    {
        printf("Error at meshconfig.ip.gateway\n");
        return -EFAULT;
    }
    inet_pton(AF_INET, p, &(esp_config.ip_info.gw));


    /////////// CRYPTO BLOCK ///////////
    if ((p = get_uci_value("meshconfig.crypto.keylen")) == NULL)
    {
        printf("Error at meshconfig.crypto.keylen\n");
        return -EFAULT;
    }
    esp_config.mesh_key_len = atoi(p);


    /////////// CHECKSUM ///////////
    esp_config.crc32 = 0;
    esp_config.crc32 = crc32(&esp_config, sizeof(esp_config_t));

    memcpy(esp_config_ret, &esp_config, sizeof(esp_config_t));

    return 0;
}


int main(int argc, char **argv)
{
    int ret;
    uint32_t crc;

    esp_config_t new_espconfig, curr_espconfig;

    // inotify for parsing changes in config file
    int inotifyFD = inotify_init();
    if(inotifyFD < 0)
    {
        printf("Couldn't initialize inotify\n");
        return inotifyFD;
    }
    int inotifyWatch = inotify_add_watch(inotifyFD, ESP_CONFIG_FILE_PATH, IN_MODIFY); 
    if (inotifyWatch < 0)
    {
        printf("Couldn't add watch to %s\n", ESP_CONFIG_FILE_PATH);
        return inotifyWatch;
    }
    char inotifyBuf[INOTIFY_MAX_BUF_SIZE];


    struct epoll_event epollConfig;
    struct epoll_event epollEvent[1];
    int epollFD = epoll_create(sizeof(inotifyFD));

    epollConfig.events = EPOLLIN | EPOLLET;
    epollConfig.data.fd = inotifyFD;
    // add our inotify into epoll
    ret = epoll_ctl(epollFD, EPOLL_CTL_ADD, inotifyFD, &epollConfig);
    if(ret < 0)
    {
        printf("Error while inotify epoll regisration: %d\n", ret);
        return ret;
    }


    ret = get_config_from_file(ESP_CONFIG_FILE_PATH, &new_espconfig);
    if(ret)
    {
        printf("Reading config file failed: %d\n", ret);
        return ret;
    }

    while(1)
    {
        ret = read_config_from_esp(&curr_espconfig);
        if(ret)
        {
            printf("Reading config from ESP failed: %d. Retry...\n", ret);
            usleep(ESP_CONFIG_READ_WAIT);
            continue;
        }

        crc = curr_espconfig.crc32;
        curr_espconfig.crc32 = 0;
        curr_espconfig.crc32 = crc32(&curr_espconfig, sizeof(esp_config_t));

        if(crc != curr_espconfig.crc32)
        {
            printf("Reading config from ESP  failed: wrong CRC\n");
            usleep(ESP_CONFIG_READ_WAIT);
            continue;
        }   

        // if esp config(current) differs from file config(new)
        if(memcmp(&curr_espconfig, &new_espconfig, sizeof(esp_config_t)) != 0)
        {
            printf("esp current config differs from file config, rewriting\n");

            ret = write_config_to_esp(&new_espconfig);
            sleep(5);
            ret = cmd_esp("on");   //restart_esp
            sleep(8);
            continue;
        }
        else break;
    }
    memcpy(&curr_espconfig, &new_espconfig, sizeof(esp_config_t));
    printf("ESP CONFIG:\n");
    print_config(&curr_espconfig);

    while (1) 
    {
        ret = epoll_wait(epollFD, epollEvent, EPOLL_MAX_EVENTS, EPOLL_RUN_TIMEOUT);

        read(inotifyFD, &inotifyBuf, INOTIFY_MAX_BUF_SIZE);

        ret = get_config_from_file(ESP_CONFIG_FILE_PATH, &new_espconfig);
        if(ret)
            printf("Reading config file failed: %d\n", ret);
        new_espconfig.crc32 = 0;
        new_espconfig.crc32 = crc32(&new_espconfig, sizeof(esp_config_t));

        if(memcmp(&curr_espconfig, &new_espconfig, sizeof(esp_config_t)) != 0)
        {
            sleep(1);
            ret = write_config_to_esp(&new_espconfig);

            memcpy(&curr_espconfig, &new_espconfig, sizeof(esp_config_t));

            printf("NEW CONFIG:\n");
            print_config(&curr_espconfig);
            ret = write_config_to_esp(&curr_espconfig);
            sleep(5);
            ret = cmd_esp("on");   //restart_esp
            sleep(8);
        }

        usleep(1000);
    }



    return 0;

}