#ifndef __CRC_H
#define __CRC_H

#include <sys/types.h>
#include <stdint.h>

uint32_t crc32(void * buf, size_t size);

#endif
