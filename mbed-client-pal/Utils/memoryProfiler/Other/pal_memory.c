/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
/*
 * pal_memory.c
 *
 *  Created on: Jun 26, 2017
 *      Author: pal
 */

#ifndef PAL_MEMORY_PRINT_DATA
    #define PAL_MEMORY_PRINT_DATA	0
#endif

#ifndef PAL_MEMORY_BUCKET
    #define PAL_MEMORY_BUCKET		0
#endif

#ifdef PAL_MEMORY_STATISTICS
#include "stdio.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "PAL_MEMORY"

#ifdef PAL_MEMORY_BUCKET

#define SMALL_BUCKET	32
#define LARGE_BUCKET	4096

typedef enum _memoryBucketSizes
{
	PAL_BUCKET_SIZE_32 = 0,
	PAL_BUCKET_SIZE_64,
	PAL_BUCKET_SIZE_128,
	PAL_BUCKET_SIZE_256,
	PAL_BUCKET_SIZE_512,
	PAL_BUCKET_SIZE_1024,
	PAL_BUCKET_SIZE_2048,
	PAL_BUCKET_SIZE_4096,
	PAL_BUCKET_SIZE_LARGE,
	PAL_BUCKET_NUMBER
}memoryBucketSizes;

typedef struct _memoryAllocationData
{
	int32_t totalsize;
	int32_t waterMark;
	int32_t buckets[PAL_BUCKET_NUMBER];
	int32_t waterMarkBuckets[PAL_BUCKET_NUMBER];
}memoryAllocationData;

static memoryAllocationData memoryStats = {0};


static inline memoryBucketSizes getBucketNumber(size_t size)
{
	if (size <= SMALL_BUCKET)
	{
		return PAL_BUCKET_SIZE_32;
	}
	if (size >= LARGE_BUCKET)
	{
		return PAL_BUCKET_SIZE_LARGE;
	}

	uint8_t bucket = 1;
	uint32_t power = 64; // Starting with 32
	while (power < size)
	{
		bucket++;
		power*=2;
	}
	return bucket;
}
#endif //PAL_MEMORY_BUCKET


void* __wrap_malloc(size_t c)
{
	void *ptr  = NULL;
#ifdef PAL_MEMORY_BUCKET
	ptr = __real_malloc(c + sizeof(size_t) + sizeof(size_t));
	if (ptr == NULL)
	{
		return NULL;
	}
	 int32_t currentTotal = pal_osAtomicIncrement((&memoryStats.totalsize),c);
	if (currentTotal > memoryStats.waterMark)
	{
		memoryStats.waterMark = currentTotal; // need to make this thread safe
	}

	*(size_t*)ptr = c;
	ptr = ((size_t*)ptr+1);
	*(size_t*)ptr = (size_t)getBucketNumber(c);
	 int32_t currentBucketTotal = pal_osAtomicIncrement(&(memoryStats.buckets[*(size_t*)ptr]),1);
	if (memoryStats.waterMarkBuckets[*(size_t*)ptr] < currentBucketTotal)
	{
		memoryStats.waterMarkBuckets[*(size_t*)ptr] = currentBucketTotal;
	}
	ptr = ((size_t*)ptr + 1);
#else
	ptr = __real_malloc(c);
#endif

#if PAL_MEMORY_PRINT_DATA
#ifdef __LINUX__
	printf("malloc: ptr - %p, size - %d\n\r",ptr,c);
#else
	tr_info("malloc: ptr - %p, size - %d\n\r",ptr,c);
#endif//LINUX

#endif
	return ptr;
}


void __wrap_free(void* ptr)
{
	if (NULL == ptr)
	{
		return;
	}
#if PAL_MEMORY_PRINT_DATA
#ifdef __LINUX__
	printf("free: ptr - %p\n\r",ptr);
#endif
#endif

#ifdef PAL_MEMORY_BUCKET
	ptr = ((size_t*)ptr-1);
	pal_osAtomicIncrement(&(memoryStats.buckets[*(size_t*)ptr]),-1);
	ptr = ((size_t*)ptr-1);
	pal_osAtomicIncrement((&memoryStats.totalsize),-1*(*(size_t*)ptr));
#endif



	__real_free(ptr);

}


void* __wrap_calloc(size_t num, size_t size)
{
	void* ptr = __wrap_malloc(num*size);
	if (NULL != ptr)
	{
		memset(ptr,0,(num*size));
	}
	return (ptr);
}



void printMemoryStats(void)
{
#ifdef PAL_MEMORY_BUCKET
	tr_info("\n*******************************************************\r\n");
	tr_info("water mark size = %ld\r\n",memoryStats.waterMark);
	tr_info("total size = %ld\r\n",memoryStats.totalsize);
	tr_info("bucket 32    allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_32]);
	tr_info("bucket 64    allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_64]);
	tr_info("bucket 128   allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_128]);
	tr_info("bucket 258   allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_256]);
	tr_info("bucket 512   allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_512]);
	tr_info("bucket 1024  allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_1024]);
	tr_info("bucket 2048  allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_2048]);
	tr_info("bucket 4096  allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_4096]);
	tr_info("bucket large allocation number %ld\r\n",memoryStats.buckets[PAL_BUCKET_SIZE_LARGE]);

	tr_info("water mark bucket 32    allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_32]);
	tr_info("water mark bucket 64    allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_64]);
	tr_info("water mark bucket 128   allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_128]);
	tr_info("water mark bucket 256   allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_256]);
	tr_info("water mark bucket 512   allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_512]);
	tr_info("water mark bucket 1024  allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_1024]);
	tr_info("water mark bucket 2048  allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_2048]);
	tr_info("water mark bucket 4096  allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_4096]);
	tr_info("water mark bucket large allocation number %ld\r\n",memoryStats.waterMarkBuckets[PAL_BUCKET_SIZE_LARGE]);
	tr_info("*******************************************************\r\n");
#endif

}
#endif
