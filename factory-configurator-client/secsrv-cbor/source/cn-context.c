#ifdef USE_CBOR_CONTEXT
#include "cn-cbor.h"
#include "cbor.h"
#include <stdlib.h>
#include <string.h>

cn_cbor_context context_obj;
cn_cbor_context *cbor_context = &context_obj;
cbor_mem_pool mem_pool_internal;

#ifdef USE_CBOR_CONTEXT_STATS
uint32_t calloc_heap_cntr = 0;
uint32_t free_heap_cntr = 0;
uint32_t calloc_pool_cntr = 0;
uint32_t free_pool_cntr = 0;
uint32_t bytes_heap_allocated = 0;
uint32_t total_bytes_heap_allocated = 0;
uint32_t max_bytes_heap_allocated = 0;
uint32_t bytes_pool_allocated = 0;
uint32_t total_bytes_pool_allocated = 0;
uint32_t max_bytes_pool_allocated = 0;
uint32_t number_of_pools_allocated = 0;
uint32_t total_bytes_allocated_for_pools = 0;
#endif // USE_CBOR_CONTEXT_STATS

//#include <strings.h>

#define BITMAP_ENTRY_SIZE_IN_BITS ( sizeof(mem_pool->bitmap[0]) * 8 )
#define BITMAP_FULL (-1)

#ifdef USE_CBOR_CONTEXT_STATS
#define CBOR_STATS_FREE(mem) do { \
                                        free_##mem##_cntr++; \
                                        bytes_##mem##_allocated -= sizeof(cn_cbor); \
                                      } while(0) 

#define CBOR_STATS_CALLOC(mem, size, count) do { \
                                        calloc_##mem##_cntr++; \
                                        bytes_##mem##_allocated += size * count; \
                                        total_bytes_##mem##_allocated += size * count; \
                                        if (bytes_##mem##_allocated > max_bytes_##mem##_allocated) { \
                                            max_bytes_##mem##_allocated = bytes_##mem##_allocated; \
                                        } \
                                        } while (0)
#else
#define CBOR_STATS_FREE(mem) 
#define CBOR_STATS_CALLOC(mem, size, count) 
#endif //USE_CBOR_CONTEXT_STATS

// Count leading zeros in pure C (https://stackoverflow.com/questions/23856596/counting-leading-zeros-in-a-32-bit-unsigned-integer-with-best-algorithm-in-c-pro) 
static int clz_pure_c(uint32_t a)
{
    static const char debruijn32[32] = {
        0, 31, 9, 30, 3, 8, 13, 29, 2, 5, 7, 21, 12, 24, 28, 19,
        1, 10, 4, 14, 6, 22, 25, 20, 11, 15, 23, 26, 16, 27, 17, 18
    };

    // This algorithm does work correctly for input 0, so we handle it independently
    if (a == 0) {
        return 32;
    }

    a |= a >> 1;
    a |= a >> 2;
    a |= a >> 4;
    a |= a >> 8;
    a |= a >> 16;
    a++;

    return debruijn32[a * 0x076be629 >> 27];
}

// Count leading zeros. Use compiler functions that use direct machine instructions if possible
static int count_leading_zeros(uint32_t a)
{
    // If GCC
#if defined(__GNUC__)
    return __builtin_clz(a);
#elif defined(__arm__)
    return __clz(a);

#else // If not GCC or ARMCC, use pure C implementation
    return clz_pure_c();

#endif
}

// Count trailing zeros using using the count leading zeros command (https://community.arm.com/community-help/f/discussions/2114/count-trailing-zeros)
static int ctz(uint32_t a)
{
    int c = count_leading_zeros(a & -a);
    return a ? 31 - c : c;
}

// Get the index of the first 0 bit in bitmap_entry
static int find_first_open_slot(int32_t bitmap_entry)
{
    int pos = ctz(~bitmap_entry);

    return (pos < 32) ? pos : -1;
}

// NOTE: CBOR library uses only calloc(1, sizeof(cn_cbor)). Currently only calloc(1,sizeof(cn_cbor)) is supported by the allocator
/**
* Allocate space for count (currently must be 1) CBOR elements.
*
* NOTE: CBOR library uses only calloc(1, sizeof(cn_cbor)). Currently only calloc(1,sizeof(cn_cbor)) currently supported by allocator.
* @param[in] count             Count of number of elements in allocated array. Currently must be 1.
* @param[in]  size             Size of each element in the allocated array. Must be sizeof(cn_cbor)
* @param[in]  context          Pointer to the CBOR context.
* @return                      The address of the allocated memory.
*/
void *cbor_calloc(size_t count, size_t size, void *context)
{
    void *ret_mem;
    int bitmap_idx, pos, bit_pos, max_bitmap_idx;
    cbor_mem_pool *mem_pool = (cbor_mem_pool *)(context);

    // Currently supports only allocations of 1 slot. CBOR lib never allocates more than that.
    if (count != 1 || size != sizeof(cn_cbor)) {
        return NULL;
    }

    // Get the index of the last entry in the bitmap array
    max_bitmap_idx = mem_pool->pool_size_in_cbors / BITMAP_ENTRY_SIZE_IN_BITS;

    // If number of CBOR objects in pool is not divisible by 8, there is an additional entry to the bitmap for the residue
    if (mem_pool->pool_size_in_cbors % BITMAP_ENTRY_SIZE_IN_BITS != 0) {
        max_bitmap_idx++;
    }

    for (bitmap_idx = 0; bitmap_idx < max_bitmap_idx; bitmap_idx++) {
        // If bitmap entry is full, try next
        if (mem_pool->bitmap[bitmap_idx] == BITMAP_FULL) {
            continue;
        }
        // Find first open slot in bitmap[bitmap_idx]
        bit_pos = find_first_open_slot(mem_pool->bitmap[bitmap_idx]);
        // If found open slot
        if (bit_pos >= 0) {

            // Adjust position for CBOR pool
            pos = bit_pos + (bitmap_idx * BITMAP_ENTRY_SIZE_IN_BITS);

            // If position not in pool (since the size is not divisible by the size of each entry in the bitmap array in bits)
            if (pos >= mem_pool->pool_size_in_cbors) {
                break;
            }

            ret_mem = &(mem_pool->pool[pos]);

            // Zero the returned memory (CBOR lib demands this)
            memset(ret_mem, 0, sizeof(mem_pool->pool[pos]));

            // Set the bit in index pos
            mem_pool->bitmap[bitmap_idx] = mem_pool->bitmap[bitmap_idx] | (1ULL << bit_pos);

            CBOR_STATS_CALLOC(pool, size, count);
            return ret_mem;
        }
    }

    // If no space in pool, use LIBC calloc
    CBOR_STATS_CALLOC(heap, size, count);
    return calloc(count, size);
}

// Return whether a given address resides within the allocated CBOR pool
#define IS_IN_POOL(cbor_ptr, mem_pool) (( (uint8_t*)cbor_ptr >= ((uint8_t*) &(mem_pool->pool[0]))) && ( (uint8_t*)cbor_ptr <= ((uint8_t*) &(mem_pool->pool[mem_pool->pool_size_in_cbors - 1]))))

// Assuming cbor_ptr points to a cn_cbor object in the pool, return its index in the pool. Use this macro ONLY after asserting that cbor_ptr is in pool using IS_IN_POOL().
#define POS_IN_POOL(cbor_ptr, mem_pool) ( ((uint8_t*)cbor_ptr - ((uint8_t*) &(mem_pool->pool[0]))) / sizeof(mem_pool->pool[0]) )

// Get the index of the bitmap array, in which the bit corresponding to mem_pool->pool[position_in_pool] resides.
#define INDEX_IN_BITMAP(position_in_pool, mem_pool) ( position_in_pool / (sizeof(mem_pool->bitmap[0]) * 8 ) )

// Get the position of the bit in the bitmap, corresponding to mem_pool->pool[position_in_pool].
#define POS_IN_INDEX(position_in_pool) ( position_in_pool % (sizeof(mem_pool->bitmap[0]) * 8 ) )

/**
* Free a cn_cbor object.
* If the cn_cbor pointed to by ptr is in the pool, simply unset the corresponding bit in the bitmap.
* If the cn_cbor pointed to by ptr is not in the pool, assume it was allocated with LIBC calloc (since pool was full), and free it using LIBC free.
*
* @param[in]  ptr              Pointer to a cn_cbor object we wish to free
* @param[in]  context          Pointer to the CBOR context.
* @return                      The address of the allocated memory.
*/

void cbor_free(void *ptr, void *context)
{
    int pos, bitmap_idx;
    cbor_mem_pool *mem_pool = (cbor_mem_pool *)(context);

    // If ptr is in internal pool simply unset its bit in the bitmap
    if (IS_IN_POOL(ptr, mem_pool)) {
        // Get position of the bit
        pos = POS_IN_POOL(ptr, mem_pool);

        bitmap_idx = INDEX_IN_BITMAP(pos, mem_pool);
        int pos_in_index = POS_IN_INDEX(pos);
        // Set the bit in the corresponding offset in the correct index of the bitmap
        mem_pool->bitmap[bitmap_idx] = mem_pool->bitmap[bitmap_idx] & ~(1ULL << pos_in_index);

        CBOR_STATS_FREE(pool);
    } else { // If not in pool - allocated with libc calloc(), so we use libc free()
        free(ptr);

        CBOR_STATS_FREE(heap);
    }
}

cn_cbor_context *cn_cbor_init_context(size_t num_of_cbors_in_pool)
{
    if (num_of_cbors_in_pool > MAX_SIZE_POOL_IN_CBORS) {
        return NULL;
    }

    memset(&mem_pool_internal, 0, sizeof(mem_pool_internal));

    cbor_context->calloc_func = cbor_calloc;
    cbor_context->free_func = cbor_free;

    mem_pool_internal.pool = calloc(num_of_cbors_in_pool, sizeof(cn_cbor));
    mem_pool_internal.pool_size_in_cbors = num_of_cbors_in_pool;

    cbor_context->context = &mem_pool_internal;

#ifdef USE_CBOR_CONTEXT_STATS
    number_of_pools_allocated++;
    total_bytes_allocated_for_pools += (num_of_cbors_in_pool * sizeof(cn_cbor));
#endif // USE_CBOR_CONTEXT_STATS

    return cbor_context;
}

void cn_cbor_free_context(cn_cbor_context *ctx)
{
    if (ctx && ctx->context) {
        free(((cbor_mem_pool *)(ctx->context))->pool);
    }
}

#ifdef USE_CBOR_CONTEXT_STATS
#include <inttypes.h>
void cn_cbor_context_print_stats()
{
    printf("  ***************** CBOR Memory Statistics *****************\n");
    printf("  * Total bytes allocated on heap:                       %" PRIu32 "\n", total_bytes_heap_allocated);
    printf("  * Number of heap allocations:                          %" PRIu32 "\n", calloc_heap_cntr);
    printf("  * Number of heap frees:                                %" PRIu32 "\n", free_heap_cntr);
    printf("  * Max peak ever allocated (heap):                      %" PRIu32 "\n", max_bytes_heap_allocated);
    printf("  *\n");
    printf("  * Total bytes allocated in pool:                       %" PRIu32 "\n", total_bytes_pool_allocated);
    printf("  * Number of pool allocations:                          %" PRIu32 "\n", calloc_pool_cntr);
    printf("  * Number of pool frees:                                %" PRIu32 "\n", free_pool_cntr);
    printf("  * Max peak ever allocated (pool):                      %" PRIu32 "\n", max_bytes_pool_allocated);
    printf("  *\n");
    printf("  * Total size of All CBOR pools ever allocated (bytes): %" PRIu32 "\n", total_bytes_allocated_for_pools);
    printf("  * Number of pools allocated:                           %" PRIu32 "\n", number_of_pools_allocated);
    printf("  ***********************************************************\n");
}

void cn_cbor_context_reset_stats()
{
    calloc_heap_cntr = 0;
    free_heap_cntr = 0;
    calloc_pool_cntr = 0;
    free_pool_cntr = 0;
    bytes_heap_allocated = 0;
    total_bytes_heap_allocated = 0;
    max_bytes_heap_allocated = 0;
    bytes_pool_allocated = 0;
    total_bytes_pool_allocated = 0;
    max_bytes_pool_allocated = 0;
    number_of_pools_allocated = 0;
    total_bytes_allocated_for_pools = 0;
}

#endif // USE_CBOR_CONTEXT_STATS

#endif // USE_CBOR_CONTEXT
