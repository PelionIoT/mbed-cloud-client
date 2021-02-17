
#ifndef ARM_UC_PAL_DELTA_PAAL_ORIGINAL_READER_H
#define ARM_UC_PAL_DELTA_PAAL_ORIGINAL_READER_H

#include "update-client-paal/arm_uc_paal_update_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int arm_uc_deltapaal_original_reader(void* buffer, uint64_t length, uint32_t offset);
arm_uc_error_t arm_uc_delta_paal_construct_original_image_file_path(char* buffer, size_t buffer_length);

#ifdef __cplusplus
}
#endif

#endif /* ARM_UC_PAL_DELTA_PAAL_ORIGINAL_READER_H */
