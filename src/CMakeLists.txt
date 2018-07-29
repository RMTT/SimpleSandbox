aux_source_directory(core/logger DIR_LOGGER_SRCS)
aux_source_directory(core/compile DIR_COMPILE_SRCS)
aux_source_directory(common DIR_COMMON_SRCS)
aux_source_directory(core/execute DIR_EXECUTE_SRCS)

add_library(imcoder_core  SHARED ${DIR_LOGGER_SRCS} ${DIR_COMPILE_SRCS} ${DIR_COMMON_SRCS} ${DIR_EXECUTE_SRCS})