aux_source_directory(core/logger DIR_LOGGER_SRCS)
aux_source_directory(core/compile DIR_COMPILE_SRCS)
aux_source_directory(common DIR_COMMON_SRCS)

add_library(core ${DIR_LOGGER_SRCS} ${DIR_COMPILE_SRCS} ${DIR_COMMON_SRCS})