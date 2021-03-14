## @file
#  SPDM library.
#
#  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

#
# Platform Macro Definition
#

include $(WORKSPACE)/GNUmakefile.Flags

#
# Module Macro Definition
#
MODULE_NAME = TestPqcCryptLib
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/UnitTest/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/UnitTest/$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/PqcCryptest.o \
    $(OUTPUT_DIR)/SigVerify.o \
    $(OUTPUT_DIR)/KemVerify.o \
    $(OUTPUT_DIR)/OsSupport.o \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a \
    $(BIN_DIR)/OsStub/DebugLib/DebugLib.a \
    $(BIN_DIR)/OsStub/PqcCryptLibOqs/PqcCryptLibOqs.a \
    $(BIN_DIR)/oqs/lib/oqs.a \
    $(BIN_DIR)/OsStub/RngLib/RngLib.a \
    $(BIN_DIR)/OsStub/MemoryAllocationLib/MemoryAllocationLib.a \
    $(OUTPUT_DIR)/$(MODULE_NAME).a \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/*.o \
    $(BIN_DIR)/OsStub/DebugLib/*.o \
    $(BIN_DIR)/OsStub/PqcCryptLibOqs/*.o \
    $(BIN_DIR)/oqs/lib/oqs.a \
    $(BIN_DIR)/OsStub/RngLib/*.o \
    $(BIN_DIR)/OsStub/MemoryAllocationLib/*.o \
    $(OUTPUT_DIR)/*.o \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH) \
    -I$(WORKSPACE)/OsStub/Include

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)/$(MODULE_NAME)

#
# Default target, which will build dependent libraries in addition to source files
#

all: mbuild

#
# ModuleTarget
#

mbuild: $(INIT_TARGET) gen_libs $(CODA_TARGET)

#
# Initialization target: print build information and create necessary directories
#
init:
	-@$(MD) $(OUTPUT_DIR)

#
# GenLibsTarget
#
gen_libs:
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/BaseMemoryLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/DebugLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/PqcCryptLibOqs/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/RngLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/MemoryAllocationLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/PqcCryptest.o : $(SOURCE_DIR)/PqcCryptest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SigVerify.o : $(SOURCE_DIR)/SigVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/KemVerify.o : $(SOURCE_DIR)/KemVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/OsSupport.o : $(SOURCE_DIR)/OsSupport.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

$(OUTPUT_DIR)/$(MODULE_NAME) : $(STATIC_LIBRARY_FILES)
	@echo $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a > $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/DebugLib/DebugLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/PqcCryptLibOqs/PqcCryptLibOqs.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/oqs/lib/oqs.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/RngLib/RngLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/MemoryAllocationLib/MemoryAllocationLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(OUTPUT_DIR)/$(MODULE_NAME).a >> $(OUTPUT_DIR)/tmp.list
	$(DLINK) $(DLINK_FLAGS) $(DLINK_SPATH) $(DLINK_OBJECT_FILES) $(DLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


