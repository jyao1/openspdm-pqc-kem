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

!INCLUDE $(WORKSPACE)\MakeFile.Flags

#
# Module Macro Definition
#
MODULE_NAME = TestPqcCryptLib
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\UnitTest\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\UnitTest\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\PqcCryptest.obj \
    $(OUTPUT_DIR)\SigVerify.obj \
    $(OUTPUT_DIR)\KemVerify.obj \
    $(OUTPUT_DIR)\OsSupport.obj \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\OsStub\BaseMemoryLib\BaseMemoryLib.lib \
    $(BIN_DIR)\OsStub\DebugLib\DebugLib.lib \
    $(BIN_DIR)\OsStub\PqcCryptLibOqs\PqcCryptLibOqs.lib \
    $(BIN_DIR)\oqs\lib\oqs.lib \
    $(BIN_DIR)\OsStub\RngLib\RngLib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\MemoryAllocationLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(OBJECT_FILES) \
    $(BIN_DIR)\OsStub\BaseMemoryLib\*.obj \
    $(BIN_DIR)\OsStub\DebugLib\*.obj \
    $(BIN_DIR)\OsStub\PqcCryptLibOqs\*.obj \
    $(BIN_DIR)\oqs\lib\oqs.lib \
    $(BIN_DIR)\OsStub\RngLib\*.obj \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\*.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)\$(MODULE_NAME)

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
	-@if not exist $(OUTPUT_DIR) $(MD) $(OUTPUT_DIR)

#
# GenLibsTarget
#
gen_libs:
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseMemoryLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\DebugLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\PqcCryptLibOqs\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\RngLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\PqcCryptest.obj : $(SOURCE_DIR)\PqcCryptest.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\PqcCryptest.c

$(OUTPUT_DIR)\SigVerify.obj : $(SOURCE_DIR)\SigVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SigVerify.c

$(OUTPUT_DIR)\KemVerify.obj : $(SOURCE_DIR)\KemVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\KemVerify.c

$(OUTPUT_DIR)\OsSupport.obj : $(SOURCE_DIR)\OsSupport.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\OsSupport.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

$(OUTPUT_DIR)\$(MODULE_NAME) : $(STATIC_LIBRARY_FILES)
	$(DLINK) $(DLINK_FLAGS) $(DLINK_SPATH) $(DLINK_OBJECT_FILES)

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


