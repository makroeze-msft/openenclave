# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_test(NAME edger8r_size_warning COMMAND edger8r --header-only size.edl)
set_tests_properties(edger8r_size_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Warning: Function 'ecall_signed_size': Size parameter 'size' should not be signed.")
