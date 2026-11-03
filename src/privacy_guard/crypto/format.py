# Existing ISLENC01 wire-format constants; do not change without versioning.
MAGIC = b'ISLENC01'
MAX_PLAINTEXT = 64 * 1024 * 1024
MAX_PACKAGE = MAX_PLAINTEXT + 4096
