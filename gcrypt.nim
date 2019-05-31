##  gcrypt.h -  GNU Cryptographic Library Interface              -*- c -*-
##  Copyright (C) 1998-2017 Free Software Foundation, Inc.
##  Copyright (C) 2012-2017 g10 Code GmbH
##
##  This file is part of Libgcrypt.
##
##  Libgcrypt is free software; you can redistribute it and/or modify
##  it under the terms of the GNU Lesser General Public License as
##  published by the Free Software Foundation; either version 2.1 of
##  the License, or (at your option) any later version.
##
##  Libgcrypt is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU Lesser General Public License for more details.
##
##  You should have received a copy of the GNU Lesser General Public
##  License along with this program; if not, see <http://www.gnu.org/licenses/>.
##
##  File: src/gcrypt.h.  Generated from gcrypt.h.in by configure.
##

type
  gcry_socklen_t* = socklen_t

##  This is required for error code compatibility.

const
  _GCRY_ERR_SOURCE_DEFAULT* = GPG_ERR_SOURCE_GCRYPT

##  The version of this header should match the one of the library. It
##    should not be used by a program because gcry_check_version() should
##    return the same version.  The purpose of this macro is to let
##    autoconf (using the AM_PATH_GCRYPT macro) check that this header
##    matches the installed library.

const
  GCRYPT_VERSION* = "1.8.4"

##  The version number of this header.  It may be used to handle minor
##    API incompatibilities.

const
  GCRYPT_VERSION_NUMBER* = 0x00010804

##  Internal: We can't use the convenience macros for the multi
##    precision integer functions when building this library.

when defined(_GCRYPT_IN_LIBGCRYPT):
##  We want to use gcc attributes when possible.  Warning: Don't use
##    these macros in your programs: As indicated by the leading
##    underscore they are subject to change without notice.

when defined(__GNUC__):
  const
    _GCRY_GCC_VERSION* = (
      __GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
  when _GCRY_GCC_VERSION >= 30100:
    const
      _GCRY_GCC_ATTR_DEPRECATED* = __attribute__((__deprecated__))
  when _GCRY_GCC_VERSION >= 29600:
    const
      _GCRY_GCC_ATTR_PURE* = __attribute__((__pure__))
  when _GCRY_GCC_VERSION >= 30200:
    const
      _GCRY_GCC_ATTR_MALLOC* = __attribute__((__malloc__))
  template _GCRY_GCC_ATTR_PRINTF*(f, a: untyped): untyped =
    __attribute__((format(printf, f, a)))

  when _GCRY_GCC_VERSION >= 40000:
    template _GCRY_GCC_ATTR_SENTINEL*(a: untyped): untyped =
      __attribute__((sentinel(a)))

when not defined(_GCRY_GCC_ATTR_PRINTF):
  template _GCRY_GCC_ATTR_PRINTF*(f, a: untyped): void =
    nil

when not defined(_GCRY_GCC_ATTR_SENTINEL):
  template _GCRY_GCC_ATTR_SENTINEL*(a: untyped): void =
    nil

##  Make up an attribute to mark functions and types as deprecated but
##    allow internal use by Libgcrypt.

when defined(_GCRYPT_IN_LIBGCRYPT):
  const
    _GCRY_ATTR_INTERNAL* = true
else:
  const
    _GCRY_ATTR_INTERNAL* = _GCRY_GCC_ATTR_DEPRECATED
##  Wrappers for the libgpg-error library.

type
  gcry_error_t* = gpg_error_t
  gcry_err_code_t* = gpg_err_code_t
  gcry_err_source_t* = gpg_err_source_t

##
## static GPG_ERR_INLINE gcry_error_t
## gcry_err_make (gcry_err_source_t source, gcry_err_code_t code)
## {
##   return gpg_err_make (source, code);
## }
##
##  The user can define GPG_ERR_SOURCE_DEFAULT before including this
##    file to specify a default source for gpg_error.

##
## static GPG_ERR_INLINE gcry_error_t
## gcry_error (gcry_err_code_t code)
## {
##   return gcry_err_make (GCRY_ERR_SOURCE_DEFAULT, code);
## }
##
## static GPG_ERR_INLINE gcry_err_code_t
## gcry_err_code (gcry_error_t err)
## {
##   return gpg_err_code (err);
## }
##
##
## static GPG_ERR_INLINE gcry_err_source_t
## gcry_err_source (gcry_error_t err)
## {
##   return gpg_err_source (err);
## }
##
##  Return a pointer to a string containing a description of the error
##    code in the error value ERR.

proc gcry_strerror*(err: gcry_error_t): cstring {.importc: "gcry_strerror",
    dynlib: foo.}
##  Return a pointer to a string containing a description of the error
##    source in the error value ERR.

proc gcry_strsource*(err: gcry_error_t): cstring {.importc: "gcry_strsource",
    dynlib: foo.}
##  Retrieve the error code for the system error ERR.  This returns
##    GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
##    this).

proc gcry_err_code_from_errno*(err: cint): gcry_err_code_t {.
    importc: "gcry_err_code_from_errno", dynlib: foo.}
##  Retrieve the system error for the error code CODE.  This returns 0
##    if CODE is not a system error code.

proc gcry_err_code_to_errno*(code: gcry_err_code_t): cint {.
    importc: "gcry_err_code_to_errno", dynlib: foo.}
##  Return an error value with the error source SOURCE and the system
##    error ERR.

proc gcry_err_make_from_errno*(source: gcry_err_source_t; err: cint): gcry_error_t {.
    importc: "gcry_err_make_from_errno", dynlib: foo.}
##  Return an error value with the system error ERR.

proc gcry_error_from_errno*(err: cint): gcry_error_t {.
    importc: "gcry_error_from_errno", dynlib: foo.}
##  NOTE: Since Libgcrypt 1.6 the thread callbacks are not anymore
##    used.  However we keep it to allow for some source code
##    compatibility if used in the standard way.
##  Constants defining the thread model to use.  Used with the OPTION
##    field of the struct gcry_thread_cbs.

const
  GCRY_THREAD_OPTION_DEFAULT* = 0
  GCRY_THREAD_OPTION_USER* = 1
  GCRY_THREAD_OPTION_PTH* = 2
  GCRY_THREAD_OPTION_PTHREAD* = 3

##  The version number encoded in the OPTION field of the struct
##    gcry_thread_cbs.

const
  GCRY_THREAD_OPTION_VERSION* = 1

##  Wrapper for struct ath_ops.

type
  gcry_thread_cbs* {.bycopy.} = object
    option*: cuint ##  The OPTION field encodes the thread model and the version number
                 ##      of this structure.
                 ##        Bits  7 - 0  are used for the thread model
                 ##        Bits 15 - 8  are used for the version number.


var _GCRY_ATTR_INTERNAL* {.importc: "_GCRY_ATTR_INTERNAL", dynlib: foo.}: gcry_thread_cbs

##
## #define GCRY_THREAD_OPTION_PTH_IMPL                                     \
##   static struct gcry_thread_cbs gcry_threads_pth = {                    \
##     (GCRY_THREAD_OPTION_PTH | (GCRY_THREAD_OPTION_VERSION << 8))}
##
## #define GCRY_THREAD_OPTION_PTHREAD_IMPL                                 \
##   static struct gcry_thread_cbs gcry_threads_pthread = {                \
##     (GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8))}
##
##  A generic context object as used by some functions.

type
  gcry_context* {.bycopy.} = object

  gcry_ctx_t* = ptr gcry_context

##  The data objects used to hold multi precision integers.

type
  gcry_mpi* {.bycopy.} = object

  gcry_mpi_t* = ptr gcry_mpi
  gcry_mpi_point* {.bycopy.} = object

  gcry_mpi_point_t* = ptr gcry_mpi_point

##
## #ifndef GCRYPT_NO_DEPRECATED
## typedef struct gcry_mpi *GCRY_MPI _GCRY_GCC_ATTR_DEPRECATED;
## typedef struct gcry_mpi *GcryMPI _GCRY_GCC_ATTR_DEPRECATED;
## #endif
##
##  A structure used for scatter gather hashing.

type
  gcry_buffer_t* {.bycopy.} = object
    size*: csize               ##  The allocated size of the buffer or 0.
    off*: csize                ##  Offset into the buffer.
    len*: csize                ##  The used length of the buffer.
    data*: pointer             ##  The buffer.


##  Check that the library fulfills the version requirement.

proc gcry_check_version*(req_version: cstring): cstring {.
    importc: "gcry_check_version", dynlib: foo.}
##  Codes for function dispatchers.
##  Codes used with the gcry_control function.

type
  gcry_ctl_cmds* {.size: sizeof(cint).} = enum ##  Note: 1 .. 2 are not anymore used.
    GCRYCTL_CFB_SYNC = 3, GCRYCTL_RESET = 4, ##  e.g. for MDs
    GCRYCTL_FINALIZE = 5, GCRYCTL_GET_KEYLEN = 6, GCRYCTL_GET_BLKLEN = 7,
    GCRYCTL_TEST_ALGO = 8, GCRYCTL_IS_SECURE = 9, GCRYCTL_GET_ASNOID = 10,
    GCRYCTL_ENABLE_ALGO = 11, GCRYCTL_DISABLE_ALGO = 12,
    GCRYCTL_DUMP_RANDOM_STATS = 13, GCRYCTL_DUMP_SECMEM_STATS = 14,
    GCRYCTL_GET_ALGO_NPKEY = 15, GCRYCTL_GET_ALGO_NSKEY = 16,
    GCRYCTL_GET_ALGO_NSIGN = 17, GCRYCTL_GET_ALGO_NENCR = 18,
    GCRYCTL_SET_VERBOSITY = 19, GCRYCTL_SET_DEBUG_FLAGS = 20,
    GCRYCTL_CLEAR_DEBUG_FLAGS = 21, GCRYCTL_USE_SECURE_RNDPOOL = 22,
    GCRYCTL_DUMP_MEMORY_STATS = 23, GCRYCTL_INIT_SECMEM = 24,
    GCRYCTL_TERM_SECMEM = 25, GCRYCTL_DISABLE_SECMEM_WARN = 27,
    GCRYCTL_SUSPEND_SECMEM_WARN = 28, GCRYCTL_RESUME_SECMEM_WARN = 29,
    GCRYCTL_DROP_PRIVS = 30, GCRYCTL_ENABLE_M_GUARD = 31, GCRYCTL_START_DUMP = 32,
    GCRYCTL_STOP_DUMP = 33, GCRYCTL_GET_ALGO_USAGE = 34, GCRYCTL_IS_ALGO_ENABLED = 35,
    GCRYCTL_DISABLE_INTERNAL_LOCKING = 36, GCRYCTL_DISABLE_SECMEM = 37,
    GCRYCTL_INITIALIZATION_FINISHED = 38, GCRYCTL_INITIALIZATION_FINISHED_P = 39,
    GCRYCTL_ANY_INITIALIZATION_P = 40, GCRYCTL_SET_CBC_CTS = 41, GCRYCTL_SET_CBC_MAC = 42, ##  Note: 43 is not anymore used.
    GCRYCTL_ENABLE_QUICK_RANDOM = 44, GCRYCTL_SET_RANDOM_SEED_FILE = 45,
    GCRYCTL_UPDATE_RANDOM_SEED_FILE = 46, GCRYCTL_SET_THREAD_CBS = 47,
    GCRYCTL_FAST_POLL = 48, GCRYCTL_SET_RANDOM_DAEMON_SOCKET = 49,
    GCRYCTL_USE_RANDOM_DAEMON = 50, GCRYCTL_FAKED_RANDOM_P = 51,
    GCRYCTL_SET_RNDEGD_SOCKET = 52, GCRYCTL_PRINT_CONFIG = 53,
    GCRYCTL_OPERATIONAL_P = 54, GCRYCTL_FIPS_MODE_P = 55,
    GCRYCTL_FORCE_FIPS_MODE = 56, GCRYCTL_SELFTEST = 57, ##  Note: 58 .. 62 are used internally.
    GCRYCTL_DISABLE_HWF = 63, GCRYCTL_SET_ENFORCED_FIPS_FLAG = 64,
    GCRYCTL_SET_PREFERRED_RNG_TYPE = 65, GCRYCTL_GET_CURRENT_RNG_TYPE = 66,
    GCRYCTL_DISABLE_LOCKED_SECMEM = 67, GCRYCTL_DISABLE_PRIV_DROP = 68,
    GCRYCTL_SET_CCM_LENGTHS = 69, GCRYCTL_CLOSE_RANDOM_DEVICE = 70,
    GCRYCTL_INACTIVATE_FIPS_FLAG = 71, GCRYCTL_REACTIVATE_FIPS_FLAG = 72,
    GCRYCTL_SET_SBOX = 73, GCRYCTL_DRBG_REINIT = 74, GCRYCTL_SET_TAGLEN = 75,
    GCRYCTL_GET_TAGLEN = 76, GCRYCTL_REINIT_SYSCALL_CLAMP = 77


##  Perform various operations defined by CMD.

proc gcry_control*(CMD: gcry_ctl_cmds): gcry_error_t {.varargs,
    importc: "gcry_control", dynlib: foo.}
##  S-expression management.
##  The object to represent an S-expression as used with the public key
##    functions.

type
  gcry_sexp* {.bycopy.} = object

  gcry_sexp_t* = ptr gcry_sexp

##
## #ifndef GCRYPT_NO_DEPRECATED
## typedef struct gcry_sexp *GCRY_SEXP _GCRY_GCC_ATTR_DEPRECATED;
## typedef struct gcry_sexp *GcrySexp _GCRY_GCC_ATTR_DEPRECATED;
## #endif
##
##  The possible values for the S-expression format.

type
  gcry_sexp_format* {.size: sizeof(cint).} = enum
    GCRYSEXP_FMT_DEFAULT = 0, GCRYSEXP_FMT_CANON = 1, GCRYSEXP_FMT_BASE64 = 2,
    GCRYSEXP_FMT_ADVANCED = 3


##  Create an new S-expression object from BUFFER of size LENGTH and
##    return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
##    is expected to be in canonized format.

proc gcry_sexp_new*(retsexp: ptr gcry_sexp_t; buffer: pointer; length: csize;
                   autodetect: cint): gcry_error_t {.importc: "gcry_sexp_new",
    dynlib: foo.}
##  Same as gcry_sexp_new but allows to pass a FREEFNC which has the
##     effect to transfer ownership of BUFFER to the created object.

proc gcry_sexp_create*(retsexp: ptr gcry_sexp_t; buffer: pointer; length: csize;
                      autodetect: cint; freefnc: proc (a1: pointer)): gcry_error_t {.
    importc: "gcry_sexp_create", dynlib: foo.}
##  Scan BUFFER and return a new S-expression object in RETSEXP.  This
##    function expects a printf like string in BUFFER.

proc gcry_sexp_sscan*(retsexp: ptr gcry_sexp_t; erroff: ptr csize; buffer: cstring;
                     length: csize): gcry_error_t {.importc: "gcry_sexp_sscan",
    dynlib: foo.}
##  Same as gcry_sexp_sscan but expects a string in FORMAT and can thus
##    only be used for certain encodings.

proc gcry_sexp_build*(retsexp: ptr gcry_sexp_t; erroff: ptr csize; format: cstring): gcry_error_t {.
    varargs, importc: "gcry_sexp_build", dynlib: foo.}
##  Like gcry_sexp_build, but uses an array instead of variable
##    function arguments.

proc gcry_sexp_build_array*(retsexp: ptr gcry_sexp_t; erroff: ptr csize;
                           format: cstring; arg_list: ptr pointer): gcry_error_t {.
    importc: "gcry_sexp_build_array", dynlib: foo.}
##  Release the S-expression object SEXP

proc gcry_sexp_release*(sexp: gcry_sexp_t) {.importc: "gcry_sexp_release",
    dynlib: foo.}
##  Calculate the length of an canonized S-expression in BUFFER and
##    check for a valid encoding.

proc gcry_sexp_canon_len*(buffer: ptr cuchar; length: csize; erroff: ptr csize;
                         errcode: ptr gcry_error_t): csize {.
    importc: "gcry_sexp_canon_len", dynlib: foo.}
##  Copies the S-expression object SEXP into BUFFER using the format
##    specified in MODE.

proc gcry_sexp_sprint*(sexp: gcry_sexp_t; mode: cint; buffer: pointer; maxlength: csize): csize {.
    importc: "gcry_sexp_sprint", dynlib: foo.}
##  Dumps the S-expression object A in a format suitable for debugging
##    to Libgcrypt's logging stream.

proc gcry_sexp_dump*(a: gcry_sexp_t) {.importc: "gcry_sexp_dump", dynlib: foo.}
proc gcry_sexp_cons*(a: gcry_sexp_t; b: gcry_sexp_t): gcry_sexp_t {.
    importc: "gcry_sexp_cons", dynlib: foo.}
proc gcry_sexp_alist*(array: ptr gcry_sexp_t): gcry_sexp_t {.
    importc: "gcry_sexp_alist", dynlib: foo.}
proc gcry_sexp_vlist*(a: gcry_sexp_t): gcry_sexp_t {.varargs,
    importc: "gcry_sexp_vlist", dynlib: foo.}
proc gcry_sexp_append*(a: gcry_sexp_t; n: gcry_sexp_t): gcry_sexp_t {.
    importc: "gcry_sexp_append", dynlib: foo.}
proc gcry_sexp_prepend*(a: gcry_sexp_t; n: gcry_sexp_t): gcry_sexp_t {.
    importc: "gcry_sexp_prepend", dynlib: foo.}
##  Scan the S-expression for a sublist with a type (the car of the
##    list) matching the string TOKEN.  If TOKLEN is not 0, the token is
##    assumed to be raw memory of this length.  The function returns a
##    newly allocated S-expression consisting of the found sublist or
##    `NULL' when not found.

proc gcry_sexp_find_token*(list: gcry_sexp_t; tok: cstring; toklen: csize): gcry_sexp_t {.
    importc: "gcry_sexp_find_token", dynlib: foo.}
##  Return the length of the LIST.  For a valid S-expression this
##    should be at least 1.

proc gcry_sexp_length*(list: gcry_sexp_t): cint {.importc: "gcry_sexp_length",
    dynlib: foo.}
##  Create and return a new S-expression from the element with index
##    NUMBER in LIST.  Note that the first element has the index 0.  If
##    there is no such element, `NULL' is returned.

proc gcry_sexp_nth*(list: gcry_sexp_t; number: cint): gcry_sexp_t {.
    importc: "gcry_sexp_nth", dynlib: foo.}
##  Create and return a new S-expression from the first element in
##    LIST; this called the "type" and should always exist and be a
##    string. `NULL' is returned in case of a problem.

proc gcry_sexp_car*(list: gcry_sexp_t): gcry_sexp_t {.importc: "gcry_sexp_car",
    dynlib: foo.}
##  Create and return a new list form all elements except for the first
##    one.  Note, that this function may return an invalid S-expression
##    because it is not guaranteed, that the type exists and is a string.
##    However, for parsing a complex S-expression it might be useful for
##    intermediate lists.  Returns `NULL' on error.

proc gcry_sexp_cdr*(list: gcry_sexp_t): gcry_sexp_t {.importc: "gcry_sexp_cdr",
    dynlib: foo.}
proc gcry_sexp_cadr*(list: gcry_sexp_t): gcry_sexp_t {.importc: "gcry_sexp_cadr",
    dynlib: foo.}
##  This function is used to get data from a LIST.  A pointer to the
##    actual data with index NUMBER is returned and the length of this
##    data will be stored to DATALEN.  If there is no data at the given
##    index or the index represents another list, `NULL' is returned.
## Note:* The returned pointer is valid as long as LIST is not
##    modified or released.

proc gcry_sexp_nth_data*(list: gcry_sexp_t; number: cint; datalen: ptr csize): cstring {.
    importc: "gcry_sexp_nth_data", dynlib: foo.}
##  This function is used to get data from a LIST.  A malloced buffer to the
##    data with index NUMBER is returned and the length of this
##    data will be stored to RLENGTH.  If there is no data at the given
##    index or the index represents another list, `NULL' is returned.

proc gcry_sexp_nth_buffer*(list: gcry_sexp_t; number: cint; rlength: ptr csize): pointer {.
    importc: "gcry_sexp_nth_buffer", dynlib: foo.}
##  This function is used to get and convert data from a LIST.  The
##    data is assumed to be a Nul terminated string.  The caller must
##    release the returned value using `gcry_free'.  If there is no data
##    at the given index, the index represents a list or the value can't
##    be converted to a string, `NULL' is returned.

proc gcry_sexp_nth_string*(list: gcry_sexp_t; number: cint): cstring {.
    importc: "gcry_sexp_nth_string", dynlib: foo.}
##  This function is used to get and convert data from a LIST. This
##    data is assumed to be an MPI stored in the format described by
##    MPIFMT and returned as a standard Libgcrypt MPI.  The caller must
##    release this returned value using `gcry_mpi_release'.  If there is
##    no data at the given index, the index represents a list or the
##    value can't be converted to an MPI, `NULL' is returned.

proc gcry_sexp_nth_mpi*(list: gcry_sexp_t; number: cint; mpifmt: cint): gcry_mpi_t {.
    importc: "gcry_sexp_nth_mpi", dynlib: foo.}
##  Extract MPIs from an s-expression using a list of parameters.  The
##  names of these parameters are given by the string LIST.  Some
##  special characters may be given to control the conversion:
##
##     + :: Switch to unsigned integer format (default).
##     - :: Switch to standard signed format.
##     / :: Switch to opaque format.
##     & :: Switch to buffer descriptor mode - see below.
##     ? :: The previous parameter is optional.
##
##  In general parameter names are single letters.  To use a string for
##  a parameter name, enclose the name in single quotes.
##
##  Unless in gcry_buffer_t mode for each parameter name a pointer to
##  an MPI variable is expected that must be set to NULL prior to
##  invoking this function, and finally a NULL is expected.  Example:
##
##    _gcry_sexp_extract_param (key, NULL, "n/x+ed",
##                              &mpi_n, &mpi_x, &mpi_e, NULL)
##
##  This stores the parameter "N" from KEY as an unsigned MPI into
##  MPI_N, the parameter "X" as an opaque MPI into MPI_X, and the
##  parameter "E" again as an unsigned MPI into MPI_E.
##
##  If in buffer descriptor mode a pointer to gcry_buffer_t descriptor
##  is expected instead of a pointer to an MPI.  The caller may use two
##  different operation modes: If the DATA field of the provided buffer
##  descriptor is NULL, the function allocates a new buffer and stores
##  it at DATA; the other fields are set accordingly with OFF being 0.
##  If DATA is not NULL, the function assumes that DATA, SIZE, and OFF
##  describe a buffer where to but the data; on return the LEN field
##  receives the number of bytes copied to that buffer; if the buffer
##  is too small, the function immediately returns with an error code
##  (and LEN set to 0).
##
##  PATH is an optional string used to locate a token.  The exclamation
##  mark separated tokens are used to via gcry_sexp_find_token to find
##  a start point inside SEXP.
##
##  The function returns 0 on success.  On error an error code is
##  returned, all passed MPIs that might have been allocated up to this
##  point are deallocated and set to NULL, and all passed buffers are
##  either truncated if the caller supplied the buffer, or deallocated
##  if the function allocated the buffer.
##
##
## gpg_error_t gcry_sexp_extract_param (gcry_sexp_t sexp,
##                                      const char *path,
##                                      const char *list,
##                                      ...) _GCRY_GCC_ATTR_SENTINEL(0);
##
## ******************************************
##                                          *
##   Multi Precision Integer Functions      *
##                                          *
## *****************************************
##  Different formats of external big integer representation.

type
  gcry_mpi_format* {.size: sizeof(cint).} = enum
    GCRYMPI_FMT_NONE = 0, GCRYMPI_FMT_STD = 1, ##  Twos complement stored without length.
    GCRYMPI_FMT_PGP = 2,        ##  As used by OpenPGP (unsigned only).
    GCRYMPI_FMT_SSH = 3,        ##  As used by SSH (like STD but with length).
    GCRYMPI_FMT_HEX = 4,        ##  Hex format.
    GCRYMPI_FMT_USG = 5,        ##  Like STD but unsigned.
    GCRYMPI_FMT_OPAQUE = 8


##  Flags used for creating big integers.

type
  gcry_mpi_flag* {.size: sizeof(cint).} = enum
    GCRYMPI_FLAG_SECURE = 1,    ##  Allocate the number in "secure" memory.
    GCRYMPI_FLAG_OPAQUE = 2, ##  The number is not a real one but just
                          ##                                  a way to store some bytes.  This is
                          ##                                  useful for encrypted big integers.
    GCRYMPI_FLAG_IMMUTABLE = 4, ##  Mark the MPI as immutable.
    GCRYMPI_FLAG_CONST = 8,     ##  Mark the MPI as a constant.
    GCRYMPI_FLAG_USER1 = 0x00000100, ##  User flag 1.
    GCRYMPI_FLAG_USER2 = 0x00000200, ##  User flag 2.
    GCRYMPI_FLAG_USER3 = 0x00000400, ##  User flag 3.
    GCRYMPI_FLAG_USER4 = 0x00000800


##  Macros to return pre-defined MPI constants.

const
  GCRYMPI_CONST_ONE* = (gcry_mpi_get_const(1))
  GCRYMPI_CONST_TWO* = (gcry_mpi_get_const(2))
  GCRYMPI_CONST_THREE* = (gcry_mpi_get_const(3))
  GCRYMPI_CONST_FOUR* = (gcry_mpi_get_const(4))
  GCRYMPI_CONST_EIGHT* = (gcry_mpi_get_const(8))

##  Allocate a new big integer object, initialize it with 0 and
##    initially allocate memory for a number of at least NBITS.

proc gcry_mpi_new*(nbits: cuint): gcry_mpi_t {.importc: "gcry_mpi_new", dynlib: foo.}
##  Same as gcry_mpi_new() but allocate in "secure" memory.

proc gcry_mpi_snew*(nbits: cuint): gcry_mpi_t {.importc: "gcry_mpi_snew", dynlib: foo.}
##  Release the number A and free all associated resources.

proc gcry_mpi_release*(a: gcry_mpi_t) {.importc: "gcry_mpi_release", dynlib: foo.}
##  Create a new number with the same value as A.

proc gcry_mpi_copy*(a: gcry_mpi_t): gcry_mpi_t {.importc: "gcry_mpi_copy", dynlib: foo.}
##  Store the big integer value U in W and release U.

proc gcry_mpi_snatch*(w: gcry_mpi_t; u: gcry_mpi_t) {.importc: "gcry_mpi_snatch",
    dynlib: foo.}
##  Store the big integer value U in W.

proc gcry_mpi_set*(w: gcry_mpi_t; u: gcry_mpi_t): gcry_mpi_t {.
    importc: "gcry_mpi_set", dynlib: foo.}
##  Store the unsigned integer value U in W.

proc gcry_mpi_set_ui*(w: gcry_mpi_t; u: culong): gcry_mpi_t {.
    importc: "gcry_mpi_set_ui", dynlib: foo.}
##  Swap the values of A and B.

proc gcry_mpi_swap*(a: gcry_mpi_t; b: gcry_mpi_t) {.importc: "gcry_mpi_swap",
    dynlib: foo.}
##  Return 1 if A is negative; 0 if zero or positive.

proc gcry_mpi_is_neg*(a: gcry_mpi_t): cint {.importc: "gcry_mpi_is_neg", dynlib: foo.}
##  W = - U

proc gcry_mpi_neg*(w: gcry_mpi_t; u: gcry_mpi_t) {.importc: "gcry_mpi_neg", dynlib: foo.}
##  W = [W]

proc gcry_mpi_abs*(w: gcry_mpi_t) {.importc: "gcry_mpi_abs", dynlib: foo.}
##  Compare the big integer number U and V returning 0 for equality, a
##    positive value for U > V and a negative for U < V.

proc gcry_mpi_cmp*(u: gcry_mpi_t; v: gcry_mpi_t): cint {.importc: "gcry_mpi_cmp",
    dynlib: foo.}
##  Compare the big integer number U with the unsigned integer V
##    returning 0 for equality, a positive value for U > V and a negative
##    for U < V.

proc gcry_mpi_cmp_ui*(u: gcry_mpi_t; v: culong): cint {.importc: "gcry_mpi_cmp_ui",
    dynlib: foo.}
##  Convert the external representation of an integer stored in BUFFER
##    with a length of BUFLEN into a newly create MPI returned in
##    RET_MPI.  If NSCANNED is not NULL, it will receive the number of
##    bytes actually scanned after a successful operation.

proc gcry_mpi_scan*(ret_mpi: ptr gcry_mpi_t; format: gcry_mpi_format; buffer: pointer;
                   buflen: csize; nscanned: ptr csize): gcry_error_t {.
    importc: "gcry_mpi_scan", dynlib: foo.}
##  Convert the big integer A into the external representation
##    described by FORMAT and store it in the provided BUFFER which has
##    been allocated by the user with a size of BUFLEN bytes.  NWRITTEN
##    receives the actual length of the external representation unless it
##    has been passed as NULL.

proc gcry_mpi_print*(format: gcry_mpi_format; buffer: ptr cuchar; buflen: csize;
                    nwritten: ptr csize; a: gcry_mpi_t): gcry_error_t {.
    importc: "gcry_mpi_print", dynlib: foo.}
##  Convert the big integer A into the external representation described
##    by FORMAT and store it in a newly allocated buffer which address
##    will be put into BUFFER.  NWRITTEN receives the actual lengths of the
##    external representation.

proc gcry_mpi_aprint*(format: gcry_mpi_format; buffer: ptr ptr cuchar;
                     nwritten: ptr csize; a: gcry_mpi_t): gcry_error_t {.
    importc: "gcry_mpi_aprint", dynlib: foo.}
##  Dump the value of A in a format suitable for debugging to
##    Libgcrypt's logging stream.  Note that one leading space but no
##    trailing space or linefeed will be printed.  It is okay to pass
##    NULL for A.

proc gcry_mpi_dump*(a: gcry_mpi_t) {.importc: "gcry_mpi_dump", dynlib: foo.}
##  W = U + V.

proc gcry_mpi_add*(w: gcry_mpi_t; u: gcry_mpi_t; v: gcry_mpi_t) {.
    importc: "gcry_mpi_add", dynlib: foo.}
##  W = U + V.  V is an unsigned integer.

proc gcry_mpi_add_ui*(w: gcry_mpi_t; u: gcry_mpi_t; v: culong) {.
    importc: "gcry_mpi_add_ui", dynlib: foo.}
##  W = U + V mod M.

proc gcry_mpi_addm*(w: gcry_mpi_t; u: gcry_mpi_t; v: gcry_mpi_t; m: gcry_mpi_t) {.
    importc: "gcry_mpi_addm", dynlib: foo.}
##  W = U - V.

proc gcry_mpi_sub*(w: gcry_mpi_t; u: gcry_mpi_t; v: gcry_mpi_t) {.
    importc: "gcry_mpi_sub", dynlib: foo.}
##  W = U - V.  V is an unsigned integer.

proc gcry_mpi_sub_ui*(w: gcry_mpi_t; u: gcry_mpi_t; v: culong) {.
    importc: "gcry_mpi_sub_ui", dynlib: foo.}
##  W = U - V mod M

proc gcry_mpi_subm*(w: gcry_mpi_t; u: gcry_mpi_t; v: gcry_mpi_t; m: gcry_mpi_t) {.
    importc: "gcry_mpi_subm", dynlib: foo.}
##  W = U * V.

proc gcry_mpi_mul*(w: gcry_mpi_t; u: gcry_mpi_t; v: gcry_mpi_t) {.
    importc: "gcry_mpi_mul", dynlib: foo.}
##  W = U * V.  V is an unsigned integer.

proc gcry_mpi_mul_ui*(w: gcry_mpi_t; u: gcry_mpi_t; v: culong) {.
    importc: "gcry_mpi_mul_ui", dynlib: foo.}
##  W = U * V mod M.

proc gcry_mpi_mulm*(w: gcry_mpi_t; u: gcry_mpi_t; v: gcry_mpi_t; m: gcry_mpi_t) {.
    importc: "gcry_mpi_mulm", dynlib: foo.}
##  W = U * (2 ^ CNT).

proc gcry_mpi_mul_2exp*(w: gcry_mpi_t; u: gcry_mpi_t; cnt: culong) {.
    importc: "gcry_mpi_mul_2exp", dynlib: foo.}
##  Q = DIVIDEND / DIVISOR, R = DIVIDEND % DIVISOR,
##    Q or R may be passed as NULL.  ROUND should be negative or 0.

proc gcry_mpi_div*(q: gcry_mpi_t; r: gcry_mpi_t; dividend: gcry_mpi_t;
                  divisor: gcry_mpi_t; round: cint) {.importc: "gcry_mpi_div",
    dynlib: foo.}
##  R = DIVIDEND % DIVISOR

proc gcry_mpi_mod*(r: gcry_mpi_t; dividend: gcry_mpi_t; divisor: gcry_mpi_t) {.
    importc: "gcry_mpi_mod", dynlib: foo.}
##  W = B ^ E mod M.

proc gcry_mpi_powm*(w: gcry_mpi_t; b: gcry_mpi_t; e: gcry_mpi_t; m: gcry_mpi_t) {.
    importc: "gcry_mpi_powm", dynlib: foo.}
##  Set G to the greatest common divisor of A and B.
##    Return true if the G is 1.

proc gcry_mpi_gcd*(g: gcry_mpi_t; a: gcry_mpi_t; b: gcry_mpi_t): cint {.
    importc: "gcry_mpi_gcd", dynlib: foo.}
##  Set X to the multiplicative inverse of A mod M.
##    Return true if the value exists.

proc gcry_mpi_invm*(x: gcry_mpi_t; a: gcry_mpi_t; m: gcry_mpi_t): cint {.
    importc: "gcry_mpi_invm", dynlib: foo.}
##  Create a new point object.  NBITS is usually 0.

proc gcry_mpi_point_new*(nbits: cuint): gcry_mpi_point_t {.
    importc: "gcry_mpi_point_new", dynlib: foo.}
##  Release the object POINT.  POINT may be NULL.

proc gcry_mpi_point_release*(point: gcry_mpi_point_t) {.
    importc: "gcry_mpi_point_release", dynlib: foo.}
##  Return a copy of POINT.

proc gcry_mpi_point_copy*(point: gcry_mpi_point_t): gcry_mpi_point_t {.
    importc: "gcry_mpi_point_copy", dynlib: foo.}
##  Store the projective coordinates from POINT into X, Y, and Z.

proc gcry_mpi_point_get*(x: gcry_mpi_t; y: gcry_mpi_t; z: gcry_mpi_t;
                        point: gcry_mpi_point_t) {.importc: "gcry_mpi_point_get",
    dynlib: foo.}
##  Store the projective coordinates from POINT into X, Y, and Z and
##    release POINT.

proc gcry_mpi_point_snatch_get*(x: gcry_mpi_t; y: gcry_mpi_t; z: gcry_mpi_t;
                               point: gcry_mpi_point_t) {.
    importc: "gcry_mpi_point_snatch_get", dynlib: foo.}
##  Store the projective coordinates X, Y, and Z into POINT.

proc gcry_mpi_point_set*(point: gcry_mpi_point_t; x: gcry_mpi_t; y: gcry_mpi_t;
                        z: gcry_mpi_t): gcry_mpi_point_t {.
    importc: "gcry_mpi_point_set", dynlib: foo.}
##  Store the projective coordinates X, Y, and Z into POINT and release
##    X, Y, and Z.

proc gcry_mpi_point_snatch_set*(point: gcry_mpi_point_t; x: gcry_mpi_t;
                               y: gcry_mpi_t; z: gcry_mpi_t): gcry_mpi_point_t {.
    importc: "gcry_mpi_point_snatch_set", dynlib: foo.}
##  Allocate a new context for elliptic curve operations based on the
##    parameters given by KEYPARAM or using CURVENAME.

proc gcry_mpi_ec_new*(r_ctx: ptr gcry_ctx_t; keyparam: gcry_sexp_t; curvename: cstring): gpg_error_t {.
    importc: "gcry_mpi_ec_new", dynlib: foo.}
##  Get a named MPI from an elliptic curve context.

proc gcry_mpi_ec_get_mpi*(name: cstring; ctx: gcry_ctx_t; copy: cint): gcry_mpi_t {.
    importc: "gcry_mpi_ec_get_mpi", dynlib: foo.}
##  Get a named point from an elliptic curve context.

proc gcry_mpi_ec_get_point*(name: cstring; ctx: gcry_ctx_t; copy: cint): gcry_mpi_point_t {.
    importc: "gcry_mpi_ec_get_point", dynlib: foo.}
##  Store a named MPI into an elliptic curve context.

proc gcry_mpi_ec_set_mpi*(name: cstring; newvalue: gcry_mpi_t; ctx: gcry_ctx_t): gpg_error_t {.
    importc: "gcry_mpi_ec_set_mpi", dynlib: foo.}
##  Store a named point into an elliptic curve context.

proc gcry_mpi_ec_set_point*(name: cstring; newvalue: gcry_mpi_point_t;
                           ctx: gcry_ctx_t): gpg_error_t {.
    importc: "gcry_mpi_ec_set_point", dynlib: foo.}
##  Decode and store VALUE into RESULT.

proc gcry_mpi_ec_decode_point*(result: gcry_mpi_point_t; value: gcry_mpi_t;
                              ctx: gcry_ctx_t): gpg_error_t {.
    importc: "gcry_mpi_ec_decode_point", dynlib: foo.}
##  Store the affine coordinates of POINT into X and Y.

proc gcry_mpi_ec_get_affine*(x: gcry_mpi_t; y: gcry_mpi_t; point: gcry_mpi_point_t;
                            ctx: gcry_ctx_t): cint {.
    importc: "gcry_mpi_ec_get_affine", dynlib: foo.}
##  W = 2 * U.

proc gcry_mpi_ec_dup*(w: gcry_mpi_point_t; u: gcry_mpi_point_t; ctx: gcry_ctx_t) {.
    importc: "gcry_mpi_ec_dup", dynlib: foo.}
##  W = U + V.

proc gcry_mpi_ec_add*(w: gcry_mpi_point_t; u: gcry_mpi_point_t; v: gcry_mpi_point_t;
                     ctx: gcry_ctx_t) {.importc: "gcry_mpi_ec_add", dynlib: foo.}
##  W = U - V.

proc gcry_mpi_ec_sub*(w: gcry_mpi_point_t; u: gcry_mpi_point_t; v: gcry_mpi_point_t;
                     ctx: gcry_ctx_t) {.importc: "gcry_mpi_ec_sub", dynlib: foo.}
##  W = N * U.

proc gcry_mpi_ec_mul*(w: gcry_mpi_point_t; n: gcry_mpi_t; u: gcry_mpi_point_t;
                     ctx: gcry_ctx_t) {.importc: "gcry_mpi_ec_mul", dynlib: foo.}
##  Return true if POINT is on the curve described by CTX.

proc gcry_mpi_ec_curve_point*(w: gcry_mpi_point_t; ctx: gcry_ctx_t): cint {.
    importc: "gcry_mpi_ec_curve_point", dynlib: foo.}
##  Return the number of bits required to represent A.

proc gcry_mpi_get_nbits*(a: gcry_mpi_t): cuint {.importc: "gcry_mpi_get_nbits",
    dynlib: foo.}
##  Return true when bit number N (counting from 0) is set in A.

proc gcry_mpi_test_bit*(a: gcry_mpi_t; n: cuint): cint {.importc: "gcry_mpi_test_bit",
    dynlib: foo.}
##  Set bit number N in A.

proc gcry_mpi_set_bit*(a: gcry_mpi_t; n: cuint) {.importc: "gcry_mpi_set_bit",
    dynlib: foo.}
##  Clear bit number N in A.

proc gcry_mpi_clear_bit*(a: gcry_mpi_t; n: cuint) {.importc: "gcry_mpi_clear_bit",
    dynlib: foo.}
##  Set bit number N in A and clear all bits greater than N.

proc gcry_mpi_set_highbit*(a: gcry_mpi_t; n: cuint) {.
    importc: "gcry_mpi_set_highbit", dynlib: foo.}
##  Clear bit number N in A and all bits greater than N.

proc gcry_mpi_clear_highbit*(a: gcry_mpi_t; n: cuint) {.
    importc: "gcry_mpi_clear_highbit", dynlib: foo.}
##  Shift the value of A by N bits to the right and store the result in X.

proc gcry_mpi_rshift*(x: gcry_mpi_t; a: gcry_mpi_t; n: cuint) {.
    importc: "gcry_mpi_rshift", dynlib: foo.}
##  Shift the value of A by N bits to the left and store the result in X.

proc gcry_mpi_lshift*(x: gcry_mpi_t; a: gcry_mpi_t; n: cuint) {.
    importc: "gcry_mpi_lshift", dynlib: foo.}
##  Store NBITS of the value P points to in A and mark A as an opaque
##    value.  On success A received the the ownership of the value P.
##    WARNING: Never use an opaque MPI for anything thing else than
##    gcry_mpi_release, gcry_mpi_get_opaque.

proc gcry_mpi_set_opaque*(a: gcry_mpi_t; p: pointer; nbits: cuint): gcry_mpi_t {.
    importc: "gcry_mpi_set_opaque", dynlib: foo.}
##  Store NBITS of the value P points to in A and mark A as an opaque
##    value.  The function takes a copy of the provided value P.
##    WARNING: Never use an opaque MPI for anything thing else than
##    gcry_mpi_release, gcry_mpi_get_opaque.

proc gcry_mpi_set_opaque_copy*(a: gcry_mpi_t; p: pointer; nbits: cuint): gcry_mpi_t {.
    importc: "gcry_mpi_set_opaque_copy", dynlib: foo.}
##  Return a pointer to an opaque value stored in A and return its size
##    in NBITS.  Note that the returned pointer is still owned by A and
##    that the function should never be used for an non-opaque MPI.

proc gcry_mpi_get_opaque*(a: gcry_mpi_t; nbits: ptr cuint): pointer {.
    importc: "gcry_mpi_get_opaque", dynlib: foo.}
##  Set the FLAG for the big integer A.  Currently only the flag
##    GCRYMPI_FLAG_SECURE is allowed to convert A into an big intger
##    stored in "secure" memory.

proc gcry_mpi_set_flag*(a: gcry_mpi_t; flag: gcry_mpi_flag) {.
    importc: "gcry_mpi_set_flag", dynlib: foo.}
##  Clear FLAG for the big integer A.  Note that this function is
##    currently useless as no flags are allowed.

proc gcry_mpi_clear_flag*(a: gcry_mpi_t; flag: gcry_mpi_flag) {.
    importc: "gcry_mpi_clear_flag", dynlib: foo.}
##  Return true if the FLAG is set for A.

proc gcry_mpi_get_flag*(a: gcry_mpi_t; flag: gcry_mpi_flag): cint {.
    importc: "gcry_mpi_get_flag", dynlib: foo.}
##  Private function - do not use.

proc gcry_mpi_get_const*(no: cint): gcry_mpi_t {.importc: "gcry_mpi_get_const",
    dynlib: foo.}
##  Unless the GCRYPT_NO_MPI_MACROS is used, provide a couple of
##    convenience macros for the big integer functions.

when not defined(GCRYPT_NO_MPI_MACROS):
  template mpi_new*(n: untyped): untyped =
    gcry_mpi_new((n))

  template mpi_secure_new*(n: untyped): untyped =
    gcry_mpi_snew((n))

  template mpi_release*(a: untyped): void =
    while true:
      gcry_mpi_release((a))
      (a) = nil
      if not 0:
        break

  template mpi_copy*(a: untyped): untyped =
    gcry_mpi_copy((a))

  template mpi_snatch*(w, u: untyped): untyped =
    gcry_mpi_snatch((w), (u))

  template mpi_set*(w, u: untyped): untyped =
    gcry_mpi_set((w), (u))

  template mpi_set_ui*(w, u: untyped): untyped =
    gcry_mpi_set_ui((w), (u))

  template mpi_abs*(w: untyped): untyped =
    gcry_mpi_abs((w))

  template mpi_neg*(w, u: untyped): untyped =
    gcry_mpi_neg((w), (u))

  template mpi_cmp*(u, v: untyped): untyped =
    gcry_mpi_cmp((u), (v))

  template mpi_cmp_ui*(u, v: untyped): untyped =
    gcry_mpi_cmp_ui((u), (v))

  template mpi_is_neg*(a: untyped): untyped =
    gcry_mpi_is_neg((a))

  template mpi_add_ui*(w, u, v: untyped): untyped =
    gcry_mpi_add_ui((w), (u), (v))

  template mpi_add*(w, u, v: untyped): untyped =
    gcry_mpi_add((w), (u), (v))

  template mpi_addm*(w, u, v, m: untyped): untyped =
    gcry_mpi_addm((w), (u), (v), (m))

  template mpi_sub_ui*(w, u, v: untyped): untyped =
    gcry_mpi_sub_ui((w), (u), (v))

  template mpi_sub*(w, u, v: untyped): untyped =
    gcry_mpi_sub((w), (u), (v))

  template mpi_subm*(w, u, v, m: untyped): untyped =
    gcry_mpi_subm((w), (u), (v), (m))

  template mpi_mul_ui*(w, u, v: untyped): untyped =
    gcry_mpi_mul_ui((w), (u), (v))

  template mpi_mul_2exp*(w, u, v: untyped): untyped =
    gcry_mpi_mul_2exp((w), (u), (v))

  template mpi_mul*(w, u, v: untyped): untyped =
    gcry_mpi_mul((w), (u), (v))

  template mpi_mulm*(w, u, v, m: untyped): untyped =
    gcry_mpi_mulm((w), (u), (v), (m))

  template mpi_powm*(w, b, e, m: untyped): untyped =
    gcry_mpi_powm((w), (b), (e), (m))

  template mpi_tdiv*(q, r, a, m: untyped): untyped =
    gcry_mpi_div((q), (r), (a), (m), 0)

  template mpi_fdiv*(q, r, a, m: untyped): untyped =
    gcry_mpi_div((q), (r), (a), (m), -1)

  template mpi_mod*(r, a, m: untyped): untyped =
    gcry_mpi_mod((r), (a), (m))

  template mpi_gcd*(g, a, b: untyped): untyped =
    gcry_mpi_gcd((g), (a), (b))

  template mpi_invm*(g, a, b: untyped): untyped =
    gcry_mpi_invm((g), (a), (b))

  template mpi_point_new*(n: untyped): untyped =
    gcry_mpi_point_new((n))

  template mpi_point_release*(p: untyped): void =
    while true:
      gcry_mpi_point_release((p))
      (p) = nil
      if not 0:
        break

  template mpi_point_copy*(p: untyped): untyped =
    gcry_mpi_point_copy((p))

  template mpi_point_get*(x, y, z, p: untyped): untyped =
    gcry_mpi_point_get((x), (y), (z), (p))

  template mpi_point_snatch_get*(x, y, z, p: untyped): untyped =
    gcry_mpi_point_snatch_get((x), (y), (z), (p))

  template mpi_point_set*(p, x, y, z: untyped): untyped =
    gcry_mpi_point_set((p), (x), (y), (z))

  template mpi_point_snatch_set*(p, x, y, z: untyped): untyped =
    gcry_mpi_point_snatch_set((p), (x), (y), (z))

  template mpi_get_nbits*(a: untyped): untyped =
    gcry_mpi_get_nbits((a))

  template mpi_test_bit*(a, b: untyped): untyped =
    gcry_mpi_test_bit((a), (b))

  template mpi_set_bit*(a, b: untyped): untyped =
    gcry_mpi_set_bit((a), (b))

  template mpi_set_highbit*(a, b: untyped): untyped =
    gcry_mpi_set_highbit((a), (b))

  template mpi_clear_bit*(a, b: untyped): untyped =
    gcry_mpi_clear_bit((a), (b))

  template mpi_clear_highbit*(a, b: untyped): untyped =
    gcry_mpi_clear_highbit((a), (b))

  template mpi_rshift*(a, b, c: untyped): untyped =
    gcry_mpi_rshift((a), (b), (c))

  template mpi_lshift*(a, b, c: untyped): untyped =
    gcry_mpi_lshift((a), (b), (c))

  template mpi_set_opaque*(a, b, c: untyped): untyped =
    gcry_mpi_set_opaque((a), (b), (c))

  template mpi_get_opaque*(a, b: untyped): untyped =
    gcry_mpi_get_opaque((a), (b))

## ***********************************
##                                   *
##    Symmetric Cipher Functions     *
##                                   *
## **********************************
##  The data object used to hold a handle to an encryption object.

type
  gcry_cipher_handle* {.bycopy.} = object

  gcry_cipher_hd_t* = ptr gcry_cipher_handle

##
## #ifndef GCRYPT_NO_DEPRECATED
## typedef struct gcry_cipher_handle *GCRY_CIPHER_HD _GCRY_GCC_ATTR_DEPRECATED;
## //typedef struct gcry_cipher_handle *GcryCipherHd _GCRY_GCC_ATTR_DEPRECATED;
## #endif
##
##  All symmetric encryption algorithms are identified by their IDs.
##    More IDs may be registered at runtime.

type
  gcry_cipher_algos* {.size: sizeof(cint).} = enum
    GCRY_CIPHER_NONE = 0, GCRY_CIPHER_IDEA = 1, GCRY_CIPHER_3DES = 2,
    GCRY_CIPHER_CAST5 = 3, GCRY_CIPHER_BLOWFISH = 4, GCRY_CIPHER_SAFER_SK128 = 5,
    GCRY_CIPHER_DES_SK = 6, GCRY_CIPHER_AES = 7, GCRY_CIPHER_AES192 = 8,
    GCRY_CIPHER_AES256 = 9, GCRY_CIPHER_TWOFISH = 10, ##  Other cipher numbers are above 300 for OpenPGP reasons.
    GCRY_CIPHER_ARCFOUR = 301,  ##  Fully compatible with RSA's RC4 (tm).
    GCRY_CIPHER_DES = 302,      ##  Yes, this is single key 56 bit DES.
    GCRY_CIPHER_TWOFISH128 = 303, GCRY_CIPHER_SERPENT128 = 304,
    GCRY_CIPHER_SERPENT192 = 305, GCRY_CIPHER_SERPENT256 = 306, GCRY_CIPHER_RFC2268_40 = 307, ##  Ron's Cipher 2 (40 bit).
    GCRY_CIPHER_RFC2268_128 = 308, ##  Ron's Cipher 2 (128 bit).
    GCRY_CIPHER_SEED = 309,     ##  128 bit cipher described in RFC4269.
    GCRY_CIPHER_CAMELLIA128 = 310, GCRY_CIPHER_CAMELLIA192 = 311,
    GCRY_CIPHER_CAMELLIA256 = 312, GCRY_CIPHER_SALSA20 = 313,
    GCRY_CIPHER_SALSA20R12 = 314, GCRY_CIPHER_GOST28147 = 315,
    GCRY_CIPHER_CHACHA20 = 316


##  The Rijndael algorithm is basically AES, so provide some macros.

const
  GCRY_CIPHER_AES128* = GCRY_CIPHER_AES
  GCRY_CIPHER_RIJNDAEL* = GCRY_CIPHER_AES
  GCRY_CIPHER_RIJNDAEL128* = GCRY_CIPHER_AES128
  GCRY_CIPHER_RIJNDAEL192* = GCRY_CIPHER_AES192
  GCRY_CIPHER_RIJNDAEL256* = GCRY_CIPHER_AES256

##  The supported encryption modes.  Note that not all of them are
##    supported for each algorithm.

type
  gcry_cipher_modes* {.size: sizeof(cint).} = enum
    GCRY_CIPHER_MODE_NONE = 0,  ##  Not yet specified.
    GCRY_CIPHER_MODE_ECB = 1,   ##  Electronic codebook.
    GCRY_CIPHER_MODE_CFB = 2,   ##  Cipher feedback.
    GCRY_CIPHER_MODE_CBC = 3,   ##  Cipher block chaining.
    GCRY_CIPHER_MODE_STREAM = 4, ##  Used with stream ciphers.
    GCRY_CIPHER_MODE_OFB = 5,   ##  Outer feedback.
    GCRY_CIPHER_MODE_CTR = 6,   ##  Counter.
    GCRY_CIPHER_MODE_AESWRAP = 7, ##  AES-WRAP algorithm.
    GCRY_CIPHER_MODE_CCM = 8,   ##  Counter with CBC-MAC.
    GCRY_CIPHER_MODE_GCM = 9,   ##  Galois Counter Mode.
    GCRY_CIPHER_MODE_POLY1305 = 10, ##  Poly1305 based AEAD mode.
    GCRY_CIPHER_MODE_OCB = 11,  ##  OCB3 mode.
    GCRY_CIPHER_MODE_CFB8 = 12, ##  Cipher feedback (8 bit mode).
    GCRY_CIPHER_MODE_XTS = 13


##  Flags used with the open function.

type
  gcry_cipher_flags* {.size: sizeof(cint).} = enum
    GCRY_CIPHER_SECURE = 1,     ##  Allocate in secure memory.
    GCRY_CIPHER_ENABLE_SYNC = 2, ##  Enable CFB sync mode.
    GCRY_CIPHER_CBC_CTS = 4,    ##  Enable CBC cipher text stealing (CTS).
    GCRY_CIPHER_CBC_MAC = 8


##  GCM works only with blocks of 128 bits

const
  GCRY_GCM_BLOCK_LEN* = (128 div 8)

##  CCM works only with blocks of 128 bits.

const
  GCRY_CCM_BLOCK_LEN* = (128 div 8)

##  OCB works only with blocks of 128 bits.

const
  GCRY_OCB_BLOCK_LEN* = (128 div 8)

##  XTS works only with blocks of 128 bits.

const
  GCRY_XTS_BLOCK_LEN* = (128 div 8)

##  Create a handle for algorithm ALGO to be used in MODE.  FLAGS may
##    be given as an bitwise OR of the gcry_cipher_flags values.

proc gcry_cipher_open*(handle: ptr gcry_cipher_hd_t; algo: cint; mode: cint;
                      flags: cuint): gcry_error_t {.importc: "gcry_cipher_open",
    dynlib: foo.}
##  Close the cipher handle H and release all resource.

proc gcry_cipher_close*(h: gcry_cipher_hd_t) {.importc: "gcry_cipher_close",
    dynlib: foo.}
##  Perform various operations on the cipher object H.

proc gcry_cipher_ctl*(h: gcry_cipher_hd_t; cmd: cint; buffer: pointer; buflen: csize): gcry_error_t {.
    importc: "gcry_cipher_ctl", dynlib: foo.}
##  Retrieve various information about the cipher object H.

proc gcry_cipher_info*(h: gcry_cipher_hd_t; what: cint; buffer: pointer;
                      nbytes: ptr csize): gcry_error_t {.
    importc: "gcry_cipher_info", dynlib: foo.}
##  Retrieve various information about the cipher algorithm ALGO.

proc gcry_cipher_algo_info*(algo: cint; what: cint; buffer: pointer; nbytes: ptr csize): gcry_error_t {.
    importc: "gcry_cipher_algo_info", dynlib: foo.}
##  Map the cipher algorithm whose ID is contained in ALGORITHM to a
##    string representation of the algorithm name.  For unknown algorithm
##    IDs this function returns "?".

proc gcry_cipher_algo_name*(algorithm: cint): cstring {.
    importc: "gcry_cipher_algo_name", dynlib: foo.}
##  Map the algorithm name NAME to an cipher algorithm ID.  Return 0 if
##    the algorithm name is not known.

proc gcry_cipher_map_name*(name: cstring): cint {.importc: "gcry_cipher_map_name",
    dynlib: foo.}
##  Given an ASN.1 object identifier in standard IETF dotted decimal
##    format in STRING, return the encryption mode associated with that
##    OID or 0 if not known or applicable.

proc gcry_cipher_mode_from_oid*(string: cstring): cint {.
    importc: "gcry_cipher_mode_from_oid", dynlib: foo.}
##  Encrypt the plaintext of size INLEN in IN using the cipher handle H
##    into the buffer OUT which has an allocated length of OUTSIZE.  For
##    most algorithms it is possible to pass NULL for in and 0 for INLEN
##    and do a in-place decryption of the data provided in OUT.

proc gcry_cipher_encrypt*(h: gcry_cipher_hd_t; `out`: pointer; outsize: csize;
                         `in`: pointer; inlen: csize): gcry_error_t {.
    importc: "gcry_cipher_encrypt", dynlib: foo.}
##  The counterpart to gcry_cipher_encrypt.

proc gcry_cipher_decrypt*(h: gcry_cipher_hd_t; `out`: pointer; outsize: csize;
                         `in`: pointer; inlen: csize): gcry_error_t {.
    importc: "gcry_cipher_decrypt", dynlib: foo.}
##  Set KEY of length KEYLEN bytes for the cipher handle HD.

proc gcry_cipher_setkey*(hd: gcry_cipher_hd_t; key: pointer; keylen: csize): gcry_error_t {.
    importc: "gcry_cipher_setkey", dynlib: foo.}
##  Set initialization vector IV of length IVLEN for the cipher handle HD.

proc gcry_cipher_setiv*(hd: gcry_cipher_hd_t; iv: pointer; ivlen: csize): gcry_error_t {.
    importc: "gcry_cipher_setiv", dynlib: foo.}
##  Provide additional authentication data for AEAD modes/ciphers.

proc gcry_cipher_authenticate*(hd: gcry_cipher_hd_t; abuf: pointer; abuflen: csize): gcry_error_t {.
    importc: "gcry_cipher_authenticate", dynlib: foo.}
##  Get authentication tag for AEAD modes/ciphers.

proc gcry_cipher_gettag*(hd: gcry_cipher_hd_t; outtag: pointer; taglen: csize): gcry_error_t {.
    importc: "gcry_cipher_gettag", dynlib: foo.}
##  Check authentication tag for AEAD modes/ciphers.

proc gcry_cipher_checktag*(hd: gcry_cipher_hd_t; intag: pointer; taglen: csize): gcry_error_t {.
    importc: "gcry_cipher_checktag", dynlib: foo.}
##  Reset the handle to the state after open.

template gcry_cipher_reset*(h: untyped): untyped =
  gcry_cipher_ctl((h), GCRYCTL_RESET, nil, 0)

##  Perform the OpenPGP sync operation if this is enabled for the
##    cipher handle H.

template gcry_cipher_sync*(h: untyped): untyped =
  gcry_cipher_ctl((h), GCRYCTL_CFB_SYNC, nil, 0)

##  Enable or disable CTS in future calls to gcry_encrypt(). CBC mode only.

template gcry_cipher_cts*(h, on: untyped): untyped =
  gcry_cipher_ctl((h), GCRYCTL_SET_CBC_CTS, nil, on)

##  #define gcry_cipher_set_sbox(h,oid) gcry_cipher_ctl( (h), GCRYCTL_SET_SBOX, \ (void *) oid, 0);
##  Indicate to the encrypt and decrypt functions that the next call
##    provides the final data.  Only used with some modes.
## #define gcry_cipher_final(a) gcry_cipher_ctl ((a), GCRYCTL_FINALIZE, NULL, 0)
##  Set counter for CTR mode.  (CTR,CTRLEN) must denote a buffer of
##    block size length, or (NULL,0) to set the CTR to the all-zero block.

proc gcry_cipher_setctr*(hd: gcry_cipher_hd_t; ctr: pointer; ctrlen: csize): gpg_error_t {.
    importc: "gcry_cipher_setctr", dynlib: foo.}
##  Retrieve the key length in bytes used with algorithm A.

proc gcry_cipher_get_algo_keylen*(algo: cint): csize {.
    importc: "gcry_cipher_get_algo_keylen", dynlib: foo.}
##  Retrieve the block length in bytes used with algorithm A.

proc gcry_cipher_get_algo_blklen*(algo: cint): csize {.
    importc: "gcry_cipher_get_algo_blklen", dynlib: foo.}
##  Return 0 if the algorithm A is available for use.

template gcry_cipher_test_algo*(a: untyped): untyped =
  gcry_cipher_algo_info((a), GCRYCTL_TEST_ALGO, nil, nil)

## ***********************************
##                                   *
##     Asymmetric Cipher Functions   *
##                                   *
## **********************************
##  The algorithms and their IDs we support.

type
  gcry_pk_algos* {.size: sizeof(cint).} = enum
    GCRY_PK_RSA = 1,            ##  RSA
    GCRY_PK_RSA_E = 2,          ##  (deprecated: use 1).
    GCRY_PK_RSA_S = 3,          ##  (deprecated: use 1).
    GCRY_PK_ELG_E = 16,         ##  (deprecated: use 20).
    GCRY_PK_DSA = 17,           ##  Digital Signature Algorithm.
    GCRY_PK_ECC = 18,           ##  Generic ECC.
    GCRY_PK_ELG = 20,           ##  Elgamal
    GCRY_PK_ECDSA = 301,        ##  (only for external use).
    GCRY_PK_ECDH = 302,         ##  (only for external use).
    GCRY_PK_EDDSA = 303


##  Flags describing usage capabilities of a PK algorithm.

const
  GCRY_PK_USAGE_SIGN* = 1
  GCRY_PK_USAGE_ENCR* = 2
  GCRY_PK_USAGE_CERT* = 4
  GCRY_PK_USAGE_AUTH* = 8
  GCRY_PK_USAGE_UNKN* = 128

##  Modes used with gcry_pubkey_get_sexp.

const
  GCRY_PK_GET_PUBKEY* = 1
  GCRY_PK_GET_SECKEY* = 2

##  Encrypt the DATA using the public key PKEY and store the result as
##    a newly created S-expression at RESULT.

proc gcry_pk_encrypt*(result: ptr gcry_sexp_t; data: gcry_sexp_t; pkey: gcry_sexp_t): gcry_error_t {.
    importc: "gcry_pk_encrypt", dynlib: foo.}
##  Decrypt the DATA using the private key SKEY and store the result as
##    a newly created S-expression at RESULT.

proc gcry_pk_decrypt*(result: ptr gcry_sexp_t; data: gcry_sexp_t; skey: gcry_sexp_t): gcry_error_t {.
    importc: "gcry_pk_decrypt", dynlib: foo.}
##  Sign the DATA using the private key SKEY and store the result as
##    a newly created S-expression at RESULT.

proc gcry_pk_sign*(result: ptr gcry_sexp_t; data: gcry_sexp_t; skey: gcry_sexp_t): gcry_error_t {.
    importc: "gcry_pk_sign", dynlib: foo.}
##  Check the signature SIGVAL on DATA using the public key PKEY.

proc gcry_pk_verify*(sigval: gcry_sexp_t; data: gcry_sexp_t; pkey: gcry_sexp_t): gcry_error_t {.
    importc: "gcry_pk_verify", dynlib: foo.}
##  Check that private KEY is sane.

proc gcry_pk_testkey*(key: gcry_sexp_t): gcry_error_t {.importc: "gcry_pk_testkey",
    dynlib: foo.}
##  Generate a new key pair according to the parameters given in
##    S_PARMS.  The new key pair is returned in as an S-expression in
##    R_KEY.

proc gcry_pk_genkey*(r_key: ptr gcry_sexp_t; s_parms: gcry_sexp_t): gcry_error_t {.
    importc: "gcry_pk_genkey", dynlib: foo.}
##  Catch all function for miscellaneous operations.

proc gcry_pk_ctl*(cmd: cint; buffer: pointer; buflen: csize): gcry_error_t {.
    importc: "gcry_pk_ctl", dynlib: foo.}
##  Retrieve information about the public key algorithm ALGO.

proc gcry_pk_algo_info*(algo: cint; what: cint; buffer: pointer; nbytes: ptr csize): gcry_error_t {.
    importc: "gcry_pk_algo_info", dynlib: foo.}
##  Map the public key algorithm whose ID is contained in ALGORITHM to
##    a string representation of the algorithm name.  For unknown
##    algorithm IDs this functions returns "?".

proc gcry_pk_algo_name*(algorithm: cint): cstring {.importc: "gcry_pk_algo_name",
    dynlib: foo.}
##  Map the algorithm NAME to a public key algorithm Id.  Return 0 if
##    the algorithm name is not known.

proc gcry_pk_map_name*(name: cstring): cint {.importc: "gcry_pk_map_name", dynlib: foo.}
##  Return what is commonly referred as the key length for the given
##    public or private KEY.

proc gcry_pk_get_nbits*(key: gcry_sexp_t): cuint {.importc: "gcry_pk_get_nbits",
    dynlib: foo.}
##  Return the so called KEYGRIP which is the SHA-1 hash of the public
##    key parameters expressed in a way depending on the algorithm.

proc gcry_pk_get_keygrip*(key: gcry_sexp_t; array: ptr cuchar): ptr cuchar {.
    importc: "gcry_pk_get_keygrip", dynlib: foo.}
##  Return the name of the curve matching KEY.

proc gcry_pk_get_curve*(key: gcry_sexp_t; `iterator`: cint; r_nbits: ptr cuint): cstring {.
    importc: "gcry_pk_get_curve", dynlib: foo.}
##  Return an S-expression with the parameters of the named ECC curve
##    NAME.  ALGO must be set to an ECC algorithm.

proc gcry_pk_get_param*(algo: cint; name: cstring): gcry_sexp_t {.
    importc: "gcry_pk_get_param", dynlib: foo.}
##  Return 0 if the public key algorithm A is available for use.

template gcry_pk_test_algo*(a: untyped): untyped =
  gcry_pk_algo_info((a), GCRYCTL_TEST_ALGO, nil, nil)

##  Return an S-expression representing the context CTX.

proc gcry_pubkey_get_sexp*(r_sexp: ptr gcry_sexp_t; mode: cint; ctx: gcry_ctx_t): gcry_error_t {.
    importc: "gcry_pubkey_get_sexp", dynlib: foo.}
## ***********************************
##                                   *
##    Cryptograhic Hash Functions    *
##                                   *
## **********************************
##  Algorithm IDs for the hash functions we know about. Not all of them
##    are implemented.

type
  gcry_md_algos* {.size: sizeof(cint).} = enum
    GCRY_MD_NONE = 0, GCRY_MD_MD5 = 1, GCRY_MD_SHA1 = 2, GCRY_MD_RMD160 = 3,
    GCRY_MD_MD2 = 5, GCRY_MD_TIGER = 6, ##  TIGER/192 as used by gpg <= 1.3.2.
    GCRY_MD_HAVAL = 7,          ##  HAVAL, 5 pass, 160 bit.
    GCRY_MD_SHA256 = 8, GCRY_MD_SHA384 = 9, GCRY_MD_SHA512 = 10, GCRY_MD_SHA224 = 11,
    GCRY_MD_MD4 = 301, GCRY_MD_CRC32 = 302, GCRY_MD_CRC32_RFC1510 = 303,
    GCRY_MD_CRC24_RFC2440 = 304, GCRY_MD_WHIRLPOOL = 305, GCRY_MD_TIGER1 = 306, ##  TIGER fixed.
    GCRY_MD_TIGER2 = 307,       ##  TIGER2 variant.
    GCRY_MD_GOSTR3411_94 = 308, ##  GOST R 34.11-94.
    GCRY_MD_STRIBOG256 = 309,   ##  GOST R 34.11-2012, 256 bit.
    GCRY_MD_STRIBOG512 = 310,   ##  GOST R 34.11-2012, 512 bit.
    GCRY_MD_GOSTR3411_CP = 311, ##  GOST R 34.11-94 with CryptoPro-A S-Box.
    GCRY_MD_SHA3_224 = 312, GCRY_MD_SHA3_256 = 313, GCRY_MD_SHA3_384 = 314,
    GCRY_MD_SHA3_512 = 315, GCRY_MD_SHAKE128 = 316, GCRY_MD_SHAKE256 = 317,
    GCRY_MD_BLAKE2B_512 = 318, GCRY_MD_BLAKE2B_384 = 319, GCRY_MD_BLAKE2B_256 = 320,
    GCRY_MD_BLAKE2B_160 = 321, GCRY_MD_BLAKE2S_256 = 322, GCRY_MD_BLAKE2S_224 = 323,
    GCRY_MD_BLAKE2S_160 = 324, GCRY_MD_BLAKE2S_128 = 325


##  Flags used with the open function.

type
  gcry_md_flags* {.size: sizeof(cint).} = enum
    GCRY_MD_FLAG_SECURE = 1,    ##  Allocate all buffers in "secure" memory.
    GCRY_MD_FLAG_HMAC = 2,      ##  Make an HMAC out of this algorithm.
    GCRY_MD_FLAG_BUGEMU1 = 0x00000100


##  (Forward declaration.)

type
  gcry_md_context* {.bycopy.} = object


##  This object is used to hold a handle to a message digest object.
##    This structure is private - only to be used by the public gcry_md_*
##    macros.
##  FIXME
##  typedef struct gcry_md_handle
##  {
##    /* Actual context.  */
##    struct gcry_md_context *ctx;
##
##    /* Buffer management.  */
##    int  bufpos;
##    int  bufsize;
##    unsigned char buf[1];
##  } *gcry_md_hd_t;
##  Compatibility types, do not use them.
##  #ifndef GCRYPT_NO_DEPRECATED
##  typedef struct gcry_md_handle *GCRY_MD_HD _GCRY_GCC_ATTR_DEPRECATED;
##  typedef struct gcry_md_handle *GcryMDHd _GCRY_GCC_ATTR_DEPRECATED;
##  #endif
##  Create a message digest object for algorithm ALGO.  FLAGS may be
##    given as an bitwise OR of the gcry_md_flags values.  ALGO may be
##    given as 0 if the algorithms to be used are later set using
##    gcry_md_enable.

proc gcry_md_open*(h: ptr gcry_md_hd_t; algo: cint; flags: cuint): gcry_error_t {.
    importc: "gcry_md_open", dynlib: foo.}
##  Release the message digest object HD.

proc gcry_md_close*(hd: gcry_md_hd_t) {.importc: "gcry_md_close", dynlib: foo.}
##  Add the message digest algorithm ALGO to the digest object HD.

proc gcry_md_enable*(hd: gcry_md_hd_t; algo: cint): gcry_error_t {.
    importc: "gcry_md_enable", dynlib: foo.}
##  Create a new digest object as an exact copy of the object HD.

proc gcry_md_copy*(bhd: ptr gcry_md_hd_t; ahd: gcry_md_hd_t): gcry_error_t {.
    importc: "gcry_md_copy", dynlib: foo.}
##  Reset the digest object HD to its initial state.

proc gcry_md_reset*(hd: gcry_md_hd_t) {.importc: "gcry_md_reset", dynlib: foo.}
##  Perform various operations on the digest object HD.

proc gcry_md_ctl*(hd: gcry_md_hd_t; cmd: cint; buffer: pointer; buflen: csize): gcry_error_t {.
    importc: "gcry_md_ctl", dynlib: foo.}
##  Pass LENGTH bytes of data in BUFFER to the digest object HD so that
##    it can update the digest values.  This is the actual hash
##    function.

proc gcry_md_write*(hd: gcry_md_hd_t; buffer: pointer; length: csize) {.
    importc: "gcry_md_write", dynlib: foo.}
##  Read out the final digest from HD return the digest value for
##    algorithm ALGO.

proc gcry_md_read*(hd: gcry_md_hd_t; algo: cint): ptr cuchar {.importc: "gcry_md_read",
    dynlib: foo.}
##  Read more output from algorithm ALGO to BUFFER of size LENGTH from
##  digest object HD. Algorithm needs to be 'expendable-output function'.

proc gcry_md_extract*(hd: gcry_md_hd_t; algo: cint; buffer: pointer; length: csize): gpg_error_t {.
    importc: "gcry_md_extract", dynlib: foo.}
##  Convenience function to calculate the hash from the data in BUFFER
##    of size LENGTH using the algorithm ALGO avoiding the creation of a
##    hash object.  The hash is returned in the caller provided buffer
##    DIGEST which must be large enough to hold the digest of the given
##    algorithm.

proc gcry_md_hash_buffer*(algo: cint; digest: pointer; buffer: pointer; length: csize) {.
    importc: "gcry_md_hash_buffer", dynlib: foo.}
##  Convenience function to hash multiple buffers.

proc gcry_md_hash_buffers*(algo: cint; flags: cuint; digest: pointer;
                          iov: ptr gcry_buffer_t; iovcnt: cint): gpg_error_t {.
    importc: "gcry_md_hash_buffers", dynlib: foo.}
##  Retrieve the algorithm used with HD.  This does not work reliable
##    if more than one algorithm is enabled in HD.

proc gcry_md_get_algo*(hd: gcry_md_hd_t): cint {.importc: "gcry_md_get_algo",
    dynlib: foo.}
##  Retrieve the length in bytes of the digest yielded by algorithm
##    ALGO.

proc gcry_md_get_algo_dlen*(algo: cint): cuint {.importc: "gcry_md_get_algo_dlen",
    dynlib: foo.}
##  Return true if the the algorithm ALGO is enabled in the digest
##    object A.

proc gcry_md_is_enabled*(a: gcry_md_hd_t; algo: cint): cint {.
    importc: "gcry_md_is_enabled", dynlib: foo.}
##  Return true if the digest object A is allocated in "secure" memory.

proc gcry_md_is_secure*(a: gcry_md_hd_t): cint {.importc: "gcry_md_is_secure",
    dynlib: foo.}
##  Deprecated: Use gcry_md_is_enabled or gcry_md_is_secure.
##  gcry_error_t gcry_md_info (gcry_md_hd_t h, int what, void *buffer, size_t *nbytes) _GCRY_ATTR_INTERNAL;
##  Retrieve various information about the algorithm ALGO.

proc gcry_md_algo_info*(algo: cint; what: cint; buffer: pointer; nbytes: ptr csize): gcry_error_t {.
    importc: "gcry_md_algo_info", dynlib: foo.}
##  Map the digest algorithm id ALGO to a string representation of the
##    algorithm name.  For unknown algorithms this function returns
##    "?".

proc gcry_md_algo_name*(algo: cint): cstring {.importc: "gcry_md_algo_name",
    dynlib: foo.}
##  Map the algorithm NAME to a digest algorithm Id.  Return 0 if
##    the algorithm name is not known.

proc gcry_md_map_name*(name: cstring): cint {.importc: "gcry_md_map_name", dynlib: foo.}
##  For use with the HMAC feature, the set MAC key to the KEY of
##    KEYLEN bytes.

proc gcry_md_setkey*(hd: gcry_md_hd_t; key: pointer; keylen: csize): gcry_error_t {.
    importc: "gcry_md_setkey", dynlib: foo.}
##  Start or stop debugging for digest handle HD; i.e. create a file
##    named dbgmd-<n>.<suffix> while hashing.  If SUFFIX is NULL,
##    debugging stops and the file will be closed.

proc gcry_md_debug*(hd: gcry_md_hd_t; suffix: cstring) {.importc: "gcry_md_debug",
    dynlib: foo.}
##  Update the hash(s) of H with the character C.  This is a buffered
##    version of the gcry_md_write function.

template gcry_md_putc*(h, c: untyped): void =
  while true:
    var h__: gcry_md_hd_t
    if (h__).bufpos == (h__).bufsize:
      gcry_md_write((h__), nil, 0)
    (h__).buf[inc((h__).bufpos)] = (c) and 0x000000FF
    if not 0:
      break

##  Finalize the digest calculation.  This is not really needed because
##    gcry_md_read() does this implicitly.

template gcry_md_final*(a: untyped): untyped =
  gcry_md_ctl((a), GCRYCTL_FINALIZE, nil, 0)

##  Return 0 if the algorithm A is available for use.

template gcry_md_test_algo*(a: untyped): untyped =
  gcry_md_algo_info((a), GCRYCTL_TEST_ALGO, nil, nil)

##  Return an DER encoded ASN.1 OID for the algorithm A in buffer B. N
##    must point to size_t variable with the available size of buffer B.
##    After return it will receive the actual size of the returned
##    OID.

template gcry_md_get_asnoid*(a, b, n: untyped): untyped =
  gcry_md_algo_info((a), GCRYCTL_GET_ASNOID, (b), (n))

## *********************************************
##                                             *
##    Message Authentication Code Functions    *
##                                             *
## ********************************************
##  The data object used to hold a handle to an encryption object.

type
  gcry_mac_handle* {.bycopy.} = object

  gcry_mac_hd_t* = ptr gcry_mac_handle

##  Algorithm IDs for the hash functions we know about. Not all of them
##    are implemented.

type
  gcry_mac_algos* {.size: sizeof(cint).} = enum
    GCRY_MAC_NONE = 0, GCRY_MAC_HMAC_SHA256 = 101, GCRY_MAC_HMAC_SHA224 = 102,
    GCRY_MAC_HMAC_SHA512 = 103, GCRY_MAC_HMAC_SHA384 = 104, GCRY_MAC_HMAC_SHA1 = 105,
    GCRY_MAC_HMAC_MD5 = 106, GCRY_MAC_HMAC_MD4 = 107, GCRY_MAC_HMAC_RMD160 = 108, GCRY_MAC_HMAC_TIGER1 = 109, ##  The fixed TIGER variant
    GCRY_MAC_HMAC_WHIRLPOOL = 110, GCRY_MAC_HMAC_GOSTR3411_94 = 111,
    GCRY_MAC_HMAC_STRIBOG256 = 112, GCRY_MAC_HMAC_STRIBOG512 = 113,
    GCRY_MAC_HMAC_MD2 = 114, GCRY_MAC_HMAC_SHA3_224 = 115,
    GCRY_MAC_HMAC_SHA3_256 = 116, GCRY_MAC_HMAC_SHA3_384 = 117,
    GCRY_MAC_HMAC_SHA3_512 = 118, GCRY_MAC_CMAC_AES = 201, GCRY_MAC_CMAC_3DES = 202,
    GCRY_MAC_CMAC_CAMELLIA = 203, GCRY_MAC_CMAC_CAST5 = 204,
    GCRY_MAC_CMAC_BLOWFISH = 205, GCRY_MAC_CMAC_TWOFISH = 206,
    GCRY_MAC_CMAC_SERPENT = 207, GCRY_MAC_CMAC_SEED = 208,
    GCRY_MAC_CMAC_RFC2268 = 209, GCRY_MAC_CMAC_IDEA = 210,
    GCRY_MAC_CMAC_GOST28147 = 211, GCRY_MAC_GMAC_AES = 401,
    GCRY_MAC_GMAC_CAMELLIA = 402, GCRY_MAC_GMAC_TWOFISH = 403,
    GCRY_MAC_GMAC_SERPENT = 404, GCRY_MAC_GMAC_SEED = 405, GCRY_MAC_POLY1305 = 501,
    GCRY_MAC_POLY1305_AES = 502, GCRY_MAC_POLY1305_CAMELLIA = 503,
    GCRY_MAC_POLY1305_TWOFISH = 504, GCRY_MAC_POLY1305_SERPENT = 505,
    GCRY_MAC_POLY1305_SEED = 506


##  Flags used with the open function.

type
  gcry_mac_flags* {.size: sizeof(cint).} = enum
    GCRY_MAC_FLAG_SECURE = 1


##  Create a MAC handle for algorithm ALGO.  FLAGS may be given as an bitwise OR
##    of the gcry_mac_flags values.  CTX maybe NULL or gcry_ctx_t object to be
##    associated with HANDLE.

proc gcry_mac_open*(handle: ptr gcry_mac_hd_t; algo: cint; flags: cuint; ctx: gcry_ctx_t): gcry_error_t {.
    importc: "gcry_mac_open", dynlib: foo.}
##  Close the MAC handle H and release all resource.

proc gcry_mac_close*(h: gcry_mac_hd_t) {.importc: "gcry_mac_close", dynlib: foo.}
##  Perform various operations on the MAC object H.

proc gcry_mac_ctl*(h: gcry_mac_hd_t; cmd: cint; buffer: pointer; buflen: csize): gcry_error_t {.
    importc: "gcry_mac_ctl", dynlib: foo.}
##  Retrieve various information about the MAC algorithm ALGO.

proc gcry_mac_algo_info*(algo: cint; what: cint; buffer: pointer; nbytes: ptr csize): gcry_error_t {.
    importc: "gcry_mac_algo_info", dynlib: foo.}
##  Set KEY of length KEYLEN bytes for the MAC handle HD.

proc gcry_mac_setkey*(hd: gcry_mac_hd_t; key: pointer; keylen: csize): gcry_error_t {.
    importc: "gcry_mac_setkey", dynlib: foo.}
##  Set initialization vector IV of length IVLEN for the MAC handle HD.

proc gcry_mac_setiv*(hd: gcry_mac_hd_t; iv: pointer; ivlen: csize): gcry_error_t {.
    importc: "gcry_mac_setiv", dynlib: foo.}
##  Pass LENGTH bytes of data in BUFFER to the MAC object HD so that
##    it can update the MAC values.

proc gcry_mac_write*(hd: gcry_mac_hd_t; buffer: pointer; length: csize): gcry_error_t {.
    importc: "gcry_mac_write", dynlib: foo.}
##  Read out the final authentication code from the MAC object HD to BUFFER.

proc gcry_mac_read*(hd: gcry_mac_hd_t; buffer: pointer; buflen: ptr csize): gcry_error_t {.
    importc: "gcry_mac_read", dynlib: foo.}
##  Verify the final authentication code from the MAC object HD with BUFFER.

proc gcry_mac_verify*(hd: gcry_mac_hd_t; buffer: pointer; buflen: csize): gcry_error_t {.
    importc: "gcry_mac_verify", dynlib: foo.}
##  Retrieve the algorithm used with MAC.

proc gcry_mac_get_algo*(hd: gcry_mac_hd_t): cint {.importc: "gcry_mac_get_algo",
    dynlib: foo.}
##  Retrieve the length in bytes of the MAC yielded by algorithm ALGO.

proc gcry_mac_get_algo_maclen*(algo: cint): cuint {.
    importc: "gcry_mac_get_algo_maclen", dynlib: foo.}
##  Retrieve the default key length in bytes used with algorithm A.

proc gcry_mac_get_algo_keylen*(algo: cint): cuint {.
    importc: "gcry_mac_get_algo_keylen", dynlib: foo.}
##  Map the MAC algorithm whose ID is contained in ALGORITHM to a
##    string representation of the algorithm name.  For unknown algorithm
##    IDs this function returns "?".

proc gcry_mac_algo_name*(algorithm: cint): cstring {.importc: "gcry_mac_algo_name",
    dynlib: foo.}
##  Map the algorithm name NAME to an MAC algorithm ID.  Return 0 if
##    the algorithm name is not known.

proc gcry_mac_map_name*(name: cstring): cint {.importc: "gcry_mac_map_name",
    dynlib: foo.}
##  Reset the handle to the state after open/setkey.

template gcry_mac_reset*(h: untyped): untyped =
  gcry_mac_ctl((h), GCRYCTL_RESET, nil, 0)

##  Return 0 if the algorithm A is available for use.

template gcry_mac_test_algo*(a: untyped): untyped =
  gcry_mac_algo_info((a), GCRYCTL_TEST_ALGO, nil, nil)

## *****************************
##                             *
##   Key Derivation Functions  *
##                             *
## ****************************
##  Algorithm IDs for the KDFs.

type
  gcry_kdf_algos* {.size: sizeof(cint).} = enum
    GCRY_KDF_NONE = 0, GCRY_KDF_SIMPLE_S2K = 16, GCRY_KDF_SALTED_S2K = 17,
    GCRY_KDF_ITERSALTED_S2K = 19, GCRY_KDF_PBKDF1 = 33, GCRY_KDF_PBKDF2 = 34,
    GCRY_KDF_SCRYPT = 48


##  Derive a key from a passphrase.

proc gcry_kdf_derive*(passphrase: pointer; passphraselen: csize; algo: cint;
                     subalgo: cint; salt: pointer; saltlen: csize; iterations: culong;
                     keysize: csize; keybuffer: pointer): gpg_error_t {.
    importc: "gcry_kdf_derive", dynlib: foo.}
## ***********************************
##                                   *
##    Random Generating Functions    *
##                                   *
## **********************************
##  The type of the random number generator.

type
  gcry_rng_types* {.size: sizeof(cint).} = enum
    GCRY_RNG_TYPE_STANDARD = 1, ##  The default CSPRNG generator.
    GCRY_RNG_TYPE_FIPS = 2,     ##  The FIPS X9.31 AES generator.
    GCRY_RNG_TYPE_SYSTEM = 3


##  The possible values for the random quality.  The rule of thumb is
##    to use STRONG for session keys and VERY_STRONG for key material.
##    WEAK is usually an alias for STRONG and should not be used anymore
##    (except with gcry_mpi_randomize); use gcry_create_nonce instead.

type
  gcry_random_level_t* {.size: sizeof(cint).} = enum
    GCRY_WEAK_RANDOM = 0, GCRY_STRONG_RANDOM = 1, GCRY_VERY_STRONG_RANDOM = 2


##  Fill BUFFER with LENGTH bytes of random, using random numbers of
##    quality LEVEL.

proc gcry_randomize*(buffer: pointer; length: csize; level: gcry_random_level) {.
    importc: "gcry_randomize", dynlib: foo.}
##  Add the external random from BUFFER with LENGTH bytes into the
##    pool. QUALITY should either be -1 for unknown or in the range of 0
##    to 100

proc gcry_random_add_bytes*(buffer: pointer; length: csize; quality: cint): gcry_error_t {.
    importc: "gcry_random_add_bytes", dynlib: foo.}
##  If random numbers are used in an application, this macro should be
##    called from time to time so that new stuff gets added to the
##    internal pool of the RNG.

template gcry_fast_random_poll*(): untyped =
  gcry_control(GCRYCTL_FAST_POLL, nil)

##  Return NBYTES of allocated random using a random numbers of quality
##    LEVEL.

proc gcry_random_bytes*(nbytes: csize; level: gcry_random_level): pointer {.
    importc: "gcry_random_bytes", dynlib: foo.}
##  Return NBYTES of allocated random using a random numbers of quality
##    LEVEL.  The random numbers are created returned in "secure"
##    memory.

proc gcry_random_bytes_secure*(nbytes: csize; level: gcry_random_level): pointer {.
    importc: "gcry_random_bytes_secure", dynlib: foo.}
##  Set the big integer W to a random value of NBITS using a random
##    generator with quality LEVEL.  Note that by using a level of
##    GCRY_WEAK_RANDOM gcry_create_nonce is used internally.

proc gcry_mpi_randomize*(w: gcry_mpi_t; nbits: cuint; level: gcry_random_level) {.
    importc: "gcry_mpi_randomize", dynlib: foo.}
##  Create an unpredicable nonce of LENGTH bytes in BUFFER.

proc gcry_create_nonce*(buffer: pointer; length: csize) {.
    importc: "gcry_create_nonce", dynlib: foo.}
## *****************************
##
##     Prime Number Functions
##
## *****************************
##  Mode values passed to a gcry_prime_check_func_t.

const
  GCRY_PRIME_CHECK_AT_FINISH* = 0
  GCRY_PRIME_CHECK_AT_GOT_PRIME* = 1
  GCRY_PRIME_CHECK_AT_MAYBE_PRIME* = 2

##  The function should return 1 if the operation shall continue, 0 to
##    reject the prime candidate.

type
  gcry_prime_check_func_t* = proc (arg: pointer; mode: cint; candidate: gcry_mpi_t): cint

##  Flags for gcry_prime_generate():
##  Allocate prime numbers and factors in secure memory.

const
  GCRY_PRIME_FLAG_SECRET* = (1 shl 0)

##  Make sure that at least one prime factor is of size
##    `FACTOR_BITS'.

const
  GCRY_PRIME_FLAG_SPECIAL_FACTOR* = (1 shl 1)

##  Generate a new prime number of PRIME_BITS bits and store it in
##    PRIME.  If FACTOR_BITS is non-zero, one of the prime factors of
##    (prime - 1) / 2 must be FACTOR_BITS bits long.  If FACTORS is
##    non-zero, allocate a new, NULL-terminated array holding the prime
##    factors and store it in FACTORS.  FLAGS might be used to influence
##    the prime number generation process.

proc gcry_prime_generate*(prime: ptr gcry_mpi_t; prime_bits: cuint;
                         factor_bits: cuint; factors: ptr ptr gcry_mpi_t;
                         cb_func: gcry_prime_check_func_t; cb_arg: pointer;
                         random_level: gcry_random_level_t; flags: cuint): gcry_error_t {.
    importc: "gcry_prime_generate", dynlib: foo.}
##  Find a generator for PRIME where the factorization of (prime-1) is
##    in the NULL terminated array FACTORS. Return the generator as a
##    newly allocated MPI in R_G.  If START_G is not NULL, use this as
##    the start for the search.

proc gcry_prime_group_generator*(r_g: ptr gcry_mpi_t; prime: gcry_mpi_t;
                                factors: ptr gcry_mpi_t; start_g: gcry_mpi_t): gcry_error_t {.
    importc: "gcry_prime_group_generator", dynlib: foo.}
##  Convenience function to release the FACTORS array.

proc gcry_prime_release_factors*(factors: ptr gcry_mpi_t) {.
    importc: "gcry_prime_release_factors", dynlib: foo.}
##  Check whether the number X is prime.

proc gcry_prime_check*(x: gcry_mpi_t; flags: cuint): gcry_error_t {.
    importc: "gcry_prime_check", dynlib: foo.}
## ***********************************
##                                   *
##      Miscellaneous Stuff          *
##                                   *
## **********************************
##  Release the context object CTX.

proc gcry_ctx_release*(ctx: gcry_ctx_t) {.importc: "gcry_ctx_release", dynlib: foo.}
##  Log data using Libgcrypt's own log interface.

proc gcry_log_debug*(fmt: cstring) {.varargs, importc: "gcry_log_debug", dynlib: foo.}
proc gcry_log_debughex*(text: cstring; buffer: pointer; length: csize) {.
    importc: "gcry_log_debughex", dynlib: foo.}
proc gcry_log_debugmpi*(text: cstring; mpi: gcry_mpi_t) {.
    importc: "gcry_log_debugmpi", dynlib: foo.}
proc gcry_log_debugpnt*(text: cstring; point: gcry_mpi_point_t; ctx: gcry_ctx_t) {.
    importc: "gcry_log_debugpnt", dynlib: foo.}
proc gcry_log_debugsxp*(text: cstring; sexp: gcry_sexp_t) {.
    importc: "gcry_log_debugsxp", dynlib: foo.}
proc gcry_get_config*(mode: cint; what: cstring): cstring {.
    importc: "gcry_get_config", dynlib: foo.}
##  Log levels used by the internal logging facility.

type
  gcry_log_levels* {.size: sizeof(cint).} = enum
    GCRY_LOG_CONT = 0,          ##  (Continue the last log line.)
    GCRY_LOG_INFO = 10, GCRY_LOG_WARN = 20, GCRY_LOG_ERROR = 30, GCRY_LOG_FATAL = 40,
    GCRY_LOG_BUG = 50, GCRY_LOG_DEBUG = 100


##  Type for progress handlers.

type
  gcry_handler_progress_t* = proc (a1: pointer; a2: cstring; a3: cint; a4: cint; a5: cint)

##  Type for memory allocation handlers.

type
  gcry_handler_alloc_t* = proc (n: csize): pointer

##  Type for secure memory check handlers.

type
  gcry_handler_secure_check_t* = proc (a1: pointer): cint

##  Type for memory reallocation handlers.

type
  gcry_handler_realloc_t* = proc (p: pointer; n: csize): pointer

##  Type for memory free handlers.

type
  gcry_handler_free_t* = proc (a1: pointer)

##  Type for out-of-memory handlers.

type
  gcry_handler_no_mem_t* = proc (a1: pointer; a2: csize; a3: cuint): cint

##  Type for fatal error handlers.

type
  gcry_handler_error_t* = proc (a1: pointer; a2: cint; a3: cstring)

##  Type for logging handlers.

type
  gcry_handler_log_t* = proc (a1: pointer; a2: cint; a3: cstring; a4: va_list)

##  Certain operations can provide progress information.  This function
##    is used to register a handler for retrieving these information.

proc gcry_set_progress_handler*(cb: gcry_handler_progress_t; cb_data: pointer) {.
    importc: "gcry_set_progress_handler", dynlib: foo.}
##  Register a custom memory allocation functions.

proc gcry_set_allocation_handler*(func_alloc: gcry_handler_alloc_t;
                                 func_alloc_secure: gcry_handler_alloc_t;
    func_secure_check: gcry_handler_secure_check_t;
                                 func_realloc: gcry_handler_realloc_t;
                                 func_free: gcry_handler_free_t) {.
    importc: "gcry_set_allocation_handler", dynlib: foo.}
##  Register a function used instead of the internal out of memory
##    handler.

proc gcry_set_outofcore_handler*(h: gcry_handler_no_mem_t; opaque: pointer) {.
    importc: "gcry_set_outofcore_handler", dynlib: foo.}
##  Register a function used instead of the internal fatal error
##    handler.

proc gcry_set_fatalerror_handler*(fnc: gcry_handler_error_t; opaque: pointer) {.
    importc: "gcry_set_fatalerror_handler", dynlib: foo.}
##  Register a function used instead of the internal logging
##    facility.

proc gcry_set_log_handler*(f: gcry_handler_log_t; opaque: pointer) {.
    importc: "gcry_set_log_handler", dynlib: foo.}
##  Reserved for future use.

proc gcry_set_gettext_handler*(f: proc (a1: cstring): cstring) {.
    importc: "gcry_set_gettext_handler", dynlib: foo.}
##  Libgcrypt uses its own memory allocation.  It is important to use
##    gcry_free () to release memory allocated by libgcrypt.

proc gcry_malloc*(n: csize): pointer {.importc: "gcry_malloc", dynlib: foo.}
proc gcry_calloc*(n: csize; m: csize): pointer {.importc: "gcry_calloc", dynlib: foo.}
proc gcry_malloc_secure*(n: csize): pointer {.importc: "gcry_malloc_secure",
    dynlib: foo.}
proc gcry_calloc_secure*(n: csize; m: csize): pointer {.importc: "gcry_calloc_secure",
    dynlib: foo.}
proc gcry_realloc*(a: pointer; n: csize): pointer {.importc: "gcry_realloc", dynlib: foo.}
proc gcry_strdup*(string: cstring): cstring {.importc: "gcry_strdup", dynlib: foo.}
proc gcry_xmalloc*(n: csize): pointer {.importc: "gcry_xmalloc", dynlib: foo.}
proc gcry_xcalloc*(n: csize; m: csize): pointer {.importc: "gcry_xcalloc", dynlib: foo.}
proc gcry_xmalloc_secure*(n: csize): pointer {.importc: "gcry_xmalloc_secure",
    dynlib: foo.}
proc gcry_xcalloc_secure*(n: csize; m: csize): pointer {.
    importc: "gcry_xcalloc_secure", dynlib: foo.}
proc gcry_xrealloc*(a: pointer; n: csize): pointer {.importc: "gcry_xrealloc",
    dynlib: foo.}
proc gcry_xstrdup*(a: cstring): cstring {.importc: "gcry_xstrdup", dynlib: foo.}
proc gcry_free*(a: pointer) {.importc: "gcry_free", dynlib: foo.}
##  Return true if A is allocated in "secure" memory.

proc gcry_is_secure*(a: pointer): cint {.importc: "gcry_is_secure", dynlib: foo.}
##  Return true if Libgcrypt is in FIPS mode.

template gcry_fips_mode_active*(): untyped =
  not not gcry_control(GCRYCTL_FIPS_MODE_P, 0)
