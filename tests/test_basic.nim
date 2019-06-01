##  GNU Cryptographic Library Interface - Nim wrapper - unit tests
##  Copyright (C) 2019 Federico Ceratto <federico.ceratto@gmail.com>

import unittest

import strutils

import gcrypt

template check_rc(rc: gcry_error_t): untyped =
  ## Expect return code to be 0, raise an exception otherwise
  if rc != 0.cint:
    raise newException(Exception, $gcry_strerror(rc))

suite "basic":
  test "version":
    echo "version " & GCRYPT_VERSION

  test "errno":
    let e = gcry_error_from_errno(3)
    check $gcry_strerror(e) == "No such process"

  test "random":
    var a = ""
    check gcry_is_secure(addr a) == 0

    let r = gcry_random_bytes_secure(16, GCRY_WEAK_RANDOM)
    check gcry_is_secure(r) == 1
    gcry_free(r)

  test "pubkey":
    var keypair: gcry_sexp_t = nil
    let param = gcry_new_sexp("(genkey\n (rsa\n  (nbits 4:1024)\n ))")

    # check parsing / sprint
    check gcry_sexp_sprint(param, GCRYSEXP_FMT_CANON) == "(6:genkey(3:rsa(5:nbits4:1024)))"

    # generate and check key
    check_rc gcry_pk_genkey(addr keypair, param)
    check_rc gcry_pk_testkey(keypair)

    let plain = "foo"
    let plain_s = gcry_new_data_sexp(plain)
    check plain_s != nil
    check gcry_sexp_sprint(plain_s, GCRYSEXP_FMT_CANON) == "(4:data(5:value3:foo))"

    # sign
    var signature: gcry_sexp_t = nil
    check_rc gcry_pk_sign(addr signature, plain_s, keypair)

    # verify
    check_rc gcry_pk_verify(signature, plain_s, keypair)

    # encrypt
    var encrypted: gcry_sexp_t = nil
    check_rc gcry_pk_encrypt(addr encrypted, plain_s, keypair)

    var decrypted: gcry_sexp_t = nil
    check_rc gcry_pk_decrypt(addr decrypted, encrypted, keypair)
    check strip($decrypted) == plain  # newline in decrypted

    gcry_sexp_release plain_s
    gcry_sexp_release encrypted
    gcry_sexp_release decrypted
    gcry_sexp_release keypair
    gcry_sexp_release param

  test "hash":
    const input = "fooo"
    const expected = "A9823A788388027D9A7A8C19F49E786B"
    let digest_length = gcry_md_get_algo_dlen(GCRY_MD_MD5)
    var digest = gcry_malloc(digest_length.csize)
    gcry_md_hash_buffer(GCRY_MD_MD5, digest, input.cstring, input.len.csize)
    let d = fromCString(digest, digest_length.int).toHex()
    check d == expected

