;; -*- mode: Scheme; tab-width: 4 -*-

;; Copyright 2020 Andrew Gierth
;;
;; SPDX-License-Identifier: MIT
;; Licensed under the MIT license (see LICENSE file)
;; Relicensing is allowed as set forth in the RELICENSE.txt
;; file, if (and only if) included in the same distribution.

(define-module (hex)
  #:use-module ((rnrs bytevectors)
				#:select (make-bytevector
						  bytevector-length
						  string->utf8
						  utf8->string
						  (bytevector-u16-native-set! . bv-u16-set!)
						  (bytevector-u16-native-ref . bv-u16-ref)
						  (bytevector-u8-set! . bv-u8-set!)
						  (bytevector-u8-ref . bv-u8-ref)))
  #:use-module (srfi srfi-11)  ;; let-values
  #:use-module (srfi srfi-2)   ;; and-let*
  #:use-module (srfi srfi-60)  ;; bitwise-merge
  #:export (bin->hex
            hex->bin))

;; we use guile's logand and ash in the hot paths in place of
;; srfi-60's bitwise-and and arithmetic-shift, because the latter
;; impose a significant performance penalty.

;; We need to grab some low-order bits which are known to be all 0's
;; for the digit '0', and are not all 0's for the digits 'F' or 'f'.
;; So just the lowest bit isn't enough, but anything from 2 to 4 bits
;; is fine. Pick 2 out of sheer arbitrariness. This form is used on
;; a hot path.

(define-syntax lowbits
  (syntax-rules ()
    ((_ n) (logand n 3))))

;; This should be the fastest available way to multiply a non-negative
;; integer by 2; it is used a lot on all the hot paths.

(define-syntax 2*
  (syntax-rules ()
    ((_ n) (ash n 1))))

;; Divide an even non-negative integer by 2; this should be fast, but
;; it's not called in inner loops.

(define-syntax div2
  (syntax-rules ()
    ((_ n) (ash n -1))))

;; Simple numeric iteration for start <= var < limit

(define-syntax numeric-for
  (syntax-rules ()
    ((_ (var start limit) body ...)
     (let ([nlimit limit])
       (do ([var start (1+ var)])
	   ((>= var nlimit))
	 body ...)))))

;; Data tables

(define hex-chars-lc
  (string->utf8 "\
000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f\
404142434445464748494a4b4c4d4e4f\
505152535455565758595a5b5c5d5e5f\
606162636465666768696a6b6c6d6e6f\
707172737475767778797a7b7c7d7e7f\
808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f\
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

(define hex-chars-uc
  (string->utf8 "\
000102030405060708090A0B0C0D0E0F\
101112131415161718191A1B1C1D1E1F\
202122232425262728292A2B2C2D2E2F\
303132333435363738393A3B3C3D3E3F\
404142434445464748494A4B4C4D4E4F\
505152535455565758595A5B5C5D5E5F\
606162636465666768696A6B6C6D6E6F\
707172737475767778797A7B7C7D7E7F\
808182838485868788898A8B8C8D8E8F\
909192939495969798999A9B9C9D9E9F\
A0A1A2A3A4A5A6A7A8A9AAABACADAEAF\
B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF\
C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF\
D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF\
E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF\
F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"))

;; For hex->bin, the valid input range for one byte is '00' to 'ff',
;; i.e. #x3030 to #x6666. So we need an array of 13879 (#x3637)
;; entries to cover it all.
;;
;; To minimize space, we want to store only one byte per entry, but
;; that presents the problem of how to represent the many 'invalid'
;; entries. So we cheat: rather than store the exact value, we offset
;; the value by subtracting a few low-order bits from the input index;
;; we choose bits that will always be no greater than the actual value
;; so that underflow is impossible, and which will be non-zero for the
;; value #xff; this means that #xff will never legitimately appear in
;; a valid table entry, so we can use it as an 'invalid' flag.

(define chars-hex
  (letrec ([vec			(make-bytevector #x3637 #xff)]
		   [add-entry	(lambda (i n)
						  (bv-u8-set! vec
									  (- n #x3030)
									  (- i (lowbits n))))])
    (numeric-for (i 0 256)
      (let* ([lc	(bv-u16-ref hex-chars-lc (2* i))]
			 [uc	(bv-u16-ref hex-chars-uc (2* i))]
			 [xc1	(bitwise-merge #xff00 lc uc)]
			 [xc2	(bitwise-merge #x00ff lc uc)])
		(add-entry i lc)
		(add-entry i uc)
		(add-entry i xc1)
		(add-entry i xc2)))
    vec))

;; Code

;; add an optional "uppercase" arg for bin->hex?

(define (bin->hex bin)
  (let* ([bin-len	(bytevector-length bin)]
		 [hex		(make-bytevector (2* bin-len))])
    (numeric-for (i 0 bin-len)
      (bv-u16-set! hex
				   (2* i)
				   (bv-u16-ref hex-chars-lc
							   (2* (bv-u8-ref bin i)))))
    hex))

(define (hex->bin hex)
  (let* ([hex-len	(bytevector-length hex)]
		 [bin-len	(div2 hex-len)])
    (unless (even? hex-len)
      (error "Length of hex string must be even"))
    (let ([bin (make-bytevector bin-len)])
      (numeric-for (i 0 bin-len)
		(unless (and-let* ([idx	(- (bv-u16-ref hex (2* i)) #x3030)]
						   [(>= idx #x0000)]
						   [(<= idx #x3636)]
						   [n	(bv-u8-ref chars-hex idx)]
						   [(< n #xff)])
				  (bv-u8-set! bin i (+ n (lowbits idx)))
				  #t)
		  (error "Invalid character in hex string")))
      bin)))
