;; -*- mode: Scheme; tab-width: 4 -*-

(eval-when (expand load eval)
  (read-set! keywords 'postfix))

(define-module (libcrypto hash)

  use-module: (oop goops)

  use-module: ((libcrypto internal)
			   select: (libcrypto-make-func))

  use-module: ((system foreign)
			   select: (bytevector->pointer
						null-pointer?
						make-c-struct
						int size_t uint64))

  use-module: ((rnrs bytevectors)
  			   select: (make-bytevector
						bytevector-length))

  use-module: ((ice-9 optargs)
			   select: (let-keywords))

  use-module: ((ice-9 binary-ports)
			   select: (get-bytevector-n!))

  export: (<hash-algorithm>		compute
		   <hash-state>			update as-bytes restart

		   result-size
		   algorithm))

;;; <hash-algorithm>

(define-class <hash-algorithm-class> (<class>)
  (instances	getter:		instances-of
				init-form:	(make-hash-table)))

(define-class <hash-algorithm> (<object>)
  (algo			getter:		algorithm
				init-keyword: #:algorithm)
  (initfn		getter:		initfn)
  (updatefn		getter:		updatefn)
  (finalfn		getter:		finalfn)
  (directfn		getter:		directfn)
  (result-size	getter:		result-size)
  (ctx-size		getter:		ctx-size)
  metaclass: <hash-algorithm-class>)

;; values are (result-bytes . context-bytes). It's OK if the context
;; size is bigger than needed, so we round it a bit.

(define %algo-sizes
  '((md5	16 . 128)	;; actually only needs 23 words
    (sha1	20 . 128)	;; actually only needs 24 words
    (sha224	28 . 128)	;; actually only needs 28 words
    (sha256	32 . 128)	;; actually only needs 28 words
    (sha384	48 . 256)	;; actually only needs 28 longs
    (sha512	64 . 256)))	;; actually only needs 28 longs

;; this makes only one object per algorithm

(define-method (make-instance (class <hash-algorithm-class>) . initargs)
  (let-keywords initargs #t ((algorithm #f))
    (let ([htab		(instances-of class)]
		  [sizes	(assq-ref %algo-sizes algorithm)])
      (unless sizes
		(error "unknown algorithm"))
      (or (hashq-ref htab algorithm)
		  (let ([obj (next-method)])
			(hashq-set! htab algorithm obj)
			obj)))))

;; this initializes a new algorithm

(define-method (initialize (self <hash-algorithm>) initargs)
  (let-keywords initargs #t ((algorithm #f))
    (let* ([sizes		(or (assq-ref %algo-sizes algorithm)
							(error "unknown algorithm"))]
		   [algoname	(string-upcase (symbol->string algorithm))]
		   [size		(car sizes)]
		   [fn			(libcrypto-make-func algoname "" '* '* size_t '*)])
      (next-method)
      (slot-set! self
				 'directfn
      			 (lambda (bv offset len)
				   (let ((res (make-bytevector size 0)))
					 (when (null-pointer? (fn (bytevector->pointer bv offset)
											  len
											  (bytevector->pointer res)))
					   (error "error"))
					 res)))
      (slot-set! self
				 'initfn
				 (libcrypto-make-func algoname "_Init" int '*))
      (slot-set! self
				 'updatefn
				 (libcrypto-make-func algoname "_Update" int '* '* size_t))
      (slot-set! self
				 'finalfn
				 (libcrypto-make-func algoname "_Final" int '* '*))
      (slot-set! self 'result-size size)
      (slot-set! self 'ctx-size (cdr sizes)))))

(define-method (compute (self <hash-algorithm>)
						(data <bytevector>))
  ((directfn self) data 0 (bytevector-length data)))

(define-method (compute (self <hash-algorithm>)
						(data <bytevector>)
						(offset <integer>))
  (let ((len (- (bytevector-length data) offset)))
    (when (or (negative? offset) (negative? len))
      (error "bad offset/len"))
    ((directfn self) data offset len)))

(define-method (compute (self <hash-algorithm>)
						(data <bytevector>)
						(offset <integer>)
						(len <integer>))
  (when (or (negative? offset)
			(negative? len)
			(> (+ offset len) (bytevector-length data))
			(error "bad offset/len"))
	((directfn self) data offset len)))

(define-method (make-ctx (self <hash-algorithm>))
  (make-bytevector (ctx-size self) 0))

;;; <hash-state>

(define-class <hash-state> (<object>)
  (impl		getter: impl)
  (algo		getter: algorithm)
  (ctx		getter: get-ctx)
  (updatefn	getter: updatefn))

(define-method (initialize (self <hash-state>) initargs)
  (let-keywords initargs #t ((algorithm #f))
    (let* ([impl	(make <hash-algorithm> algorithm: algorithm)]
		   [ctx		(make-ctx impl)]
		   [ctxptr	(bytevector->pointer ctx)]
		   [updatefn (updatefn impl)]
		   [initfn	(initfn impl)])
	  (when (zero? (initfn ctxptr))
		(error "error"))
      (next-method)
      (slot-set! self 'algo algorithm)
      (slot-set! self 'impl impl)
      (slot-set! self 'ctx ctx)
	  ;; saving this as a closure saves some getter calls on the hot
	  ;; path.
      (slot-set! self 'updatefn
				 (lambda (bv offset len)
				   (when (zero? (updatefn ctxptr
										  (bytevector->pointer bv offset)
										  len))
					 (error "error")))))))

(define-method (result-size (self <hash-state>))
  (result-size (impl self)))

(define-method (restart (self <hash-state>))
  (when (zero? ((initfn (impl self)) (bytevector->pointer (get-ctx self))))
	(error "error")))

(define-method (update (self <hash-state>)
					   (data <bytevector>))
  ((updatefn self) data 0 (bytevector-length data)))

(define-method (update (self <hash-state>)
					   (data <bytevector>)
					   (offset <integer>))
  (let ((len (- (bytevector-length data) offset)))
    (when (or (negative? offset) (negative? len))
      (error "bad offset/len"))
    ((updatefn self) data offset len)))

(define-method (update (self <hash-state>)
					   (data <bytevector>)
					   (offset <integer>)
					   (len <integer>))
  (when (or (negative? offset)
			(negative? len)
			(> (+ offset len) (bytevector-length data)))
    (error "bad offset/len"))
  ((updatefn self) data offset len))

(define %default-bufsz 131072)

(define-method (update (self <hash-state>)
					   (port <input-port>))
  (update self port %default-bufsz))

(define-method (update (self <hash-state>)
					   (port <input-port>)
					   (bufsz <integer>))
  (let* ([buf		(make-bytevector bufsz 0)]
		 [updatefn	(updatefn self)])
    (let loop ([nread (get-bytevector-n! port buf 0 bufsz)])
      (unless (eof-object? nread)
		(updatefn buf 0 nread)
		(loop (get-bytevector-n! port buf 0 bufsz))))))

(define-method (as-bytes (self <hash-state>))
  (let* ([impl		(impl self)]
		 [finalfn	(finalfn impl)]
		 [res		(make-bytevector (result-size impl) 0)])
    (when (zero? (finalfn (bytevector->pointer res)
						  (bytevector->pointer (get-ctx self))))
      (error "error"))
	(restart self)
	res))
