
(eval-when (expand load eval)
  (read-set! keywords 'postfix))

(define-module (libcrypto internal)
  use-module: (system foreign)
  export: (libcrypto-make-func))

(define %libcrypto (delay (dynamic-link "libcrypto")))

(define (libcrypto-make-func pfx sfx ret . args)
  (pointer->procedure ret
		      (dynamic-func (string-append pfx sfx) (force %libcrypto))
		      args))
