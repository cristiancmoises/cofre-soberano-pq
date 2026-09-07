;; Build from a checkout with:
;; guix build -f packaging/guix/package.scm
;; Requires a Guix revision providing rust-1.95.

(use-modules (ice-9 rdelim)
             (guix packages)
             (guix gexp)
             (guix git-download)
             (guix build-system cargo)
             (guix import crate)
             ((guix licenses) #:prefix license:)
             (gnu packages rust))

(define source-directory
  (canonicalize-path
   (string-append (dirname (current-filename)) "/../..")))

(define cofre-soberano-pq
  (package
    (name "cofre-soberano-pq")
    (version
     (call-with-input-file (string-append source-directory "/Cargo.toml")
       (lambda (port)
         (let loop ((line (read-line port)))
           (cond
            ((eof-object? line) (error "Cargo.toml has no workspace version"))
            ((string-prefix? "version " line)
             (cadr (string-split line #\")))
            (else (loop (read-line port))))))))
    (source (local-file source-directory "cofre-soberano-pq-source"
                        #:recursive? #t
                        #:select? (git-predicate source-directory)))
    (build-system cargo-build-system)
    (arguments
     (list #:rust rust-1.95
           #:install-source? #f
           #:features ''("qgateway/pkcs11")
           #:cargo-build-flags ''("--release" "--workspace")
           #:cargo-test-flags ''("--workspace" "--features" "qgateway/pkcs11")
           #:cargo-install-paths ''("crates/qaudit" "crates/qaudit-portal"
                                   "crates/qgateway")
           #:phases
           #~(modify-phases %standard-phases
               (replace 'install
                 (lambda _
                   (for-each
                    (lambda (binary)
                      (install-file (string-append "target/release/" binary)
                                    (string-append #$output "/bin")))
                    '("qaudit" "qaudit-portal" "qgateway"))))
               (add-after 'install 'install-documentation
                 (lambda _
                   (let ((doc (string-append #$output
                                             "/share/doc/cofre-soberano-pq")))
                     (for-each (lambda (file) (install-file file doc))
                               '("README.md" "README.pt-BR.md"
                                 "LICENSE-AGPL" "NOTICE"))
                     (copy-recursively "docs" (string-append doc "/docs"))
                     (copy-recursively "screenshots"
                                       (string-append doc "/screenshots"))))))))
    (inputs (cargo-inputs-from-lockfile
             (string-append source-directory "/Cargo.lock")))
    (home-page "https://git.securityops.co/cristiancmoises/cofre-soberano-pq")
    (synopsis "Post-quantum signed audit logs and TCP gateway")
    (description
     "Cofre Soberano PQ provides qaudit for signing and verifying audit logs,
qaudit-portal for viewing them, and qgateway for forwarding TCP traffic over
its experimental post-quantum transport.  It supports ML-DSA signatures,
BLAKE3 audit chains, and an optional PKCS#11 signing backend.")
    (license license:agpl3+)))

cofre-soberano-pq
