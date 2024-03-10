;;;; Implementation of RFC 8439: ChaCha20 and Poly1305 for IETF Protocols.
;; https://datatracker.ietf.org/doc/html/rfc8439

(defconstant +state-constants+ #(#x61707865 #x3320646e #x79622d32 #x6b206574))
(defconstant +p+ (- (expt 2 130) 5))

(defun norm32 (n)
  "Computes n mod 2^32."
  (logand n #xFFFFFFFF))

(defun 32+ (x y)
  "Computes (x + y) mod 2^32."
  (declare ((unsigned-byte 32) x y))
  (norm32 (+ x y)))

(defun rotl32 (n times)
  "Performs a 32-bit bitwise shift left with wrap-around."
  (norm32 (logior
           (ash n times)
           (ash n (- times 32)))))

;; 2.1 The ChaCha Quarter Round
(defun qround (a b c d)
  (declare ((unsigned-byte 32) a b c d))
  (setf
   a (32+ a b) d (logxor d a) d (rotl32 d 16)
   c (32+ c d) b (logxor b c) b (rotl32 b 12)
   a (32+ a b) d (logxor d a) d (rotl32 d 8)
   c (32+ c d) b (logxor b c) b (rotl32 b 7))
  (values a b c d))

;; 2.1.1.  Test Vector for the ChaCha Quarter Round
(defun test-vector-211 ()
  (multiple-value-bind (a b c d)
      (qround #x11111111 #x01020304 #x9b8d6f43 #x01234567)
    (format t "a = ~X~%" a)
    (format t "b = ~X~%" b)
    (format t "c = ~X~%" c)
    (format t "d = ~X~%" d)))

(defun print-state (state)
  (dotimes (i 4)
    (let* ((z (* i 4))
           (a (+ 0 z))
           (b (+ 1 z))
           (c (+ 2 z))
           (d (+ 3 z)))
    (format t "~X ~X ~X ~X~%"
            (aref state a) (aref state b) (aref state c) (aref state d)))))
  
;; 2.2 A Quarter Round on the ChaCha State
(defun quarterround (state x y z w)
  (multiple-value-bind (a b c d)
      (qround (aref state x) (aref state y) (aref state z) (aref state w))
    (setf
     (aref state x) a
     (aref state y) b
     (aref state z) c
     (aref state w) d)))

;; 2.2.1 Test Vector for the Quarter Round on the ChaCha State
(defun test-vector-221 ()
  (let ((state
          (make-array
           16
           :element-type '(unsigned-byte 32)
           :initial-contents '(
                               #x879531e0  #xc5ecf37d  #x516461b1  #xc9a62f8a
                               #x44c20ef3  #x3390af7f  #xd9fc690b  #x2a5f714c
                               #x53372767  #xb00a5631  #x974c541a  #x359e9963
                               #x5c971061  #x3d631689  #x2098d9d6  #x91dbd320))))
    (quarterround state 2 7 8 13)
    (print-state state)))

;; 2.3.  The ChaCha20 Block Function
(defun state-add (s1 s2)
  (dotimes (i 16)
    (setf (aref s1 i) (32+ (aref s1 i) (aref s2 i)))))

(defun print-array (a)
  (dotimes (i (length a))
    (format t "~2,'0X " (aref a i)))
  (format t "~%"))

;; uint32 array -> uint8 array
(defun serialize-state (s)
  (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (let ((word (aref s i)))
        (setf (aref result (* i 4))
              (logand #x000000FF word))
        (setf (aref result (+ (* i 4) 1))
              (ash (logand #x0000FF00 word) -8))
        (setf (aref result (+ (* i 4) 2))
              (ash (logand #x00FF0000 word) -16))
        (setf (aref result (+ (* i 4) 3))
              (ash (logand #xFF000000 word) -24))))
    result))

(defun inner-block (state)
  (quarterround state 0 4 8 12)
  (quarterround state 1 5 9 13)
  (quarterround state 2 6 10 14)
  (quarterround state 3 7 11 15)
  (quarterround state 0 5 10 15)
  (quarterround state 1 6 11 12)
  (quarterround state 2 7 8 13)
  (quarterround state 3 4 9 14))

;; (key: u32[8], counter: number|u32[1], nonce: u32[3]) => u8[]
(defun chacha20-block (key counter nonce)
  (let* ((cntr (if (numberp counter)
                   (make-array 1 :element-type '(unsigned-byte 32)
                                 :initial-contents (list counter))
                   counter))
         (state (concatenate 'vector +state-constants+ key cntr nonce))
         (initial-state (copy-seq state)))
    (dotimes (i 10)
      (inner-block state))
    (state-add state initial-state)
    (serialize-state state)))

;; 2.3.2.  Test Vector for the ChaCha20 Block Function
(defun test-vector-232 ()
  (let* ((key (make-array 8
                          :element-type '(unsigned-byte 32)
                          :initial-contents '(#x03020100 #x07060504
                                              #x0b0a0908 #x0f0e0d0c
                                              #x13121110 #x17161514
                                              #x1b1a1918 #x1f1e1d1c)))
         (nonce (make-array 3
                            :element-type '(unsigned-byte 32)
                            :initial-contents '(#x09000000 #x4a000000
                                                #x00000000)))
         (counter (make-array 1
                              :element-type '(unsigned-byte 32)
                              :initial-contents '(#x00000001)))
         (result (chacha20-block key counter nonce)))
    (print-array result)
    result))

;; 2.4.1.  The ChaCha20 Encryption Algorithm
;; (key: u32[8], counter: number|u32[1], nonce: u32[3], plaintext: u8[]) => u8[]
(defun chacha20-encrypt (key counter nonce plaintext)
  (let ((ciphertext
          (make-array (length plaintext) :element-type '(unsigned-byte 8)))
        (cntr (if (numberp counter) counter (aref counter 0))))
    (dotimes (j (floor (/ (length plaintext) 64)))
      (let* ((key-stream (chacha20-block key (+ j cntr) nonce)))
        (loop for k from (* j 64) to (+ (* j 64) 63)
              do
                 (setf (aref ciphertext k)
                       (logxor (aref plaintext k)
                               (aref key-stream (- k (* j 64))))))))
    (unless (eql 0 (mod (length plaintext) 64))
      (let* ((j (floor (/ (length plaintext) 64)))
             (key-stream (chacha20-block key (+ j cntr) nonce)))
        (loop for k from (* j 64) to (1- (length plaintext))
              do
                 (setf (aref ciphertext k)
                       (logxor (aref plaintext k)
                               (aref key-stream (- k (* j 64))))))))
    ciphertext))

;; 2.4.2.  Test Vector for the ChaCha20 Cipher
(defun test-vector-242 ()
  (let* ((key (make-array 8
                          :element-type '(unsigned-byte 32)
                          :initial-contents '(#x03020100 #x07060504
                                              #x0b0a0908 #x0f0e0d0c
                                              #x13121110 #x17161514
                                              #x1b1a1918 #x1f1e1d1c)))
         (nonce (make-array 3
                            :element-type '(unsigned-byte 32)
                            :initial-contents '(#x00000000 #x4a000000
                                                #x00000000)))
         (counter (make-array 1
                              :element-type '(unsigned-byte 32)
                              :initial-contents '(#x00000001)))
         (plaintext (make-array 114
                                :element-type '(unsigned-byte 8)
                                :initial-contents
                                '(#x4c #x61 #x64 #x69 #x65 #x73 #x20 #x61
                                  #x6e #x64 #x20 #x47 #x65 #x6e #x74 #x6c
                                  #x65 #x6d #x65 #x6e #x20 #x6f #x66 #x20
                                  #x74 #x68 #x65 #x20 #x63 #x6c #x61 #x73
                                  #x73 #x20 #x6f #x66 #x20 #x27 #x39 #x39
                                  #x3a #x20 #x49 #x66 #x20 #x49 #x20 #x63
                                  #x6f #x75 #x6c #x64 #x20 #x6f #x66 #x66
                                  #x65 #x72 #x20 #x79 #x6f #x75 #x20 #x6f
                                  #x6e #x6c #x79 #x20 #x6f #x6e #x65 #x20
                                  #x74 #x69 #x70 #x20 #x66 #x6f #x72 #x20
                                  #x74 #x68 #x65 #x20 #x66 #x75 #x74 #x75
                                  #x72 #x65 #x2c #x20 #x73 #x75 #x6e #x73
                                  #x63 #x72 #x65 #x65 #x6e #x20 #x77 #x6f
                                  #x75 #x6c #x64 #x20 #x62 #x65 #x20 #x69
                                  #x74 #x2e)))
         (result (chacha20-encrypt key counter nonce plaintext)))
    (print-array result)
    result))

(defun test-vector-242-decrypt ()
  (let* ((key (make-array 8
                          :element-type '(unsigned-byte 32)
                          :initial-contents '(#x03020100 #x07060504
                                              #x0b0a0908 #x0f0e0d0c
                                              #x13121110 #x17161514
                                              #x1b1a1918 #x1f1e1d1c)))
         (nonce (make-array 3
                            :element-type '(unsigned-byte 32)
                            :initial-contents '(#x00000000 #x4a000000
                                                #x00000000)))
         (counter (make-array 1
                              :element-type '(unsigned-byte 32)
                              :initial-contents '(#x00000001)))
         (plaintext (make-array 114
                                :element-type '(unsigned-byte 8)
                                ;; This is the ciphertext output from
                                ;; test-vector-242!
                                :initial-contents
                                '(#x6E #x2E #x35 #x9A #x25 #x68 #xF9 #x80
                                  #x41 #xBA #x07 #x28 #xDD #x0D #x69 #x81
                                  #xE9 #x7E #x7A #xEC #x1D #x43 #x60 #xC2
                                  #x0A #x27 #xAF #xCC #xFD #x9F #xAE #x0B
                                  #xF9 #x1B #x65 #xC5 #x52 #x47 #x33 #xAB
                                  #x8F #x59 #x3D #xAB #xCD #x62 #xB3 #x57
                                  #x16 #x39 #xD6 #x24 #xE6 #x51 #x52 #xAB
                                  #x8F #x53 #x0C #x35 #x9F #x08 #x61 #xD8
                                  #x07 #xCA #x0D #xBF #x50 #x0D #x6A #x61
                                  #x56 #xA3 #x8E #x08 #x8A #x22 #xB6 #x5E
                                  #x52 #xBC #x51 #x4D #x16 #xCC #xF8 #x06
                                  #x81 #x8C #xE9 #x1A #xB7 #x79 #x37 #x36
                                  #x5A #xF9 #x0B #xBF #x74 #xA3 #x5B #xE6
                                  #xB4 #x0B #x8E #xED #xF2 #x78 #x5E #x42
                                  #x87 #x4D)))
         (result (chacha20-encrypt key counter nonce plaintext)))
    (print-array result)
    ;; Should be the original plaintext.
    result))


;; 2.5.1.  The Poly1305 Algorithm
(defun clamp (r)
  (logand r #x0ffffffc0ffffffc0ffffffc0fffffff))

;; lo, hi => inclusive range of indexes to use
;; (arr: u8[], lo: number, hi: number) => number
(defun le-bytes-to-num (arr lo hi)
  (let ((result 0))
    (dotimes (i (- hi lo))
      (let ((j (+ i lo)))
        (setf result (+ result (ash (aref arr j) (* i 8))))))
    result))

;; (num: number) => u8[16]
(defun num-to-16-le-bytes (num)
  (let ((result (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (let* ((mask (ash #xFF (* i 8)))
             (octet (ash (logand num mask) (- (* i 8)))))
        (setf (aref result i) octet)))
    result))

;; (num: number) => u8[8]
(defun num-to-8-le-bytes (num)
  (let ((result (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8)
      (let* ((mask (ash #xFF (* i 8)))
             (octet (ash (logand num mask) (- (* i 8)))))
        (setf (aref result i) octet)))
    result))

;; key: array of (unsigned-byte 8)
(defun poly1305-mac (msg key)
  (let ((r (clamp (le-bytes-to-num key 0 16)))
        (s (le-bytes-to-num key 16 32))
        (a 0))
    (dotimes (i (ceiling (/ (length msg) 16)))
      (let* ((lo (* i 16))
             (hi (min (length msg) (* (1+ i) 16)))
             (n0 (le-bytes-to-num msg lo hi))
             (n0-bits (* 8 (- hi lo)))
             (extra-bit (ash 1 n0-bits))
             (n (+ n0 extra-bit)))
        (setf a (+ a n))
        (setf a (mod (* r a) +p+))))
    (setf a (+ a s))
    (num-to-16-le-bytes a)))

;; 2.5.2.  Poly1305 Test Vector
(defun test-vector-252 ()
  (let* ((key (make-array 32
                          :element-type '(unsigned-byte 8)
                          :initial-contents
                          '(#x85 #xd6 #xbe #x78 #x57 #x55 #x6d #x33
                            #x7f #x44 #x52 #xfe #x42 #xd5 #x06 #xa8
                            #x01 #x03 #x80 #x8a #xfb #x0d #xb2 #xfd
                            #x4a #xbf #xf6 #xaf #x41 #x49 #xf5 #x1b)))
         (msg (make-array 34
                          :element-type '(unsigned-byte 8)
                          :initial-contents
                          '(#x43 #x72 #x79 #x70 #x74 #x6f #x67 #x72
                            #x61 #x70 #x68 #x69 #x63 #x20 #x46 #x6f
                            #x72 #x75 #x6d #x20 #x52 #x65 #x73 #x65
                            #x61 #x72 #x63 #x68 #x20 #x47 #x72 #x6f
                            #x75 #x70)))
         (result (poly1305-mac msg key)))
    (print-array result)))

;; 2.6.1.  Poly1305 Key Generation
;; (arr: u8[], from: number, to: number) => u8[]
(defun slice-u8 (arr from to)
  (let ((result (make-array (- to from) :element-type '(unsigned-byte 8))))
    (dotimes (i (- to from))
      (setf (aref result i) (aref arr (+ i from))))
    result))

;; Convert a u8 array to a u32 array.
;; (arr: u8[]) => u32-array
(defun u8*-to-u32* (arr)
  (let ((result (make-array
                 (floor (/ (length arr) 4))
                 :element-type '(unsigned-byte 32))))
    (dotimes (i (floor (/ (length arr) 4)))
      (setf (aref result i)
            (logior (aref arr (* i 4))
                    (ash (aref arr (+ (* i 4) 1)) 8)
                    (ash (aref arr (+ (* i 4) 2)) 16)
                    (ash (aref arr (+ (* i 4) 3)) 24))))
    result))

;; (key: u8[32], nonce: u8[12]) => u8[]
(defun poly1305-key-gen (key nonce)
  (slice-u8 (chacha20-block (u8*-to-u32* key) 0 (u8*-to-u32* nonce))
            0 32))

;; 2.6.2.  Poly1305 Key Generation Test Vector
(defun test-vector-262 ()
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-contents '(#x80 #x81 #x82 #x83 #x84 #x85 #x86 #x87
                                                 #x88 #x89 #x8a #x8b #x8c #x8d #x8e #x8f
                                                 #x90 #x91 #x92 #x93 #x94 #x95 #x96 #x97
                                                 #x98 #x99 #x9a #x9b #x9c #x9d #x9e #x9f)))
         (nonce (make-array 12 :element-type '(unsigned-byte 8)
                               :initial-contents '(#x00 #x00 #x00 #x00 #x00 #x01 #x02 #x03
                                                   #x04 #x05 #x06 #x07)))
         (result (poly1305-key-gen key nonce)))
    (print-array result)))

;; 2.8.  AEAD Construction
(defun make-u8* (len)
  (make-array len :element-type '(unsigned-byte 8)))

(defun concat-u8* (&rest args)
  (apply #'concatenate 'vector args))

;; Generates an array of zeroes that, if concatenated to `arr`, would result in an array with a
;; length divisible by 16.
;; (arr: u8[]) => u8[]
(defun pad16 (arr)
  (let ((n (mod (length arr) 16)))
    (if (= 0 n)
        (make-u8* 0)
        (make-u8* (- 16 n)))))

;; (aad: u8[], key: u8[32], iv: u8[8], constant: u8[4], plaintext: u8[]) => u8[], u8[16]
(defun chacha20-aead-encrypt (aad key iv constant plaintext)
  (let* ((nonce (concat-u8* constant iv))
         (otk (poly1305-key-gen key nonce))
         (key32 (u8*-to-u32* key))
         (nonce32 (u8*-to-u32* nonce))
         (ciphertext (chacha20-encrypt key32 1 nonce32 plaintext))
         (mac-data (concat-u8* aad (pad16 aad)
                               ciphertext (pad16 ciphertext)
                               (num-to-8-le-bytes (length aad))
                               (num-to-8-le-bytes (length ciphertext))))
         (tag (poly1305-mac mac-data otk)))
    (values ciphertext tag)))

;; (aad: u8[], key: u8[32], iv: u8[8], constant: u8[4], ciphertext: u8[]) => u8[], u8[16]
(defun chacha20-aead-decrypt (aad key iv constant ciphertext)
  (let* ((nonce (concat-u8* constant iv))
         (otk (poly1305-key-gen key nonce))
         (key32 (u8*-to-u32* key))
         (nonce32 (u8*-to-u32* nonce))
         (plaintext (chacha20-encrypt key32 1 nonce32 ciphertext))
         (mac-data (concat-u8* aad (pad16 aad)
                               ciphertext (pad16 ciphertext)
                               (num-to-8-le-bytes (length aad))
                               (num-to-8-le-bytes (length ciphertext))))
         (tag (poly1305-mac mac-data otk)))
    (values plaintext tag)))

;; 2.8.2.  Test Vector for AEAD_CHACHA20_POLY1305
(defun test-vector-282 ()
  (let* ((plaintext (make-array 114
                                :element-type '(unsigned-byte 8)
                                :initial-contents
                                '(#x4c #x61 #x64 #x69 #x65 #x73 #x20 #x61
                                  #x6e #x64 #x20 #x47 #x65 #x6e #x74 #x6c
                                  #x65 #x6d #x65 #x6e #x20 #x6f #x66 #x20
                                  #x74 #x68 #x65 #x20 #x63 #x6c #x61 #x73
                                  #x73 #x20 #x6f #x66 #x20 #x27 #x39 #x39
                                  #x3a #x20 #x49 #x66 #x20 #x49 #x20 #x63
                                  #x6f #x75 #x6c #x64 #x20 #x6f #x66 #x66
                                  #x65 #x72 #x20 #x79 #x6f #x75 #x20 #x6f
                                  #x6e #x6c #x79 #x20 #x6f #x6e #x65 #x20
                                  #x74 #x69 #x70 #x20 #x66 #x6f #x72 #x20
                                  #x74 #x68 #x65 #x20 #x66 #x75 #x74 #x75
                                  #x72 #x65 #x2c #x20 #x73 #x75 #x6e #x73
                                  #x63 #x72 #x65 #x65 #x6e #x20 #x77 #x6f
                                  #x75 #x6c #x64 #x20 #x62 #x65 #x20 #x69
                                  #x74 #x2e)))
         (aad (make-array 12
                              :element-type '(unsigned-byte 8)
                              :initial-contents '(#x50 #x51 #x52 #x53 #xc0 #xc1 #xc2 #xc3
                                                  #xc4 #xc5 #xc6 #xc7)))
         (key (make-array 32
                          :element-type '(unsigned-byte 8)
                          :initial-contents '(#x80 #x81 #x82 #x83 #x84 #x85 #x86 #x87
                                              #x88 #x89 #x8a #x8b #x8c #x8d #x8e #x8f
                                              #x90 #x91 #x92 #x93 #x94 #x95 #x96 #x97
                                              #x98 #x99 #x9a #x9b #x9c #x9d #x9e #x9f)))
         (iv (make-array 8
                            :element-type '(unsigned-byte 8)
                            :initial-contents '(#x40 #x41 #x42 #x43 #x44 #x45 #x46 #x47)))
         (constant (make-array 4
                            :element-type '(unsigned-byte 8)
                            :initial-contents '(#x07 #x00 #x00 #x00))))
    (multiple-value-bind (ciphertext tag)
        (chacha20-aead-encrypt aad key iv constant plaintext)
      (format t "Ciphertext: ")
      (print-array ciphertext)
      (format t "Tag       : ")
      (print-array tag)
      (multiple-value-bind (ptext tag2)
          (chacha20-aead-decrypt aad key iv constant ciphertext)
        (format t "Decrypted : ")
        (print-array ptext)
        (format t "Tag       : ")
        (print-array tag2)))))
