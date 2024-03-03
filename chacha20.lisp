;; RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
;; https://datatracker.ietf.org/doc/html/rfc8439#section-2.2

(defconstant +STATE-CONSTANTS+ #(#x61707865 #x3320646e #x79622d32 #x6b206574))

;; n mod 2^32
(defun norm32 (n)
  (logand n #xFFFFFFFF))

;; (x + y) mod 2^32
(defun 32+ (x y)
  (norm32 (+ x y)))

;; 32-bit bitwise shift left with wrap-around.
(defun rotl32 (n times)
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
    (format t "~X " (aref a i)))
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

;; key  : 256-bit / 8 32-bit words
;; nonce:  96-bit / 3 32-bit words
;; count:  32-bit / 1 32-bit word
(defun chacha20-block (key counter nonce)
  (let* ((cntr (if (numberp counter)
                   (make-array 1 :element-type '(unsigned-byte 32)
                                 :initial-contents (list counter))
                   counter))
         (state (concatenate 'vector +STATE-CONSTANTS+ key cntr nonce))
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
;;; plaintext and ciphertext are arrays with an element-type of (unsigned-byte 8).
(defun chacha20-encrypt (key counter nonce plaintext)
  (let ((ciphertext
          (make-array (length plaintext) :element-type '(unsigned-byte 8)))
        (cntr (aref counter 0)))
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
        (print-array ciphertext)))

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
