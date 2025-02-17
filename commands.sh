"C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect 127.0.0.1:4444 -dtls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256  -debug -msg -state -tlsextdebug 

"C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect 127.0.0.1:4444 -dtls1_2 -cipher PSK-AES128-CCM -psk YOUR_PSK -psk_identity my_identity  -debug -msg
"C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect 127.0.0.1:4444 -dtls1_2 -cipher PSK-AES128-CCM8 -psk 1a2b3c4d5e6f -psk_identity my_identity -debug -msg

"C:\Program Files\Git\usr\bin\openssl.exe" list -cipher-algorithms

connect