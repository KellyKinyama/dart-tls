"C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect 127.0.0.1:4444 -dtls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256  -debug -msg

"C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect 127.0.0.1:4444 -dtls1_2 -cipher PSK-AES128-CCM -psk abc123 -psk_identity my_identity  -debug -msg
"C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect 127.0.0.1:4444 -dtls1_2 -cipher PSK-AES128-CCM8 -psk abc123 -psk_identity my_identity -debug -msg
"C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect 127.0.0.1:4444 -dtls1_2 -cipher PSK-AES128-GCM-SHA256 -psk abc123 -psk_identity my_identity -debug -msg

0xAB, 0xC1, 0x23

"C:\Program Files\Git\usr\bin\openssl.exe" list -cipher-algorithms

connect