SET FIPS_PATH=C:\openssl-fips64\openssl-fips

SET INC_C=C:\openssl-fips64\openssl\inc32
SET INCL_C=C:\openssl-fips64\openssl\tmp32

SET INC=-I %INC_C% -I %INCL_C%
SET CFLAG=/MD /Ox -DOPENSSL_THREADS  -DDSO_WIN32 -W3 -Gs0 -Gy -nologo -DOPENSSL_SYSNAME_WIN32 -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DUNICODE -D_UNICODE -D_CRT_SECURE_NO_DEPRECATE -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -I\usr\local\ssl\fips-2.0/include -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DOPENSSL_NO_RC5 -DOPENSSL_NO_MD2 -DOPENSSL_NO_KRB5 -DOPENSSL_FIPS -DOPENSSL_NO_JPAKE -DOPENSSL_NO_DYNAMIC_ENGINE
SET LIB_CFLAG= /Zl /Zi
SET SHLIB_CFLAG=
SET SHLIB_CFLAGS=%INC% %CFLAG% %LIB_CFLAG% %SHLIB_CFLAG%

SET FIPS_LINK=link
SET FIPS_CC=cl
SET FIPS_CC_ARGS=/FoC:\ibekg\win32\nodejs_ibekg\x64\Release-FIPS\ %SHLIB_CFLAGS% -c
SET PREMAIN_DSO_EXE=C:\openssl-fips64\openssl\out32\fips_premain_dso.exe
SET FIPS_TARGET=C:\ibekg\win32\nodejs_ibekg\x64\Release-FIPS\Out\nodejs_ibekg.node
SET FIPS_SHA1_EXE=%FIPS_PATH%\bin\fips_standalone_sha1.exe
SET FIPSLIB_D=%FIPS_PATH%\lib

perl %FIPS_PATH%\bin\fipslink.pl /ERRORREPORT:PROMPT /OUT:"x64\Release-FIPS\Out\nodejs_ibekg.node" /LTCG /NXCOMPAT /DYNAMICBASE "C:\nodejs64\Release\node.lib" "C:\openssl-fips64\openssl\out32\libeaycompat32.lib" "C:\jansson\win32\vs2010\Output\x64\Release\jansson.lib" "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" /DLL /MACHINE:X64 /OPT:REF /OPT:ICF /NOLOGO /TLBID:1 /IMPLIB:"x64\Release-FIPS\Out\nodejs_ibekg.lib"  "x64\Release-FIPS\nodejs_ibekg.obj" "x64\Release-FIPS\crypto.obj" "x64\Release-FIPS\secure_storage.obj" "x64\Release-FIPS\utils.obj" "x64\Release-FIPS\uuid_gen.obj" "x64\Release-FIPS\fips_premain.obj"