{
  "targets": [
    {
      "target_name": "nodejs_ibekg",
      "defines": ['PLATFORM="<(OS)"', '_FILE_OFFSET_BITS=64'],      
      "sources": ["src/nodejs/nodejs_ibekg.cpp", "src/secure_storage.cpp", "src/uuid_gen.cpp", "src/crypto.cpp", "src/utils.cpp"],
      "defines": ["OPENSSL_FIPS_BUILD"],
      "cflags": ["-fPIC"],
      "ldflags": [""],
      "include_dirs": ["/usr/local/ssl/include", "/usr/local/ssl/fips-2.0/include", "/usr/local/include", "/usr/include/glib-2.0", "/usr/lib/x86_64-linux-gnu/glib-2.0/include", "/usr/include/gnome-keyring-1"],
      "libraries": ["/usr/local/ssl/lib/libcrypto.so -Wl,-rpath=/usr/local/ssl/lib", "/usr/local/lib/libjansson.a", "-lglib-2.0", "/usr/lib/x86_64-linux-gnu/libgnome-keyring.so"]
    }
  ]
}