#Java Interface for PKCS#11.

Provides a Java PKCS#11 interface that provides low-level interface
as close as possible to the cryptoki C interface and wraps with
Java-styled interface providing convenience methods and using
exceptions for error handling.

Uses a provider architecture to allow any implementation of the 
native mapping. Includes JNA < https://github.com/java-native-access/jna > 
as default provider to bridge between Java and native cryptoki lib.

# Install

Build and install with:

>mvn install

If you want to build without running the tests, use:

>mvn install -DskipTests

# Run tests
The tests, from src/test/java/org/pkcs11/jacknji11/CryptokiTest.java, are run on every call to mvn install.
In order to run the tests on your HSMs (note that not all operations may pass) you can set these environment variables:

```
export JACKNJI11_TEST_TESTSLOT=1762252043
export JACKNJI11_TEST_INITSLOT=1762252043
export JACKNJI11_TEST_SO_PIN=sopin
export JACKNJI11_TEST_USER_PIN=userpin
```

The tests rely on a library named libcryptoki.so being available on the `LD_LIBRARY_PATH`. But you can use an alternate library as described in the following section.

## Providing alternate cryptoki dll
The `CE` and `C` classes provide `Initialize()` and `Initialize(String)` functions. The first function does not take a cryptoki library path, but the second one takes a cryptoki library path. If you want to provide an alternate pkcs11 library, you have two choices:
  1. Use the `JACKNJI11_PKCS11_LIB_PATH` environment variable to set the absolute path of the library. For example: 

```export JACKNJI11_PKCS11_LIB_PATH=/usr/local/lib/utimaco/cs2_pkcs11.so```

  2. Use the `Initialize(String)` function to provide the library manually, as below:
```CE.Initialize("/usr/local/lib/utimaco/cs2_pkcs11.so");```

