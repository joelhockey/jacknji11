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

# Loading native cryptoki library
By default, the `cryptoki` library (`cryptoki.dll` or `libcryptoki.so`) must be available (`LD_LIBRARY_PATH` for linux).
You must either copy/symlink your library to have this name, or you can specify the library path using
`JACKNJI11_PKCS11_LIB_PATH`.

If for example you run SoftHSM2, you have could either:
```
export JACKNJI11_PKCS11_LIB_PATH=/usr/lib/softhsm/libsofthsm2.so
```
or
```
sudo ln -s /usr/lib/softhsm/libsofthsm2.so /usr/lib/softhsm/libcryptoki.so
export LD_LIBRARY_PATH=/usr/lib/softhsm
```
