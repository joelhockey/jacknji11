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

The tests rely on a library named libcryptoki.so being available on the LD_LIBRARY_PATH.
If you for example run SoftHSM2, you have to see to that this exists.

```
sudo ln -s /usr/local/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libcryptoki.so
export LD_LIBRARY_PATH=/usr/local/lib/softhsm
```

Note: LD_LIBRARY_PATH is used by Linux systems to point to directories where libraries should be loaded, apart from the system path. If your libcryptoki.so resides in a directory that is not searched by default by the system, you can use LD_LIBRARY_PATH in order for the system to find your libcryptoki.so.

