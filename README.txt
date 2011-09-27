Java Interface for PKCS#11.

Provides a Java PKCS#11 interface that provides low-level interface
as close as possible to the cryptoki C interface and wraps with
Java-styled interface providing convenience methods and using
exceptions for error handling.

Uses a provider architecture to allow any implementation of the 
native mapping.  Includes JNA < https://github.com/twall/jna > 
as default provider to bridge between Java and native cryptoki lib.
