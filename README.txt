Java Interface for PKCS#11.

Uses JNA < https://github.com/twall/jna > to provide bridge between
Java and native cryptoki lib.  Provides direct mapping JNA (Native.java),
C-style interface with a few fixes for JNA direct mapping struct[]
handling (C.java), and a convenient java interface (CE.java) that throws
Exceptions rather than returning int return code and provides
automatic array sizing for encrypt / decrypt and other operations.
