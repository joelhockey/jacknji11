/*
 * Copyright 2010-2011 Joel Hockey (joel.hockey@gmail.com). All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.pkcs11.jacknji11;

/**
 * Native interface for PKCS#11 functions.
 * This interface allows for pluggable providers to do any native
 * interface or network protocol conversion.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions.
 * <ol>
 * <li>{@link org.pkcs11.jacknji11.NativeProvider} provides the lowest level
 * direct mapping to the <code>'C_*'</code> functions.  There is little
 * reason why you would ever want to invoke it directly, but you can.
 * <li>{@link org.pkcs11.jacknji11.C} provides the exact same functions
 * as {@link org.pkcs11.jacknji11.NativeProvider} by calling through to the
 * corresponding native method.  The <code>'C_'</code> at the start of the
 * function name is removed since the <code>'C.'</code> when you call the
 * static methods of this class looks similar.  In addition to calling
 * the native methods, {@link org.pkcs11.jacknji11.C} provides logging
 * through apache commons logging.  You can use this if you require fine-grain
 * control over something such as checking
 * {@link org.pkcs11.jacknji11.CKR} return codes.
 * <li>{@link org.pkcs11.jacknji11.CE} (<b>C</b>ryptoki
 * with <b>E</b>xceptions) provides the most user-friendly interface
 * and is the preferred interface to use.  It calls
 * related function(s) in {@link org.pkcs11.jacknji11.C},
 * and converts any non-zero return values into a
 * {@link org.pkcs11.jacknji11.CKRException}.  It automatically resizes
 * arrays and other helpful things.
 * </ol>
 *
 * Method descriptions taken from
 * <a href="ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf">PKCS #11 v2.20</a>
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public interface NativeProvider {
    /**
C_Initialize initializes the Cryptoki library.  pInitArgs either has the value NULL_PTR
or points to a CK_C_INITIALIZE_ARGS structure containing information on how the
library should deal with multi-threaded access.  If an application will not be accessing
Cryptoki through multiple threads simultaneously, it can generally supply the value
NULL_PTR to C_Initialize (the consequences of supplying this value will be explained
below).
<p>If  pInitArgs is non-NULL_PTR,  C_Initialize should cast it to a
CK_C_INITIALIZE_ARGS_PTR and then dereference the resulting pointer to obtain
the  CK_C_INITIALIZE_ARGS fields  CreateMutex,  DestroyMutex,  LockMutex,
UnlockMutex, flags, and pReserved.  For this version of Cryptoki, the value of pReserved
thereby obtained must be NULL_PTR; if it's not, then C_Initialize should return with
the value CKR_ARGUMENTS_BAD.
<p>If the CKF_LIBRARY_CANT_CREATE_OS_THREADS flag in the flags field is set,
that indicates that application threads which are executing calls to the Cryptoki library
are not permitted to use the native operation system calls to spawn off new threads.  In
other words, the library's code may not create its own threads.  If the library is unable to
function properly under this restriction,  C_Initialize should return with the value
CKR_NEED_TO_CREATE_THREADS.
<p>A call to  C_Initialize specifies one of four different ways to support multi-threaded
access via the value of the CKF_OS_LOCKING_OK flag in the  flags field and the
values of the CreateMutex, DestroyMutex, LockMutex, and UnlockMutex function pointer
fields:
<ol><li>
If the flag isn't set, and the function pointer fields aren't supplied (i.e., they all have
the value NULL_PTR), that means that the application  won't be accessing the
Cryptoki library from multiple threads simultaneously.
<li>If the flag is set, and the function pointer fields aren't supplied (i.e., they all have the
value NULL_PTR), that means that the application will be performing multi-threaded
Cryptoki access, and the library needs to use the native operating system primitives to
ensure safe multi-threaded access.  If the library is unable to do this, C_Initialize
should return with the value CKR_CANT_LOCK.
<li>If the flag  isn't set, and the function pointer fields  are supplied (i.e., they all have
non-NULL_PTR values), that means that the application will be performing multi-
threaded Cryptoki access, and the library needs to use the supplied function pointers
for mutex-handling to ensure safe multi-threaded access.  If the library is unable to do
this, C_Initialize should return with the value CKR_CANT_LOCK.
<li>If the flag is set, and the function pointer fields are supplied (i.e., they all have non-
NULL_PTR values), that means that the application  will be performing multi-
threaded Cryptoki access, and the library  needs to use either the native operating
system primitives or the supplied function pointers for mutex-handling to ensure safe
multi-threaded access.  If the library is unable to do this, C_Initialize should return
with the value CKR_CANT_LOCK.
</ol>
<p>If some, but not all, of the supplied function pointers to  C_Initialize are non-
NULL_PTR, then C_Initialize should return with the value CKR_ARGUMENTS_BAD.
<p>A call to  C_Initialize with  pInitArgs set to NULL_PTR is treated like a call to
C_Initialize with  pInitArgs pointing to a CK_C_INITIALIZE_ARGS which has the
CreateMutex,  DestroyMutex,  LockMutex,  UnlockMutex, and  pReserved fields set to
NULL_PTR, and has the flags field set to 0.
<p>C_Initialize should be the first Cryptoki call made by an application, except for calls to
C_GetFunctionList.  What this function actually does is implementation-dependent;
typically, it might cause Cryptoki to initialize  its internal memory buffers, or any other
resources it requires.
<p>If several applications are using Cryptoki, each one should call C_Initialize.  Every call
to C_Initialize should (eventually) be succeeded by a single call to C_Finalize.
     * @param pInitArgs recommend setting null for mutexes and flags to {@link CK_C_INITIALIZE_ARGS#CKF_OS_LOCKING_OK}
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CANT_LOCK},
{@link CKR#CRYPTOKI_ALREADY_INITIALIZED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#NEED_TO_CREATE_THREADS}, {@link CKR#OK}
     */
    long C_Initialize(CK_C_INITIALIZE_ARGS pInitArgs);

    /**
C_Finalize is called to indicate that an application is finished with the Cryptoki library.
It should be the last Cryptoki call made by an application.  The pReserved parameter is
reserved for future versions; for this version, it should be set to NULL_PTR (if
C_Finalize is called with a non-NULL_PTR value for  pReserved, it should return the
value CKR_ARGUMENTS_BAD.
<p>If several applications are using Cryptoki, each one should call  C_Finalize.  Each
application's call to C_Finalize should be preceded by a single call to C_Initialize; in
between the two calls, an application can make calls to other Cryptoki functions.  See
Section 6.6 for more details.
<p>Despite the fact that the parameters supplied to C_Initialize can in general allow for safe
multi-threaded access to a Cryptoki library, the behavior of C_Finalize is nevertheless
undefined if it is called by an application while other threads of the application are
making Cryptoki calls.  The exception to this exceptional behavior of C_Finalize occurs
when a thread calls C_Finalize while another of the application's threads is blocking on
Cryptoki's  C_WaitForSlotEvent function.  When this happens, the blocked thread
becomes unblocked and returns the value CKR_CRYPTOKI_NOT_INITIALIZED.  See
C_WaitForSlotEvent for more information.
     * @param pReserved reserved for future use, must be null
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}
     */
    long C_Finalize(NativePointer pReserved);

    /**
C_GetInfo returns general information about Cryptoki.  pInfo points to the location that
receives the information.
     * @param pInfo location that receives information
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}
     */
    long C_GetInfo(CK_INFO pInfo);

    /**
C_GetSlotList is used to obtain a list of slots in the system.  tokenPresent indicates
whether the list obtained includes only those slots with a token present (CK_TRUE), or
all slots (CK_FALSE); pulCount points to the location that receives the number of slots.
There are two ways for an application to call C_GetSlotList:
<ol>
<li>If pSlotList is NULL_PTR, then all that C_GetSlotList does is return (in *pulCount)
the number of slots, without actually returning a list of slots.  The contents of the
buffer pointed to by pulCount on entry to C_GetSlotList has no meaning in this case,
and the call returns the value CKR_OK.
<li>If  pSlotList is not NULL_PTR, then *pulCount must contain the size (in terms of
CK_SLOT_ID elements) of the buffer pointed to by pSlotList.  If that buffer is large
enough to hold the list of slots, then the  list is returned in it, and CKR_OK is
returned.  If not, then the call to  C_GetSlotList returns the value
CKR_BUFFER_TOO_SMALL.  In either case, the value *pulCount is set to hold the
number of slots.
</ol>
<p>Because C_GetSlotList does not allocate any space of its own, an application will often
call C_GetSlotList twice (or sometimes even more times'if an application is trying to
get a list of all slots with a token present, then the number of such slots can
(unfortunately) change between when the application asks for how many such slots there
are and when the application asks for the slots themselves).  However, multiple calls to
C_GetSlotList are by no means required.
<p>All slots which C_GetSlotList reports must be able to be queried as valid slots by
C_GetSlotInfo.  Furthermore, the set of slots accessible through a Cryptoki library is
checked at the time that C_GetSlotList, for list length prediction (NULL pSlotList
argument) is called. If an application calls C_GetSlotList with a non-NULL pSlotList,
and then the user adds or removes a hardware device, the changed slot list will only be
visible and effective if C_GetSlotList is called again with NULL. Even if C_
GetSlotList is successfully called this way, it may or may not be the case that the
changed slot list will be successfully recognized depending on the library
implementation.  On some platforms, or earlier PKCS11 compliant libraries, it may be
necessary to successfully call C_Initialize or to restart the entire system.
     * @param tokenPresent only slots with tokens?
     * @param pSlotList receives array of slot IDs
     * @param pulCount receives number of slots
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK}
     */
    long C_GetSlotList(boolean tokenPresent, long[] pSlotList, LongRef pulCount);

    /**
C_GetSlotInfo obtains information about a particular slot in the system. slotID is the ID
of the slot; pInfo points to the location that receives the slot information.
     * @param slotID the ID of the slot
     * @param pInfo receives the slot information
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR},
{@link CKR#HOST_MEMORY}, {@link CKR#OK}, {@link CKR#SLOT_ID_INVALID}
     */
    long C_GetSlotInfo(long slotID, CK_SLOT_INFO pInfo);

    /**
C_GetTokenInfo obtains information about a particular token in the system.  slotID is
the ID of the token's slot; pInfo points to the location that receives the token information.
     * @param slotID ID of the token's slot
     * @param pInfo receives the token information
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#SLOT_ID_INVALID}, {@link CKR#TOKEN_NOT_PRESENT},
{@link CKR#TOKEN_NOT_RECOGNIZED}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_GetTokenInfo(long slotID, CK_TOKEN_INFO pInfo);

    /**
C_WaitForSlotEvent waits for a slot event, such as token insertion or token removal, to
occur.  flags determines whether or not the C_WaitForSlotEvent call blocks (i.e., waits
for a slot event to occur); pSlot points to a location which will receive the ID of the slot
that the event occurred in.  pReserved is reserved for future versions; for this version of
Cryptoki, it should be NULL_PTR.
<p>At present, the only flag defined for use in the flags argument is CKF_DONT_BLOCK:
Internally, each Cryptoki application has a flag for each slot which is used to track
whether or not any unrecognized events involving that slot have occurred.  When an
application initially calls C_Initialize, every slot's event flag is cleared.  Whenever a slot
event occurs, the flag corresponding to the slot in which the event occurred is set.
<p>If C_WaitForSlotEvent is called with the CKF_DONT_BLOCK flag set in the  flags
argument, and some slot's event flag is set, then that event flag is cleared, and the call
returns with the ID of that slot in the location pointed to by pSlot.  If more than one slot's
event flag is set at the time of the call, one such slot is chosen by the library to have its
event flag cleared and to have its slot ID returned.
<p>If C_WaitForSlotEvent is called with the CKF_DONT_BLOCK flag set in the  flags
argument, and no slot's event flag is set, then the call returns with the value
CKR_NO_EVENT.  In this case, the contents of the location pointed to by pSlot when
C_WaitForSlotEvent are undefined.
<p>If C_WaitForSlotEvent is called with the CKF_DONT_BLOCK flag clear in the flags
argument, then the call behaves as above, except that it will block.  That is, if no slot's
event flag is set at the time of the call, C_WaitForSlotEvent will wait until some slot's
event flag becomes set.  If a  thread of an application has a C_WaitForSlotEvent call
blocking when another thread of that application calls  C_Finalize, the
C_WaitForSlotEvent call returns with the value
CKR_CRYPTOKI_NOT_INITIALIZED.
<p>Although the parameters supplied to C_Initialize can in general allow for safe multi-
threaded access to a Cryptoki library, C_WaitForSlotEvent is exceptional in that the
behavior of Cryptoki is undefined if multiple threads of a single application make
simultaneous calls to C_WaitForSlotEvent.
     * @param flags blocking/non-blocking flag
     * @param pSlot location that receives the slot ID
     * @param pReserved reserved.  Should by NULL_PTR
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#NO_EVENT}, {@link CKR#OK}
     */
    long C_WaitForSlotEvent(long flags, LongRef pSlot, NativePointer pReserved);

    /**
C_GetMechanismList is used to obtain a list of mechanism types supported by a token.
SlotID is the ID of the token's slot;  pulCount points to the location that receives the
number of mechanisms.
<p>There are two ways for an application to call C_GetMechanismList:
<ol>
<li>If pMechanismList is NULL_PTR, then all that C_GetMechanismList does is return
(in *pulCount) the number of mechanisms, without actually returning a list of
mechanisms.  The contents of *pulCount on entry to C_GetMechanismList has no
meaning in this case, and the call returns the value CKR_OK.
<li>If pMechanismList is not NULL_PTR, then *pulCount must contain the size (in terms
of  CK_MECHANISM_TYPE elements) of the buffer pointed to by
pMechanismList.  If that buffer is large enough to hold the list of mechanisms, then
the list is returned in it, and CKR_OK is returned.  If not, then the call to
C_GetMechanismList returns the value CKR_BUFFER_TOO_SMALL.  In either
case, the value *pulCount is set to hold the number of mechanisms.
</ol>
<p>Because C_GetMechanismList does not allocate any space of its own, an application
will often call C_GetMechanismList twice.  However, this behavior is by no means
required.
     * @param slotID ID of token's slot
     * @param pMechanismList gets mech. array
     * @param pulCount gets # of mechs.
     * @return {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#SLOT_ID_INVALID}, {@link CKR#TOKEN_NOT_PRESENT},
{@link CKR#TOKEN_NOT_RECOGNIZED}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_GetMechanismList(long slotID, long[] pMechanismList, LongRef pulCount);

    /**
C_GetMechanismInfo obtains information about a particular mechanism possibly
supported by a token. slotID is the ID of the token's slot; type is the type of mechanism;
pInfo points to the location that receives the mechanism information.
     * @param slotID ID of the token's slot
     * @param type type of mechanism
     * @param pInfo receives mechanism info
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#MECHANISM_INVALID},
{@link CKR#OK}, {@link CKR#SLOT_ID_INVALID}, {@link CKR#TOKEN_NOT_PRESENT},
{@link CKR#TOKEN_NOT_RECOGNIZED}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO pInfo);

    /**
C_InitToken initializes a token. slotID is the ID of the token's slot; pPin points to the
SO's initial PIN (which need not be null-terminated); ulPinLen is the length in bytes of
the PIN;  pLabel points to the 32-byte label of the  token (which must be padded with
blank characters, and which must  not be null-terminated). This standard allows PIN
values to contain any valid UTF8 character, but the token may impose subset restrictions.
If the token has not been initialized (i.e. new from the factory), then the pPin parameter
becomes the initial value of the SO PIN.  If the token is being reinitialized, the  pPin
parameter is checked against the existing SO PIN to authorize the initialization operation.
In both cases, the SO PIN is the value pPin after the function completes successfully. If
the SO PIN is lost, then the card must be reinitialized using a mechanism outside the
scope of this standard. The  CKF_TOKEN_INITIALIZED  flag in the
CK_TOKEN_INFO structure indicates the action that will result from calling
C_InitToken. If set, the token will be reinitialized, and the client must supply the
existing SO password in pPin.
<p>When a token is initialized, all objects that can be destroyed are destroyed (i.e., all except
for "indestructible" objects such as keys built into the token).  Also, access by the normal
user is disabled until the SO sets the normal user's PIN.  Depending on the token, some
"default" objects may be created, and attributes of some objects may be set to default
values.
<p>If the token has a "protected authentication path", as indicated by the
CKF_PROTECTED_AUTHENTICATION_PATH flag in its  CK_TOKEN_INFO
being set, then that means that there is some way for a user to be authenticated to the
token without having the application send a PIN through the Cryptoki library.  One such
possibility is that the user enters a PIN on  a PINpad on the token itself, or on the slot
device.  To initialize a token with such a protected authentication path, the  pPin
parameter to  C_InitToken should be NULL_PTR.  During the execution of
C_InitToken, the SO's PIN will be entered through the protected authentication path.
<p>If the token has a protected authentication path other than a PINpad, then it is token-
dependent whether or not C_InitToken can be used to initialize the token.
A token cannot be initialized if Cryptoki detects that any application has an open session
with it; when a call to C_InitToken is made under such circumstances, the call fails with
error CKR_SESSION_EXISTS.  Unfortunately, it may happen when  C_InitToken is
called that some other application does have an open session with the token, but Cryptoki
cannot detect this, because it cannot detect anything about other applications using the
token.  If this is the case, then the consequences of the C_InitToken call are undefined.
<p>The C_InitToken function may not be sufficient to properly initialize complex tokens. In
these situations, an initialization mechanism outside the scope of Cryptoki must be
employed. The definition of "complex token" is product specific.
     * @param slotID ID of the token's slot
     * @param pPin the SO's initial PIN
     * @param ulPinLen length in bytes of the PIN
     * @param pLabel32 32-byte token label (blank padded)
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#PIN_INCORRECT}, {@link CKR#PIN_LOCKED}, {@link CKR#SESSION_EXISTS},
{@link CKR#SLOT_ID_INVALID}, {@link CKR#TOKEN_NOT_PRESENT},
{@link CKR#TOKEN_NOT_RECOGNIZED}, {@link CKR#TOKEN_WRITE_PROTECTED},
{@link CKR#ARGUMENTS_BAD}
     */
    long C_InitToken(long slotID, byte[] pPin, long ulPinLen, byte[] pLabel32);

    /**
C_InitPIN initializes the normal user's PIN.   hSession is the session's handle;  pPin
points to the normal user's PIN; ulPinLen is the length in bytes of the PIN. This standard
allows PIN values to contain any valid UTF8 character, but the token may impose subset
restrictions.
<p>C_InitPIN can only be called in the "R/W SO Functions" state.  An attempt to call it
from a session in any other state fails with error CKR_USER_NOT_LOGGED_IN.
If the token has a "protected authentication path", as indicated by the
CKF_PROTECTED_AUTHENTICATION_PATH flag in its CK_TOKEN_INFO being
set, then that means that there is some way  for a user to be authenticated to the token
without having the application send a PIN  through the Cryptoki library.  One such
possibility is that the user enters a PIN on  a PINpad on the token itself, or on the slot
device.  To initialize the normal user's  PIN on a token with such a protected
authentication path, the pPin parameter to C_InitPIN should be NULL_PTR.  During the
execution of  C_InitPIN, the SO will enter the new PIN through the protected
authentication path.
<p>If the token has a protected authentication path other than a PINpad, then it is token-
dependent whether or not C_InitPIN can be used to initialize the normal user's token
access.
     * @param hSession the session's handle
     * @param pPin the normal user's PIN
     * @param ulPinLen length in bytes of the PIN
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK}, {@link CKR#PIN_INVALID},
{@link CKR#PIN_LEN_RANGE}, {@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_READ_ONLY},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#TOKEN_WRITE_PROTECTED},
{@link CKR#USER_NOT_LOGGED_IN}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_InitPIN(long hSession, byte[] pPin, long ulPinLen);

    /**
C_SetPIN modifies the PIN of the user that is currently logged in, or the CKU_USER
PIN if the session is not logged in.  hSession is the session's handle; pOldPin points to
the old PIN; ulOldLen is the length in bytes of the old PIN; pNewPin points to the new
PIN; ulNewLen is the length in bytes of the new PIN. This standard allows PIN values to
contain any valid UTF8 character, but the token may impose subset restrictions.
C_SetPIN can only be called in the "R/W Public Session" state, "R/W SO Functions"
state, or "R/W User Functions" state.  An attempt to call it from a session in any other
state fails with error CKR_SESSION_READ_ONLY.
<p>If the token has a "protected authentication path", as indicated by the
CKF_PROTECTED_AUTHENTICATION_PATH flag in its CK_TOKEN_INFO being
set, then that means that there is some way  for a user to be authenticated to the token
without having the application send a PIN  through the Cryptoki library.  One such
possibility is that the user enters a PIN on  a PINpad on the token itself, or on the slot
device.  To modify the current user's PIN on a token with such a protected authentication
path, the pOldPin and pNewPin parameters to C_SetPIN should be NULL_PTR.  During
the execution of C_SetPIN, the current user will enter the old PIN and the new PIN
through the protected authentication path.  It is not specified how the PINpad should be
used to enter two PINs; this varies.
<p>If the token has a protected authentication path other than a PINpad, then it is token-
dependent whether or not C_SetPIN can be used to modify the current user's PIN.
     * @param hSession the session's handle
     * @param pOldPin the old PIN
     * @param ulOldLen length of the old PIN
     * @param pNewPin the new PIN
     * @param ulNewLen length of the new PIN
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#PIN_INCORRECT}, {@link CKR#PIN_INVALID}, {@link CKR#PIN_LEN_RANGE},
{@link CKR#PIN_LOCKED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SESSION_READ_ONLY},
{@link CKR#TOKEN_WRITE_PROTECTED}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_SetPIN(long hSession, byte[] pOldPin, long ulOldLen, byte[] pNewPin, long ulNewLen);

    /**
C_OpenSession opens a session between an application and a token in a particular slot.
slotID is the slot's ID; flags indicates the type of session; pApplication is an application-
defined pointer to be passed to the notification callback;  Notify is the address of the
notification callback function (see Section 11.17); phSession points to the location that
receives the handle for the new session.
<p>When opening a session with C_OpenSession, the flags parameter consists of the logical
OR of zero or more bit flags defined in the CK_SESSION_INFO data type.  For legacy
reasons, the  CKF_SERIAL_SESSION bit must always be set; if a call to
C_OpenSession does not have this bit set, the call should return unsuccessfully with the
error code CKR_PARALLEL_NOT_SUPPORTED.
<p>There may be a limit on the number of concurrent sessions an application may have with
the token, which may depend on whether the session is "read-only" or "read/write".  An
attempt to open a session which does not succeed because there are too many existing
sessions of some type should return CKR_SESSION_COUNT.
If the token is write-protected (as indicated in the CK_TOKEN_INFO structure), then
only read-only sessions may be opened with it.
<p>If the application calling C_OpenSession already has a R/W SO session open with the
token, then any attempt to open a R/O session with the token fails with error code
CKR_SESSION_READ_WRITE_SO_EXISTS (see Section 6.7.7).
The  Notify callback function is used by Cryptoki  to notify the application of certain
events.  If the application does not wish  to support callbacks, it should pass a value of
NULL_PTR as the  Notify parameter.  See Section 11.17 for more information about
application callbacks.
     * @param slotID the slot's ID
     * @param flags from CK_SESSION_INFO
     * @param application passed to callback
     * @param notify callback function
     * @param phSession gets session handle
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#SESSION_COUNT}, {@link CKR#SESSION_PARALLEL_NOT_SUPPORTED},
{@link CKR#SESSION_READ_WRITE_SO_EXISTS}, {@link CKR#SLOT_ID_INVALID},
{@link CKR#TOKEN_NOT_PRESENT}, {@link CKR#TOKEN_NOT_RECOGNIZED},
{@link CKR#TOKEN_WRITE_PROTECTED}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef phSession);

    /**
C_CloseSession closes a session between an application and a token.   hSession is the
session's handle.
When a session is closed, all session objects created by the session are destroyed
automatically, even if the application has other sessions "using" the objects (see Sections
6.7.5-6.7.7 for more details).
<p>If this function is successful and it closes the last session between the application and the
token, the login state of the token for the application returns to public sessions. Any new
sessions to the token opened by the application will be either R/O Public or R/W Public
sessions.
<p>Depending on the token, when the last open session any application has with the token is
closed, the token may be "ejected" from its reader (if this capability exists).
Despite the fact this C_CloseSession is supposed to close a session, the return value
CKR_SESSION_CLOSED is an  error return.  It actually indicates the (probably
somewhat unlikely) event that while this function call was executing, another call was
made to C_CloseSession to close this particular session, and that call finished executing
first.  Such uses of sessions are a bad idea, and Cryptoki makes little promise of what will
occur in general if an application indulges in this sort of behavior.
     * @param hSession the session's handle
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID}.
     */
    long C_CloseSession(long hSession);

    /**
C_CloseAllSessions closes all sessions an application has with a token. slotID specifies
the token's slot.
<p>When a session is closed, all session objects created by the session are destroyed
automatically.
<p>After successful execution of this function, the login state of the token for the application
returns to public sessions. Any new sessions to the token opened by the application will
be either R/O Public or R/W Public sessions.
<p>Depending on the token, when the last open session any application has with the token is
closed, the token may be "ejected" from its reader (if this capability exists).
     * @param slotID the token's slot
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#SLOT_ID_INVALID}, {@link CKR#TOKEN_NOT_PRESENT}
     */
    long C_CloseAllSessions(long slotID);

    /**
C_GetSessionInfo obtains information about a session.  hSession is the session's handle;
pInfo points to the location that receives the session information.
     * @param hSession the session's handle
     * @param pInfo received session info
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#ARGUMENTS_BAD}
     */
    long C_GetSessionInfo(long hSession, CK_SESSION_INFO pInfo);

    /**
C_GetOperationState obtains a copy of the cryptographic operations state of a session,
encoded as a string of bytes.  hSession is the session's handle; pOperationState points to
the location that receives the state;  pulOperationStateLen points to the location that
receives the length in bytes of the state.
<p>Although the saved state output by C_GetOperationState is not really produced by a
"cryptographic mechanism",  C_GetOperationState nonetheless uses the convention
described in Section 11.2 on producing output.
Precisely what the "cryptographic operations state" this function saves is varies from
token to token; however, this state is what is provided as input to C_SetOperationState
to restore the cryptographic activities of a session.
<p>Consider a session which is performing a message digest operation using SHA-1 (i.e., the
session is using the  CKM_SHA_1 mechanism).  Suppose that the message digest
operation was initialized properly, and that precisely 80 bytes of data have been supplied
so far as input to SHA-1.  The application now wants to "save the state" of this digest
operation, so that it can continue it later.  In this particular case, since SHA-1 processes
512 bits (64 bytes) of input at a time, the cryptographic operations state of the session
most likely consists of three distinct parts: the state of SHA-1's 160-bit internal chaining
variable; the 16 bytes of unprocessed input data; and some administrative data indicating
that this saved state comes from a session which was performing SHA-1 hashing.  Taken
together, these three pieces of information suffice to continue the current hashing
operation at a later time.
<p>Consider next a session which is performing an encryption operation with DES (a block
cipher with a block size of 64 bits) in CBC (cipher-block chaining) mode (i.e., the session
is using the CKM_DES_CBC mechanism).  Suppose that precisely 22 bytes of data (in
addition to an IV for the CBC mode) have been supplied so far as input to DES, which
means that the first two 8-byte blocks of  ciphertext have already been produced and
output.  In this case, the cryptographic operations state of the session most likely consists
of three or four distinct parts: the second 8-byte block of ciphertext (this will be used for
cipher-block chaining to produce the next block of ciphertext); the 6 bytes of data still
awaiting encryption; some administrative data indicating that this saved state comes from
a session which was performing DES encryption in CBC mode; and possibly the DES
key being used for encryption (see  C_SetOperationState for more information on
whether or not the key is present in the saved state).
<p>If a session is performing two cryptographic operations simultaneously (see Section
11.13), then the cryptographic operations state of the session will contain all the
necessary information to restore both operations.
An attempt to save the cryptographic operations state of a session which does not
currently have some active savable cryptographic operation(s) (encryption, decryption,
digesting, signing without message recovery, verification without message recovery, or
some legal combination of two of these) should fail with the error
CKR_OPERATION_NOT_INITIALIZED.
<p>An attempt to save the cryptographic operations state of a session which is performing an
appropriate cryptographic operation (or two),  but which cannot be satisfied for any of
various reasons (certain necessary state information and/or key information can't leave
the token, for example) should fail with the error CKR_STATE_UNSAVEABLE.
     * @param hSession the session's handle
     * @param pOperationState gets state
     * @param pulOperationStateLen gets state length
     * @return {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#STATE_UNSAVEABLE}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_GetOperationState(long hSession, byte[] pOperationState, LongRef pulOperationStateLen);

    /**
C_SetOperationState restores the cryptographic operations state of a session from a
string of bytes obtained with C_GetOperationState.  hSession is the session's handle;
pOperationState points to the location  holding the saved state;  ulOperationStateLen
holds the length of the saved state; hEncryptionKey holds a handle to the key which will
be used for an ongoing encryption or decryption operation in the restored session (or 0 if
no encryption or decryption key is needed, either because no such operation is ongoing in
the stored session or because all the necessary key information is present in the saved
state); hAuthenticationKey holds a handle to the key which will be used for an ongoing
signature, MACing, or verification operation in the restored session (or 0 if no such key
is needed, either because no such operation is ongoing in the stored session or because all
the necessary key information is present in the saved state).
<p>The state need not have been obtained from the same session (the "source session") as it
is being restored to (the "destination  session").  However, the source session and
destination session should have a common session state (e.g.,
CKS_RW_USER_FUNCTIONS), and should be with a common token.  There is also no
guarantee that cryptographic operations state  may be carried across logins, or across
different Cryptoki implementations.
<p>If C_SetOperationState is supplied with alleged saved cryptographic operations state
which it can determine is not valid saved state (or is cryptographic operations state from
a session with a different session state, or is cryptographic operations state from a
different token), it fails with the error CKR_SAVED_STATE_INVALID.
Saved state obtained from calls to  C_GetOperationState may or may not contain
information about keys in use for ongoing cryptographic operations.  If a saved
cryptographic operations state has an ongoing encryption or decryption operation, and the
key in use for the operation is not saved in the state, then it must be supplied to
C_SetOperationState in the  hEncryptionKey argument.  If it is not, then
C_SetOperationState will fail and return the error CKR_KEY_NEEDED.  If the key in
use for the operation is saved in the state, then it can be supplied in the hEncryptionKey
argument, but this is not required.
<p>Similarly, if a saved cryptographic operations state has an ongoing signature, MACing,
or verification operation, and the key in use for the operation is not saved in the state,
then it must be supplied to C_SetOperationState in the hAuthenticationKey argument.
If it is not, then C_SetOperationState will fail with the error CKR_KEY_NEEDED.  If
the key in use for the operation  is saved in the state, then it  can be supplied in the
hAuthenticationKey argument, but this is not required.
If an irrelevant key is supplied to C_SetOperationState call (e.g., a nonzero key handle
is submitted in the  hEncryptionKey argument, but the saved cryptographic operations
state supplied does not have an ongoing encryption or decryption operation, then
C_SetOperationState fails with the error CKR_KEY_NOT_NEEDED.
<p>If a key is supplied as an argument to C_SetOperationState, and C_SetOperationState
can somehow detect that this key was not the key being used in the source session for the
supplied cryptographic operations state (it may be able to detect this if the key or a hash
of the key is present in the saved state, for example), then C_SetOperationState fails
with the error CKR_KEY_CHANGED.
<p>An application can look at the  CKF_RESTORE_KEY_NOT_NEEDED flag in the
flags field of the CK_TOKEN_INFO field for a token to determine whether or not it
needs to supply key handles to C_SetOperationState calls.  If this flag is true, then a call
to C_SetOperationState never needs a key handle to be supplied to it.  If this flag is
false, then at least some of the time, C_SetOperationState requires a key handle, and so
the application should probably always pass in any relevant key handles when restoring
cryptographic operations state to a session.
<p>C_SetOperationState can successfully restore cryptographic operations state to a
session even if that session has active cryptographic or object search operations when
C_SetOperationState is called (the ongoing operations are abruptly cancelled).
     * @param hSession the session's handle
     * @param pOperationState holds state
     * @param ulOperationStateLen holds state length
     * @param hEncryptionKey en/decryption key
     * @param hAuthenticationKey sign/verify key
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#KEY_CHANGED},
{@link CKR#KEY_NEEDED}, {@link CKR#KEY_NOT_NEEDED}, {@link CKR#OK},
{@link CKR#SAVED_STATE_INVALID}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#ARGUMENTS_BAD}
     */
    long C_SetOperationState(long hSession, byte[] pOperationState, long ulOperationStateLen, long hEncryptionKey, long hAuthenticationKey);

    /**
C_Login logs a user into a token.  hSession is a session handle; userType is the user type;
pPin points to the user's PIN; ulPinLen is the length of the PIN. This standard allows
PIN values to contain any valid UTF8 character, but the token may impose subset
restrictions.
<p>When the user type is either CKU_SO or CKU_USER, if the call succeeds, each of the
application's sessions will enter either the  "R/W SO Functions" state, the "R/W User
Functions" state, or the "R/O User Functions" state. If the user type is
CKU_CONTEXT_SPECIFIC , the behavior of C_Login depends on the context in which
it is called. Improper use of this user  type will result in a return value
CKR_OPERATION_NOT_INITIALIZED..
<p>If the token has a "protected authentication path", as indicated by the
CKF_PROTECTED_AUTHENTICATION_PATH flag in its  CK_TOKEN_INFO
being set, then that means that there is some way for a user to be authenticated to the
token without having the application send a PIN through the Cryptoki library.  One such
possibility is that the user enters a PIN on  a PINpad on the token itself, or on the slot
device.  Or the user might not even use a PIN'authentication could be achieved by some
fingerprint-reading device, for example.   To log into a token with a protected
authentication path, the  pPin parameter to  C_Login should be NULL_PTR.  When
C_Login returns, whatever authentication method supported by the token will have been
performed; a return value of CKR_OK  means that the user was successfully
authenticated, and a return value of CKR_PIN_INCORRECT means that the user was
denied access.
<p>If there are any active cryptographic or object finding operations in an application's
session, and then C_Login is successfully executed by that application, it may or may not
be the case that those operations are still active.  Therefore, before logging in, any active
operations should be finished.
<p>If the application calling C_Login has a R/O session open with the token, then it will be
unable to log the SO into a session (see Section 6.7.7).  An attempt to do this will result
in the error code CKR_SESSION_READ_ONLY_EXISTS.
<p>C_Login may be called repeatedly, without intervening C_Logout calls, if (and only if) a
key with the CKA_ALWAYS_AUTHENTICATE attribute set to CK_TRUE exists, and
the user needs to do cryptographic operation on this key. See further Section 10.9.
     * @param hSession the session's handle
     * @param userType the user type
     * @param pPin the user's PIN
     * @param ulPinLen the length of the PIN
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#PIN_INCORRECT},
{@link CKR#PIN_LOCKED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SESSION_READ_ONLY_EXISTS},
{@link CKR#USER_ALREADY_LOGGED_IN},
{@link CKR#USER_ANOTHER_ALREADY_LOGGED_IN},
{@link CKR#USER_PIN_NOT_INITIALIZED}, {@link CKR#USER_TOO_MANY_TYPES},
{@link CKR#USER_TYPE_INVALID}
     */
    long C_Login(long hSession, long userType, byte[] pPin, long ulPinLen);

    /**
C_Logout logs a user out from a token.  hSession is the session's handle.
Depending on the current user type, if the call succeeds, each of the application's
sessions will enter either the "R/W Public  Session" state or the "R/O Public Session"
state.
<p>When C_Logout successfully executes, any of the application's handles to private
objects become invalid (even if a user is later logged back into the token, those handles
remain invalid).  In addition, all private  session objects from sessions belonging to the
application are destroyed.
<p>If there are any active cryptographic or object-finding operations in an application's
session, and then C_Logout is successfully executed by that application, it may or may
not be the case that those operations are still active.  Therefore, before logging out, any
active operations should be finished.
     * @param hSession the session's handle
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_Logout(long hSession);

    /**
C_CreateObject creates a new object. hSession is the session's handle; pTemplate points
to the object's template;  ulCount is the number of attributes in the template;  phObject
points to the location that receives the new object's handle.
<p>If a call to C_CreateObject cannot support the precise template supplied to it, it will fail
and return without creating any object.
<p>If  C_CreateObject is used to create a key object, the key object will have its
CKA_LOCAL attribute set to CK_FALSE. If that key object is a secret or private key
then the new key will have the  CKA_ALWAYS_SENSITIVE attribute set to
CK_FALSE, and the CKA_NEVER_EXTRACTABLE attribute set to CK_FALSE.
<p>Only session objects can be created during a read-only session.  Only public objects can
be created unless the normal user is logged in.
     * @param hSession the session's handle
     * @param pTemplate the objects's template
     * @param ulCount attributes in template
     * @param phObject gets new object's handle
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_READ_ONLY},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#ATTRIBUTE_VALUE_INVALID},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#DOMAIN_PARAMS_INVALID}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK}, {@link CKR#PIN_EXPIRED},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#SESSION_READ_ONLY}, {@link CKR#TEMPLATE_INCOMPLETE},
{@link CKR#TEMPLATE_INCONSISTENT}, {@link CKR#TOKEN_WRITE_PROTECTED},
{@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_CreateObject(long hSession, CKA[] pTemplate, long ulCount, LongRef phObject);

    /**
C_CopyObject copies an object, creating  a new object for the copy.   hSession is the
session's handle; hObject is the object's handle; pTemplate points to the template for the
new object; ulCount is the number of attributes in the template; phNewObject points to
the location that receives the handle for the copy of the object.
<p>The template may specify new values for any attributes of the object that can ordinarily
be modified (e.g., in the course of copying a secret key, a key's CKA_EXTRACTABLE
attribute may be changed from CK_TRUE to CK_FALSE, but not the other way around.
If this change is made, the new key's CKA_NEVER_EXTRACTABLE attribute will
have the value CK_FALSE.  Similarly, the template may specify that the new key's
CKA_SENSITIVE attribute be CK_TRUE; the new key will have the same value for its
CKA_ALWAYS_SENSITIVE attribute as the original key).  It may also specify new
values of the CKA_TOKEN and CKA_PRIVATE attributes (e.g., to copy a session
object to a token object).  If the template  specifies a value of an attribute which is
incompatible with other existing attributes of the object, the call fails with the return code
CKR_TEMPLATE_INCONSISTENT.
<p>If a call to C_CopyObject cannot support the precise template supplied to it, it will fail
and return without creating any object.
Only session objects can be created during a read-only session.  Only public objects can
be created unless the normal user is logged in.
     * @param hSession the session's handle
     * @param hObject
     * @param pTemplate template for new object
     * @param ulCount attributes in template
     * @param phNewObject receives handle of copy
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_READ_ONLY},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#ATTRIBUTE_VALUE_INVALID},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OBJECT_HANDLE_INVALID}, {@link CKR#OK}, {@link CKR#PIN_EXPIRED},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#SESSION_READ_ONLY}, {@link CKR#TEMPLATE_INCONSISTENT},
{@link CKR#TOKEN_WRITE_PROTECTED}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_CopyObject(long hSession, long hObject, CKA[] pTemplate, long ulCount, LongRef phNewObject);

    /**
C_DestroyObject destroys an object.  hSession is the session's handle;  and hObject is
the object's handle.
Only session objects can be destroyed during a read-only session.  Only public objects
can be destroyed unless the normal user is logged in.
     * @param hSession the session's handle
     * @param hObject the objects's handle
     * @return  {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OBJECT_HANDLE_INVALID}, {@link CKR#OK}, {@link CKR#PIN_EXPIRED},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#SESSION_READ_ONLY}, {@link CKR#TOKEN_WRITE_PROTECTED}
     */
    long C_DestroyObject(long hSession, long hObject);

    /**
C_GetObjectSize gets the size of an object in bytes.  hSession is the session's handle;
hObject is the object's handle; pulSize points to the location that receives the size in bytes
of the object.
<p>Cryptoki does not specify what the precise meaning of an object's size is.  Intuitively, it
is some measure of how much token memory the object takes up.  If an application
deletes (say) a private object of size S, it  might be reasonable to assume that the
ulFreePrivateMemory field of the token's CK_TOKEN_INFO structure increases by
approximately S.
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pulSize receives size of object
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#INFORMATION_SENSITIVE}, {@link CKR#OBJECT_HANDLE_INVALID}, {@link CKR#OK},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_GetObjectSize(long hSession, long hObject, LongRef pulSize);

    /**
C_GetAttributeValue obtains the value of one or more attributes of an object.  hSession
is the session's handle;  hObject is the object's handle;  pTemplate points to a template
that specifies which attribute values are to be obtained, and receives the attribute values;
ulCount is the number of attributes in the template.
<p>For each (type,  pValue,  ulValueLen) triple in the template,  C_GetAttributeValue
performs the following algorithm:
<ol>
<li>If the specified attribute (i.e., the attribute specified by the  type field) for the object
cannot be revealed because the object is sensitive or unextractable, then the
ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
CK_LONG, it holds -1).
<li>Otherwise, if the specified attribute for the object is invalid (the object does not
possess such an attribute), then the ulValueLen field in that triple is modified to hold
the value -1.
<li>Otherwise, if the pValue field has the value NULL_PTR, then the ulValueLen field is
modified to hold the exact length of the specified attribute for the object.
<li>Otherwise, if the length specified in ulValueLen is large enough to hold the value of
the specified attribute for the object, then  that attribute is copied into the buffer
located at pValue, and the ulValueLen field is modified to hold the exact length of the
attribute.
<li>Otherwise, the ulValueLen field is modified to hold the value -1.
If case 1 applies to any of the requested attributes, then the call should return the value
CKR_ATTRIBUTE_SENSITIVE.  If case 2 applies to any of the requested attributes,
then the call should return the value CKR_ATTRIBUTE_TYPE_INVALID.  If case 5
applies to any of the requested attributes, then the call should return the value
CKR_BUFFER_TOO_SMALL.  As usual, if more than one of these error codes is
applicable, Cryptoki may return any of them.  Only if none of them applies to any of the
requested attributes will CKR_OK be returned.
</ol>
<p>In the special case of an attribute whose value is an array of attributes, for example
CKA_WRAP_TEMPLATE, where it is passed in with pValue not NULL, then if the
pValue of elements within the array is NULL_PTR then the  ulValueLen of elements
within the array will be set  to the required length. If the pValue of elements within the
array is not NULL_PTR, then the ulValueLen element of attributes within the array must
reflect the space that the corresponding pValue points to, and pValue is filled in if there is
sufficient room. Therefore it is important to initialize the contents of a buffer before
calling C_GetAttributeValue to get such an array value. If any ulValueLen within the
array isn't large enough, it will be set to '1 and the function will return
CKR_BUFFER_TOO_SMALL, as it does if an attribute in the pTemplate argument has
ulValueLen too small. Note that any attribute whose value is an array of attributes is
identifiable by virtue of the attribute  type having the CKF_ARRAY_ATTRIBUTE bit
set.
<p>Note that the error codes CKR_ATTRIBUTE_SENSITIVE,
CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL  do not
denote true errors for C_GetAttributeValue.  If a call to C_GetAttributeValue returns
any of these three values, then the call must nonetheless have processed every attribute in
the template supplied to C_GetAttributeValue.  Each attribute in the template whose
value can be returned by the call to C_GetAttributeValue will be returned by the call to
C_GetAttributeValue.
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pTemplate specifies attrs; gets vals
     * @param ulCount attributes in template
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_SENSITIVE},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OBJECT_HANDLE_INVALID}, {@link CKR#OK}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_GetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount);

    /**
C_SetAttributeValue modifies the value of one or  more attributes of an object.
hSession is the session's handle;  hObject is the object's handle;  pTemplate points to a
template that specifies which attribute values are to be modified and their new values;
ulCount is the number of attributes in the template.
Only session objects can be modified during a read-only session.
<p>The template may specify new values for any attributes of the object that can be
modified.  If the template specifies a value  of an attribute which is incompatible with
other existing attributes of the object,  the call fails with the return code
CKR_TEMPLATE_INCONSISTENT.
<p>Not all attributes can be modified; see Section 9.7 for more details.
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pTemplate specifies attrs and values
     * @param ulCount attributes in template
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_READ_ONLY},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#ATTRIBUTE_VALUE_INVALID},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OBJECT_HANDLE_INVALID}, {@link CKR#OK}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SESSION_READ_ONLY},
{@link CKR#TEMPLATE_INCONSISTENT}, {@link CKR#TOKEN_WRITE_PROTECTED},
{@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_SetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount);

    /**
C_FindObjectsInit initializes a search for token and session objects that match a
template.  hSession is the session's handle;  pTemplate points to a search template that
specifies the attribute values to match; ulCount is the number of attributes in the search
template. The matching criterion is an exact byte-for-byte match with all attributes in the
template. To find all objects, set ulCount to 0.
<p>After calling C_FindObjectsInit, the application may call C_FindObjects one or more
times to obtain handles for objects matching the template, and then eventually call
C_FindObjectsFinal to finish the active search operation.  At most one search operation
may be active at a given time in a given session.
The object search operation will only find  objects that the session can view.  For
example, an object search in an "R/W Public Session" will not find any private objects
(even if one of the attributes in the search template specifies that the search is for private
objects).
<p>If a search operation is active, and objects are created or destroyed which fit the search
template for the active search operation, then those objects may or may not be found by
the search operation.  Note that this means that, under these circumstances, the search
operation may return invalid object handles.
<p>Even though  C_FindObjectsInit can return the values
CKR_ATTRIBUTE_TYPE_INVALID and  CKR_ATTRIBUTE_VALUE_INVALID, it
is not required to.  For example, if it is given a search template with nonexistent attributes
in it, it can return CKR_ATTRIBUTE_TYPE_INVALID, or it can initialize a search
operation which will match no objects and return CKR_OK.
     * @param hSession the session's handle
     * @param pTemplate attribute values to match
     * @param ulCount attrs in search template
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_TYPE_INVALID},
{@link CKR#ATTRIBUTE_VALUE_INVALID}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_FindObjectsInit(long hSession, CKA[] pTemplate, long ulCount);

    /**
C_FindObjects continues a search for token and session objects that match a template,
obtaining additional object handles. hSession is the session's handle; phObject points to
the location that receives the list (array) of additional object handles; ulMaxObjectCount
is the maximum number of object handles to be returned; pulObjectCount points to the
location that receives the actual number of object handles returned.
If there are no more objects matching the template, then the location that pulObjectCount
points to receives the value 0.
<p>The search must have been initialized with C_FindObjectsInit.
     * @param hSession the session's handle
     * @param phObject gets obj handles
     * @param ulMaxObjectCount max handles to get
     * @param pulObjectCount actual # returned
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_FindObjects(long hSession, long[] phObject, long ulMaxObjectCount, LongRef pulObjectCount);

    /**
C_FindObjectsFinal terminates a search for token and session objects.  hSession is the
session's handle.
     * @param hSession the session's handle
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_FindObjectsFinal(long hSession);

    /**
C_EncryptInit initializes an encryption operation.  hSession is the session's handle;
pMechanism points to the encryption mechanism; hKey is the handle of the encryption
key.
<p>The CKA_ENCRYPT attribute of the encryption key, which indicates whether the key
supports encryption, must be CK_TRUE.
After calling C_EncryptInit, the application can either call C_Encrypt to encrypt data
in a single part; or call  C_EncryptUpdate zero or more times, followed by
C_EncryptFinal, to encrypt data in multiple parts.  The encryption operation is active
until the application uses a call to C_Encrypt or C_EncryptFinal to actually obtain the
final piece of ciphertext.  To process additional data (in single or multiple parts), the
application must call C_EncryptInit again.
     * @param hSession the session's handle
     * @param pMechanism the encryption mechanism
     * @param hKey handle of encryption key
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_FUNCTION_NOT_PERMITTED}, {@link CKR#KEY_HANDLE_INVALID},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#KEY_TYPE_INCONSISTENT},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_EncryptInit(long hSession, CKM pMechanism, long hKey);

    /**
C_Encrypt encrypts single-part data. hSession is the session's handle; pData points to
the data;  ulDataLen is the length in bytes of the data;  pEncryptedData points to the
location that receives the encrypted data; pulEncryptedDataLen points to the location that
holds the length in bytes of the encrypted data.
<p>C_Encrypt uses the convention described in Section 11.2 on producing output.
The encryption operation must have been initialized with  C_EncryptInit.  A call to
C_Encrypt always terminates the active encryption operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the ciphertext.
<p>C_Encrypt can not be used to terminate a multi-part operation, and must be called after
C_EncryptInit without intervening C_EncryptUpdate calls.
<p>For some encryption mechanisms, the input plaintext data has certain length constraints
(either because the mechanism can only encrypt relatively short pieces of plaintext, or
because the mechanism's input data must consist of an integral number of blocks).  If
these constraints are not satisfied, then  C_Encrypt will fail with return code
CKR_DATA_LEN_RANGE.
<p>The plaintext and ciphertext can be in the same place,  i.e., it is OK if  pData and
pEncryptedData point to the same location.
For most mechanisms,  C_Encrypt is equivalent to a sequence of  C_EncryptUpdate
operations followed by C_EncryptFinal.
     * @param hSession the session's handle
     * @param pData the plaintext data
     * @param ulDataLen bytes of plaintext
     * @param pEncryptedData gets ciphertext
     * @param pulEncryptedDataLen gets c-text size
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_INVALID},
{@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY},
{@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_Encrypt(long hSession, byte[] pData, long ulDataLen, byte[] pEncryptedData, LongRef pulEncryptedDataLen);

    /**
C_EncryptUpdate continues a multiple-part encryption operation, processing another
data part. hSession is the session's handle; pPart points to the data part; ulPartLen is the
length of the data part; pEncryptedPart points to the location that receives the encrypted
data part; pulEncryptedPartLen points to the location that holds the length in bytes of the
encrypted data part.
<p>C_EncryptUpdate uses the convention described in Section 11.2 on producing output.
The encryption operation must have been initialized with C_EncryptInit.  This function
may be called any number of times in succession.  A call to C_EncryptUpdate which
results in an error other than CKR_BUFFER_TOO_SMALL terminates the current
encryption operation.
<p>The plaintext and ciphertext can be in the same place,  i.e., it is OK if  pPart and
pEncryptedPart point to the same location.
     * @param hSession the session's handle
     * @param pPart the plaintext data
     * @param ulPartLen plaintext data len
     * @param pEncryptedPart gets ciphertext
     * @param pulEncryptedPartLen gets c-text size
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_LEN_RANGE},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_EncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen);

    /**
C_EncryptFinal finishes a multiple-part encryption operation. hSession is the session's
handle;  pLastEncryptedPart points to the location that receives the last encrypted data
part, if any; pulLastEncryptedPartLen points to the location that holds the length of the
last encrypted data part.
<p>C_EncryptFinal uses the convention described in Section 11.2 on producing output.
The encryption operation must have been initialized with  C_EncryptInit.  A call to
C_EncryptFinal always terminates the active encryption operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the ciphertext.
<p>For some multi-part encryption mechanisms, the input plaintext data has certain length
constraints, because the mechanism's input data must consist of an integral number of
blocks.  If these constraints are not satisfied, then C_EncryptFinal will fail with return
code CKR_DATA_LEN_RANGE.
     * @param hSession the session's handle
     * @param pLastEncryptedPart last c-text
     * @param pulLastEncryptedPartLen gets last size
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_LEN_RANGE},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_EncryptFinal(long hSession, byte[] pLastEncryptedPart, LongRef pulLastEncryptedPartLen);

    /**
C_DecryptInit initializes a decryption operation.  hSession is the session's handle;
pMechanism points to the decryption mechanism; hKey is the handle of the decryption
key.
<p>The CKA_DECRYPT attribute of the decryption key, which indicates whether the key
supports decryption, must be CK_TRUE.
<p>After calling C_DecryptInit, the application can either call C_Decrypt to decrypt data
in a single part; or call  C_DecryptUpdate zero or more times, followed by
C_DecryptFinal, to decrypt data in multiple parts.  The decryption operation is active
until the application uses a call to C_Decrypt or C_DecryptFinal to actually obtain the
final piece of plaintext.  To process additional data (in single or multiple parts), the
application must call C_DecryptInit again
     * @param hSession the session's handle
     * @param pMechanism te decryption mechanism
     * @param hKey handle of decryption key
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_FUNCTION_NOT_PERMITTED}, {@link CKR#KEY_HANDLE_INVALID},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#KEY_TYPE_INCONSISTENT},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_DecryptInit(long hSession, CKM pMechanism, long hKey);

    /**
C_Decrypt decrypts encrypted data in a single part.  hSession is the session's handle;
pEncryptedData points to the encrypted data;  ulEncryptedDataLen is the length of the
encrypted data; pData points to the location that receives the recovered data; pulDataLen
points to the location that holds the length of the recovered data.
<p>C_Decrypt uses the convention described in Section 11.2 on producing output.
The decryption operation must have been initialized with  C_DecryptInit.  A call to
C_Decrypt always terminates the active decryption operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the plaintext.
<p>C_Decrypt can not be used to terminate a multi-part operation, and must be called after
C_DecryptInit without intervening C_DecryptUpdate calls.
The ciphertext and plaintext can be in the same place,  i.e., it is OK if pEncryptedData
and pData point to the same location.
<p>If the input ciphertext data cannot be decrypted because it has an inappropriate length,
then either CKR_ENCRYPTED_DATA_INVALID or
CKR_ENCRYPTED_DATA_LEN_RANGE may be returned.
For most mechanisms,  C_Decrypt is equivalent to a sequence of  C_DecryptUpdate
operations followed by C_DecryptFinal.
     * @param hSession the session's handle
     * @param pEncryptedData ciphertext
     * @param ulEncryptedDataLen ciphertext length
     * @param pData gets plaintext
     * @param pulDataLen gets p-text size
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#ENCRYPTED_DATA_INVALID}, {@link CKR#ENCRYPTED_DATA_LEN_RANGE},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_Decrypt(long hSession, byte[] pEncryptedData, long ulEncryptedDataLen, byte[] pData, LongRef pulDataLen);

    /**
C_DecryptUpdate continues a multiple-part decryption operation, processing another
encrypted data part.  hSession is the session's handle;  pEncryptedPart points to the
encrypted data part; ulEncryptedPartLen is the length of the encrypted data part; pPart
points to the location that receives the recovered data part;  pulPartLen points to the
location that holds the length of the recovered data part.
<p>C_DecryptUpdate uses the convention described in Section 11.2 on producing output.
The decryption operation must have been initialized with C_DecryptInit.  This function
may be called any number of times in succession.  A call to C_DecryptUpdate which
results in an error other than CKR_BUFFER_TOO_SMALL terminates the current
decryption operation.
<p>The ciphertext and plaintext can be in the same place, i.e., it is OK if pEncryptedPart and
pPart point to the same location.
     * @param hSession the session's handle
     * @param pEncryptedPart encrypted data
     * @param ulEncryptedPartLen input length
     * @param pData gets plaintext
     * @param pulDataLen gets p-text size
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#ENCRYPTED_DATA_INVALID}, {@link CKR#ENCRYPTED_DATA_LEN_RANGE},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_DecryptUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pData, LongRef pulDataLen);

    /**
C_DecryptFinal finishes a multiple-part decryption operation. hSession is the session's
handle; pLastPart points to the location that receives the last recovered data part, if any;
pulLastPartLen points to the location that holds the length of the last recovered data part.
C_DecryptFinal uses the convention described in Section 11.2 on producing output.
<p>The decryption operation must have been initialized with  C_DecryptInit.  A call to
C_DecryptFinal always terminates the active decryption operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the plaintext.
<p>If the input ciphertext data cannot be decrypted because it has an inappropriate length,
then either CKR_ENCRYPTED_DATA_INVALID or
CKR_ENCRYPTED_DATA_LEN_RANGE may be returned.
     * @param hSession the session's handle
     * @param pLastPart gets plaintext
     * @param pulLastPartLen gets p-text size
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#ENCRYPTED_DATA_INVALID}, {@link CKR#ENCRYPTED_DATA_LEN_RANGE},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_DecryptFinal(long hSession, byte[] pLastPart, LongRef pulLastPartLen);

    /**
C_DigestInit initializes a message-digesting operation. hSession is the session's handle;
pMechanism points to the digesting mechanism.
After calling C_DigestInit, the application can either call C_Digest to digest data in a
single part; or call C_DigestUpdate zero or more times, followed by C_DigestFinal, to
digest data in multiple parts.  The message-digesting operation is active until the
application uses a call to C_Digest or C_DigestFinal  to actually obtain the message
digest.  To process additional data (in single or multiple parts), the application must call
C_DigestInit again.

     * @param hSession the session's handle
     * @param pMechanism the digesting mechanism
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#MECHANISM_INVALID},
{@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK}, {@link CKR#OPERATION_ACTIVE},
{@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_DigestInit(long hSession, CKM pMechanism);

    /**
C_Digest digests data in a single part. hSession is the session's handle, pData points to
the data; ulDataLen is the length of the data; pDigest points to the location that receives
the message digest;  pulDigestLen points to the location that holds the length of the
message digest.
<p>C_Digest uses the convention described in Section 11.2 on producing output.
The digest operation must have been initialized with C_DigestInit.  A call to C_Digest
always terminates the active digest operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the message digest.
C_Digest  can not be used to terminate a multi-part operation, and must be called after
C_DigestInit without intervening C_DigestUpdate calls.
<p>The input data and digest output can be in the same place,  i.e., it is OK if  pData and
pDigest point to the same location.
<p>C_Digest is equivalent to a sequence of  C_DigestUpdate operations followed by
C_DigestFinal.
     * @param hSession the session's handle
     * @param pData data to be digested
     * @param ulDataLen bytes of data to digest
     * @param pDigest gets the message digest
     * @param pulDigestLen gets digest length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_Digest(long hSession, byte[] pData, long ulDataLen, byte[] pDigest, LongRef pulDigestLen);

    /**
C_DigestUpdate continues a multiple-part message-digesting operation, processing
another data part.  hSession is the session's handle,  pPart points to the data part;
ulPartLen is the length of the data part.
<p>The message-digesting operation must have been initialized with C_DigestInit. Calls to
this function and C_DigestKey may be interspersed any number of times in any order.  A
call to C_DigestUpdate which results in an error terminates the current digest operation.
     * @param hSession the session's handle
     * @param pPart data to be digested
     * @param ulPartLen bytes of data to be digested
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_DigestUpdate(long hSession, byte[] pPart, long ulPartLen);

    /**
C_DigestKey continues a multiple-part message-digesting operation by digesting the
value of a secret key.  hSession is the session's handle; hKey is the handle of the secret
key to be digested.
<p>The message-digesting operation must have been initialized with C_DigestInit.  Calls to
this function and  C_DigestUpdate may be interspersed any number of times in any
order.
<p>If the value of the supplied key cannot be digested purely for some reason related to its
length, C_DigestKey should return the error code CKR_KEY_SIZE_RANGE.
     * @param hSession the session's handle
     * @param hKey the secret key to digest
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_HANDLE_INVALID}, {@link CKR#KEY_INDIGESTIBLE},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_DigestKey(long hSession, long hKey);

    /**
C_DigestFinal finishes a multiple-part message-digesting operation, returning the
message digest.  hSession is the session's handle;  pDigest points to the location that
receives the message digest; pulDigestLen points to the location that holds the length of
the message digest.
<p>C_DigestFinal uses the convention described in Section 11.2 on producing output.
The digest operation must have been initialized with  C_DigestInit.  A call to
C_DigestFinal always terminates the active digest operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the message digest.
     * @param hSession the session's handle
     * @param pDigest gets the message digest
     * @param pulDigestLen gets byte count of digest
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_DigestFinal(long hSession, byte[] pDigest, LongRef pulDigestLen);

    /**
C_SignInit initializes a signature operation, where  the signature is an appendix to the
data. hSession is the session's handle; pMechanism points to the signature mechanism;
hKey is the handle of the signature key.
<p>The CKA_SIGN attribute of the signature key, which indicates whether the key supports
signatures with appendix, must be CK_TRUE.
<p>After calling C_SignInit, the application can either call C_Sign to sign in a single part;
or call  C_SignUpdate one or more times, followed by  C_SignFinal, to sign data in
multiple parts.  The signature operation is  active until the application uses a call to
C_Sign or C_SignFinal to actually obtain the signature.  To process additional data (in
single or multiple parts), the application must call C_SignInit again.
     * @param hSession the session's handle
     * @param pMechanism the signature mechanism
     * @param hKey handle of signature key
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_FUNCTION_NOT_PERMITTED}, {@link CKR#KEY_HANDLE_INVALID},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#KEY_TYPE_INCONSISTENT},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_SignInit(long hSession, CKM pMechanism, long hKey);

    /**
C_Sign signs data in a single part, where the  signature is an appendix to the data.
hSession is the session's handle; pData points to the data; ulDataLen is the length of the
data; pSignature points to the location that receives the signature; pulSignatureLen points
to the location that holds the length of the signature.
<p>C_Sign uses the convention described in Section 11.2 on producing output.
The signing operation must have been initialized with C_SignInit.  A call to C_Sign
always terminates the active signing operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the signature.
<p>C_Sign  can not be used to terminate a multi-part operation, and must be called after
C_SignInit without intervening C_SignUpdate calls.
<p>For most mechanisms, C_Sign is equivalent to a sequence of C_SignUpdate operations
followed by C_SignFinal.
     * @param hSession the session's handle
     * @param pData the data to sign
     * @param ulDataLen count of bytes to sign
     * @param pSignature gets the signature
     * @param pulSignatureLen gets signature length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_INVALID},
{@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY},
{@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN},
{@link CKR#FUNCTION_REJECTED}
     */
    long C_Sign(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen);

    /**
C_SignUpdate continues a multiple-part signature operation, processing another data
part.  hSession is the session's handle,  pPart points to the data part;  ulPartLen is the
length of the data part.
<p>The signature operation must have been initialized with C_SignInit. This function may
be called any number of times in succession.  A call to C_SignUpdate which results in
an error terminates the current signature operation.
     * @param hSession the session's handle
     * @param pPart the data to sign
     * @param ulPartLen count of bytes to sign
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY},
{@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_SignUpdate(long hSession, byte[] pPart, long ulPartLen);

    /**
C_SignFinal finishes a multiple-part signature operation, returning the signature.
hSession is the session's handle;  pSignature points to the location that receives the
signature; pulSignatureLen points to the location that holds the length of the signature.
<p>C_SignFinal uses the convention described in Section 11.2 on producing output.
The signing operation must have been initialized with  C_SignInit.  A call to
C_SignFinal always terminates the active signing operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the signature.
     * @param hSession the session's handle
     * @param pSignature gets the signature
     * @param pulSignatureLen gets signature length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_LEN_RANGE},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN},
{@link CKR#FUNCTION_REJECTED}
     */
    long C_SignFinal(long hSession, byte[] pSignature, LongRef pulSignatureLen);

    /**
C_SignRecoverInit initializes a signature operation, where the data can be recovered
from the signature. hSession is the session's handle; pMechanism points to the structure
that specifies the signature mechanism; hKey is the handle of the signature key.
The CKA_SIGN_RECOVER attribute of the signature key, which indicates whether the
key supports signatures where the data can be recovered from the signature, must be
CK_TRUE.
<p>After calling C_SignRecoverInit, the application may call C_SignRecover to sign in a
single part.  The signature operation is active until the application uses a call to
C_SignRecover  to actually obtain the signature.  To process additional data in a single
part, the application must call C_SignRecoverInit again.
     * @param hSession the session's handle
     * @param pMechanism the signature mechanism
     * @param hKey handle of the signature key
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_FUNCTION_NOT_PERMITTED}, {@link CKR#KEY_HANDLE_INVALID},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#KEY_TYPE_INCONSISTENT},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_SignRecoverInit(long hSession, CKM pMechanism, long hKey);

    /**
C_SignRecover signs data in a single operation, where the data can be recovered from
the signature. hSession is the session's handle; pData points to the data; uLDataLen is the
length of the data;  pSignature points to the location that receives the signature;
pulSignatureLen points to the location that holds the length of the signature.
<p>C_SignRecover uses the convention described in Section 11.2 on producing output.
The signing operation must have been initialized with C_SignRecoverInit.  A call to
C_SignRecover always terminates the active signing operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the signature.
     * @param hSession the session's handle
     * @param pData the data to sign
     * @param ulDataLen count of bytes to sign
     * @param pSignature gets the signature
     * @param pulSignatureLen gets signature length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_INVALID},
{@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY},
{@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_SignRecover(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen);

    /**
C_VerifyInit initializes a verification operation, where the signature is an appendix to
the data.  hSession is the session's handle;  pMechanism points to the structure that
specifies the verification mechanism; hKey is the handle of the verification key.
<p>The CKA_VERIFY attribute of the verification key, which indicates whether the key
supports verification where the signature is an appendix to the data, must be CK_TRUE.
After calling C_VerifyInit, the application can either call C_Verify to verify a signature
on data in a single part; or call  C_VerifyUpdate one or more times, followed by
C_VerifyFinal, to verify a signature on data in multiple parts.  The verification operation
is active until the application calls C_Verify or C_VerifyFinal. To process additional
data (in single or multiple parts), the application must call C_VerifyInit again.
     * @param hSession the session's handle
     * @param pMechanism the verification mechanism
     * @param hKey verification key
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_FUNCTION_NOT_PERMITTED}, {@link CKR#KEY_HANDLE_INVALID},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#KEY_TYPE_INCONSISTENT},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_VerifyInit(long hSession, CKM pMechanism, long hKey);

    /**
C_Verify verifies a signature in a single-part operation, where the signature is an
appendix to the data.  hSession is the session's handle;  pData points to the data;
ulDataLen is the length of the data; pSignature points to the signature; ulSignatureLen is
the length of the signature.
<p>The verification operation must have been initialized with  C_VerifyInit.  A call to
C_Verify always terminates the active verification operation.
A successful call to C_Verify should return either the value CKR_OK (indicating that
the supplied signature is valid) or CKR_SIGNATURE_INVALID (indicating that the
supplied signature is invalid).  If the signature can be seen to be invalid purely on the
basis of its length, then CKR_SIGNATURE_LEN_RANGE should be returned.  In any
of these cases, the active signing operation is terminated.
C_Verify can not be used to terminate a multi-part operation, and must be called after
C_VerifyInit without intervening C_VerifyUpdate calls.
<p>For most mechanisms,  C_Verify is equivalent to a sequence of  C_VerifyUpdate
operations followed by C_VerifyFinal.
     * @param hSession the session's handle
     * @param pData signed data
     * @param ulDataLen length of signed data
     * @param pSignature signature
     * @param ulSignatureLen signature length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DATA_INVALID}, {@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SIGNATURE_INVALID},
{@link CKR#SIGNATURE_LEN_RANGE}
     */
    long C_Verify(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, long ulSignatureLen);

    /**
C_VerifyUpdate continues a multiple-part verification operation, processing another
data part. hSession is the session's handle, pPart points to the data part; ulPartLen is the
length of the data part.
<p>The verification operation must have been initialized with C_VerifyInit. This function
may be called any number of times in succession.  A call to C_VerifyUpdate which
results in an error terminates the current verification operation.
     * @param hSession the session's handle
     * @param pPart signed data
     * @param ulPartLen length of signed data
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY},
{@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}

     */
    long C_VerifyUpdate(long hSession, byte[] pPart, long ulPartLen);

    /**
C_VerifyFinal finishes a multiple-part verification operation, checking the signature.
hSession is the session's handle; pSignature points to the signature; ulSignatureLen is the
length of the signature.
<p>The verification operation must have been initialized with  C_VerifyInit.  A call to
C_VerifyFinal always terminates the active verification operation.
A successful call to C_VerifyFinal should return either the value CKR_OK (indicating
that the supplied signature is valid) or CKR_SIGNATURE_INVALID (indicating that
the supplied signature is invalid).  If the signature can be seen to be invalid purely on the
basis of its length, then CKR_SIGNATURE_LEN_RANGE should be returned.  In any
of these cases, the active verifying operation is terminated.
     * @param hSession the session's handle
     * @param pSignature signature to verify
     * @param ulSignatureLen signature length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY},
{@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SIGNATURE_INVALID},
{@link CKR#SIGNATURE_LEN_RANGE}
     */
    long C_VerifyFinal(long hSession, byte[] pSignature, long ulSignatureLen);

    /**
C_VerifyRecoverInit initializes a signature verification operation, where the data is
recovered from the signature. hSession is the session's handle; pMechanism points to the
structure that specifies the verification mechanism; hKey is the handle of the verification
key.
<p>The CKA_VERIFY_RECOVER attribute of the verification key, which indicates
whether the key supports verification where the data is recovered from the signature,
must be CK_TRUE.
<p>After calling C_VerifyRecoverInit, the application may call C_VerifyRecover to verify
a signature on data in a single part.  The verification operation is active until the
application uses a call to C_VerifyRecover to actually obtain the recovered message.
     * @param hSession the session's handle
     * @param pMechanism the verification mechanism
     * @param hKey verification key
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_FUNCTION_NOT_PERMITTED}, {@link CKR#KEY_HANDLE_INVALID},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#KEY_TYPE_INCONSISTENT},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_VerifyRecoverInit(long hSession, CKM pMechanism, long hKey);

    /**
C_VerifyRecover verifies a signature in a single-part operation, where the data is
recovered from the signature. hSession is the session's handle; pSignature points to the
signature; ulSignatureLen is the length of the signature; pData points to the location that
receives the recovered data; and pulDataLen points to the location that holds the length
of the recovered data.
<p>C_VerifyRecover uses the convention described in Section 11.2 on producing output.
The verification operation must have been initialized with C_VerifyRecoverInit.  A call
to C_VerifyRecover always terminates the active verification operation unless it returns
CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
to determine the length of the buffer needed to hold the recovered data.
<p>A successful call to  C_VerifyRecover should return either the value CKR_OK
(indicating that the supplied signature is valid) or CKR_SIGNATURE_INVALID
(indicating that the supplied signature is invalid).  If the signature can be seen to be
invalid purely on the basis of its length, then CKR_SIGNATURE_LEN_RANGE should
be returned.  The return codes CKR_SIGNATURE_INVALID and
CKR_SIGNATURE_LEN_RANGE have a higher priority than the return code
CKR_BUFFER_TOO_SMALL,  i.e., if  C_VerifyRecover is supplied with an invalid
signature, it will never return CKR_BUFFER_TOO_SMALL.
     * @param hSession the session's handle
     * @param pSignature signature to verify
     * @param ulSignatureLen signature length
     * @param pData gets signed data
     * @param pulDataLen gets signed data len
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_INVALID},
{@link CKR#DATA_LEN_RANGE}, {@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY},
{@link CKR#DEVICE_REMOVED}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#OK}, {@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SIGNATURE_LEN_RANGE},
{@link CKR#SIGNATURE_INVALID}
     */
    long C_VerifyRecover(long hSession, byte[] pSignature, long ulSignatureLen, byte[] pData, LongRef pulDataLen);

    /**
C_DigestEncryptUpdate continues multiple-part digest and encryption operations,
processing another data part. hSession is the session's handle; pPart points to the data
part; ulPartLen is the length of the data part; pEncryptedPart points to the location that
receives the digested and encrypted data part; pulEncryptedPartLen points to the location
that holds the length of the encrypted data part.
<p>C_DigestEncryptUpdate uses the convention described in Section 11.2 on producing
output.  If a C_DigestEncryptUpdate call does not produce encrypted output (because
an error occurs, or because  pEncryptedPart has the value NULL_PTR, or because
pulEncryptedPartLen is too small to hold the entire encrypted part output), then no
plaintext is passed to the active digest operation.
<p>Digest and encryption operations must both be active (they must have been initialized
with C_DigestInit and C_EncryptInit, respectively).  This function may be called any
number of times in succession, and may be interspersed with  C_DigestUpdate,
C_DigestKey, and  C_EncryptUpdate calls (it would be somewhat unusual to
intersperse calls to C_DigestEncryptUpdate with calls to C_DigestKey, however).
     * @param hSession the session's handle
     * @param pPart the plaintext data
     * @param ulPartLen plaintet length
     * @param pEncryptedPart gets ciphertext
     * @param pulEncryptedPartLen gets c-text length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_LEN_RANGE},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_DigestEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen);

    /**
 C_DecryptDigestUpdate continues a multiple-part combined decryption and digest
operation, processing another data part. hSession is the session's handle; pEncryptedPart
points to the encrypted data part; ulEncryptedPartLen is the length of the encrypted data
part; pPart points to the location that receives the recovered data part; pulPartLen points
to the location that holds the length of the recovered data part.
<p>C_DecryptDigestUpdate uses the convention described in Section 11.2 on producing
output. If a C_DecryptDigestUpdate call does not produce decrypted output (because an
error occurs, or because pPart has the value NULL_PTR, or because pulPartLen is too
small to hold the entire decrypted part output), then no plaintext is passed to the active
digest operation.
<p>Decryption and digesting operations must both be active (they must have been initialized
with C_DecryptInit and C_DigestInit, respectively).  This function may be called any
number of times in succession, and may be interspersed with  C_DecryptUpdate,
C_DigestUpdate, and C_DigestKey calls (it would be somewhat unusual to intersperse
calls to C_DigestEncryptUpdate with calls to C_DigestKey, however).
<p>Use of C_DecryptDigestUpdate involves a pipelining issue that does not arise when
using  C_DigestEncryptUpdate, the "inverse function" of  C_DecryptDigestUpdate.
This is because when  C_DigestEncryptUpdate is called, precisely the same input is
passed to both the active digesting operation and the active encryption operation;
however, when  C_DecryptDigestUpdate is called, the input passed to the active
digesting operation is the output of the active decryption operation.  This issue comes up
only when the mechanism used for decryption performs padding.
<p>In particular, envision a 24-byte ciphertext which was obtained by encrypting an 18-byte
plaintext with DES in CBC mode with PKCS padding.  Consider an application which
will simultaneously decrypt this ciphertext and digest the original plaintext thereby
obtained.
<p>After initializing decryption and digesting operations, the application passes the 24-byte
ciphertext (3 DES blocks) into  C_DecryptDigestUpdate.   C_DecryptDigestUpdate
returns exactly 16 bytes of plaintext, since at this point, Cryptoki doesn't know if there's
more ciphertext coming, or if the last block of ciphertext held any padding.  These 16
bytes of plaintext are passed into the active digesting operation.
<p>Since there is no more ciphertext, the application calls  C_DecryptFinal.  This tells
Cryptoki that there's no more ciphertext coming, and the call returns the last 2 bytes of
plaintext.  However, since the active decryption and digesting operations are linked only
through the C_DecryptDigestUpdate call, these 2 bytes of plaintext are not passed on to
be digested.
<p>A call to C_DigestFinal, therefore, would compute the message digest of  the first 16
bytes of the plaintext, not the message digest of the entire plaintext.  It is crucial that,
before C_DigestFinal is called, the last 2 bytes of plaintext get passed into the active
digesting operation via a C_DigestUpdate call.
<p>Because of this, it is critical that when an application uses a padded decryption
mechanism with  C_DecryptDigestUpdate, it knows exactly how much plaintext has
been passed into the active digesting operation.   Extreme caution is warranted when
using a padded decryption mechanism with C_DecryptDigestUpdate.
     * @param hSession the session's handle
     * @param pEncryptedPart ciphertext
     * @param ulEncryptedPartLen ciphertext length
     * @param pPart gets plaintext
     * @param pulPartLen gets plaintext length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#ENCRYPTED_DATA_INVALID}, {@link CKR#ENCRYPTED_DATA_LEN_RANGE},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_DecryptDigestUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen);

    /**
C_SignEncryptUpdate continues a multiple-part combined signature and encryption
operation, processing another data part. hSession is the session's handle; pPart points to
the data part;  ulPartLen is the length of the data part;  pEncryptedPart points to the
location that receives the digested and encrypted data part; and pulEncryptedPart points
to the location that holds the length of the encrypted data part.
<p>C_SignEncryptUpdate uses the convention described in Section 11.2 on producing
output.  If a C_SignEncryptUpdate call does not produce encrypted output (because an
error occurs, or because  pEncryptedPart has the value NULL_PTR, or because
pulEncryptedPartLen is too small to hold the entire encrypted part output), then no
plaintext is passed to the active signing operation.
<p>Signature and encryption operations must both be active (they must have been initialized
with C_SignInit and C_EncryptInit, respectively).  This function may be called any
number of times in succession, and may be interspersed with  C_SignUpdate and
C_EncryptUpdate calls.
     * @param hSession the session's handle
     * @param pPart the plaintext data
     * @param ulPartLen plaintext length
     * @param pEncryptedPart gets ciphertext
     * @param pulEncryptedPartLen gets c-text length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_LEN_RANGE},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_SignEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen);

    /**
C_DecryptVerifyUpdate continues a multiple-part combined decryption and
verification operation, processing another data part.  hSession is the session's handle;
pEncryptedPart points to the encrypted data;  ulEncryptedPartLen is the length of the
encrypted data;  pPart points to the location that receives the recovered data; and
pulPartLen points to the location that holds the length of the recovered data.
<p>C_DecryptVerifyUpdate uses the convention described in Section 11.2 on producing
output.  If a C_DecryptVerifyUpdate call does not produce decrypted output (because
an error occurs, or because pPart has the value NULL_PTR, or because pulPartLen is
too small to hold the entire encrypted part  output), then no plaintext is passed to the
active verification operation.
<p>Decryption and signature operations must both be active (they must have been initialized
with C_DecryptInit and C_VerifyInit, respectively).  This function may be called any
number of times in succession, and may be interspersed with C_DecryptUpdate and
C_VerifyUpdate calls.
<p>Use of C_DecryptVerifyUpdate involves a pipelining issue that does not arise when
using C_SignEncryptUpdate, the "inverse function" of C_DecryptVerifyUpdate.  This
is because when C_SignEncryptUpdate is called, precisely the same input is passed to
both the active signing operation and the active encryption operation; however, when
C_DecryptVerifyUpdate is called, the input passed to  the active verifying operation is
the  output of the active decryption operation.  This issue comes up only when the
mechanism used for decryption performs padding.
<p>In particular, envision a 24-byte ciphertext which was obtained by encrypting an 18-byte
plaintext with DES in CBC mode with PKCS padding.  Consider an application which
will simultaneously decrypt this ciphertext and verify a signature on the original plaintext
thereby obtained.
<p>After initializing decryption and verification operations, the application passes the 24-
byte ciphertext (3 DES blocks) into  C_DecryptVerifyUpdate.
<p>C_DecryptVerifyUpdate returns exactly 16 bytes of plaintext, since at this point,
Cryptoki doesn't know if there's more ciphertext coming, or if the last block of
ciphertext held any padding.  These 16 bytes  of plaintext are passed into the active
verification operation.
<p>Since there is no more ciphertext, the application calls  C_DecryptFinal.  This tells
Cryptoki that there's no more ciphertext coming, and the call returns the last 2 bytes of
plaintext.  However, since the active decryption and verification operations are linked
only through the C_DecryptVerifyUpdate call, these 2 bytes of plaintext are not passed
on to the verification mechanism.
<p>A call to C_VerifyFinal, therefore, would verify whether or not the signature supplied is
a valid signature on  the first 16 bytes of the plaintext, not on the entire plaintext.  It is
crucial that, before C_VerifyFinal is called, the last 2 bytes of plaintext get passed into
the active verification operation via a C_VerifyUpdate call.
<p>Because of this, it is critical that when an application uses a padded decryption
mechanism with  C_DecryptVerifyUpdate, it knows exactly how much plaintext has
been passed into the active verification operation.  Extreme caution is warranted when
using a padded decryption mechanism with C_DecryptVerifyUpdate.
     * @param hSession the session's handle
     * @param pEncryptedPart ciphertext
     * @param ulEncryptedPartLen ciphertext length
     * @param pPart gets plaintext
     * @param pulPartLen gets p-text length
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DATA_LEN_RANGE},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#ENCRYPTED_DATA_INVALID}, {@link CKR#ENCRYPTED_DATA_LEN_RANGE},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_NOT_INITIALIZED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}
     */
    long C_DecryptVerifyUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen);

    /**
C_GenerateKey generates a secret key or set of domain parameters, creating a new
object.  hSession is the session's handle;  pMechanism points to the generation
mechanism;  pTemplate points to the template for  the new key or set of domain
parameters;  ulCount is the number of attributes in the template;  phKey points to the
location that receives the handle of the new key or set of domain parameters.
If the generation mechanism is for domain parameter generation, the  CKA_CLASS
attribute will have the value CKO_DOMAIN_PARAMETERS; otherwise, it will have
the value CKO_SECRET_KEY.
<p>Since the type of key or domain parameters to be generated is implicit in the generation
mechanism, the template does not need to supply a key type.  If it does supply a key type
which is inconsistent with the generation mechanism, C_GenerateKey fails and returns
the error code CKR_TEMPLATE_INCONSISTENT.  The CKA_CLASS attribute is
treated similarly.
<p>If a call to C_GenerateKey cannot support the precise template supplied to it, it will fail
and return without creating an object.
<p>The object created by a successful call to C_GenerateKey will have its CKA_LOCAL
attribute set to CK_TRUE.
     * @param hSession the session's handle
     * @param pMechanism key generation mec.
     * @param pTemplate template for new key
     * @param ulCount # of attrs in template
     * @param phKey gets handle of new key
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_READ_ONLY},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#ATTRIBUTE_VALUE_INVALID},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#MECHANISM_INVALID},
{@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK}, {@link CKR#OPERATION_ACTIVE},
{@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SESSION_READ_ONLY},
{@link CKR#TEMPLATE_INCOMPLETE}, {@link CKR#TEMPLATE_INCONSISTENT},
{@link CKR#TOKEN_WRITE_PROTECTED}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_GenerateKey(long hSession, CKM pMechanism, CKA[] pTemplate, long ulCount, LongRef phKey);

    /**
C_GenerateKeyPair generates a public/private key  pair, creating new key objects.
hSession is the session's handle; pMechanism points to the key generation mechanism;
pPublicKeyTemplate points to the template for the public key;
ulPublicKeyAttributeCount is the number of attributes in the public-key template;
pPrivateKeyTemplate points to the template for the private key;
ulPrivateKeyAttributeCount is the number of attributes in the private-key template;
phPublicKey points to the location that receives the handle of the new public key;
phPrivateKey points to the location that receives the handle of the new private key.
<p>Since the types of keys to be generated are implicit in the key pair generation mechanism,
the templates do not need to supply key types.  If one of the templates does supply a key
type which is inconsistent with the key generation mechanism,  C_GenerateKeyPair
fails and returns the error code CKR_TEMPLATE_INCONSISTENT.  The
CKA_CLASS attribute is treated similarly.
<p>If a call to C_GenerateKeyPair cannot support the precise templates supplied to it, it
will fail and return without creating any key objects.
<p>A call to C_GenerateKeyPair will never create just one key and return.  A call can fail,
and create no keys; or it can succeed, and create a matching public/private key pair.
The key objects created by a successful call to  C_GenerateKeyPair will have their
CKA_LOCAL attributes set to CK_TRUE.
<p>Note carefully the order of the arguments to  C_GenerateKeyPair.  The last two
arguments do not have the same order as they did in the original Cryptoki Version 1.0
document.  The order of these two arguments has caused some unfortunate confusion.
     * @param hSession the session's handle
     * @param pMechanism key-gen mech.
     * @param pPublicKeyTemplate template for pub. key
     * @param ulPublicKeyAttributeCount # pub attrs.
     * @param pPrivateKeyTemplate template for priv. key
     * @param ulPrivateKeyAttributeCount # priv. attrs.
     * @param phPublicKey gets pub key handle
     * @param phPrivateKey gets priv key handle
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_READ_ONLY},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#ATTRIBUTE_VALUE_INVALID},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#DOMAIN_PARAMS_INVALID}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SESSION_READ_ONLY},
{@link CKR#TEMPLATE_INCOMPLETE}, {@link CKR#TEMPLATE_INCONSISTENT},
{@link CKR#TOKEN_WRITE_PROTECTED}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_GenerateKeyPair(long hSession, CKM pMechanism, CKA[] pPublicKeyTemplate, long ulPublicKeyAttributeCount, CKA[] pPrivateKeyTemplate, long ulPrivateKeyAttributeCount, LongRef phPublicKey, LongRef phPrivateKey);

    /**
C_WrapKey wraps (i.e., encrypts) a private or secret key.  hSession is the session's
handle; pMechanism points to the wrapping mechanism; hWrappingKey is the handle of
the wrapping key; hKey is the handle of the key to be wrapped; pWrappedKey points to
the location that receives the wrapped key; and pulWrappedKeyLen points to the location
that receives the length of the wrapped key.
<p>C_WrapKey uses the convention described in Section 11.2 on producing output.
The  CKA_WRAP attribute of the wrapping key,  which indicates whether the key
supports wrapping, must be CK_TRUE.  The CKA_EXTRACTABLE attribute of the
key to be wrapped must also be CK_TRUE.
<p>If the key to be wrapped cannot be wrapped for some token-specific reason, despite its
having its CKA_EXTRACTABLE attribute set to CK_TRUE, then C_WrapKey fails
with error code CKR_KEY_NOT_WRAPPABLE.  If it cannot be wrapped with the
specified wrapping key and mechanism solely because of its length, then C_WrapKey
fails with error code CKR_KEY_SIZE_RANGE.
<p>C_WrapKey can be used in the following situations:
<ul>
<li>To wrap any secret key with a public key that supports encryption and decryption.
<li>To wrap any secret key with any other secret key. Consideration must be given to key
size and mechanism strength or the token may not allow the operation.
<li>To wrap a private key with any secret key.
</ul>
<p>Of course, tokens vary in which types of keys can actually be wrapped with which
mechanisms.
<p>To partition the wrapping keys so they can only wrap a subset of extractable keys the
attribute CKA_WRAP_TEMPLATE can be used on the wrapping key to specify an
attribute set that will be compared against the attributes of the key to be wrapped. If all
attributes match according to the C_FindObject rules of attribute matching then the wrap
will proceed. The value of this attribute is an attribute template and the size is the number
of items in the template times the size of CK_ATTRIBUTE. If this attribute is not
supplied then any template is acceptable. Attributes not present are not checked. If any
attribute mismatch occurs on an attempt to wrap a key then the function shall return
CKR_KEY_HANDLE_INVALID.
     * @param hSession the session's handle
     * @param pMechanism the wrapping mechanism
     * @param hWrappingKey wrapping key
     * @param hKey key to be wrapped
     * @param pWrappedKey gets wrapped key
     * @param pulWrappedKeyLen gets wrapped key size
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#BUFFER_TOO_SMALL},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_HANDLE_INVALID}, {@link CKR#KEY_NOT_WRAPPABLE},
{@link CKR#KEY_SIZE_RANGE}, {@link CKR#KEY_UNEXTRACTABLE},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN},
{@link CKR#WRAPPING_KEY_HANDLE_INVALID},
{@link CKR#WRAPPING_KEY_SIZE_RANGE},
{@link CKR#WRAPPING_KEY_TYPE_INCONSISTENT}
     */
    long C_WrapKey(long hSession, CKM pMechanism, long hWrappingKey, long hKey, byte[] pWrappedKey, LongRef pulWrappedKeyLen);

    /**
C_UnwrapKey unwraps (i.e. decrypts) a wrapped key, creating a new private key or
secret key object. hSession is the session's handle; pMechanism points to the unwrapping
mechanism; hUnwrappingKey is the handle of the unwrapping key; pWrappedKey points
to the wrapped key;  ulWrappedKeyLen is the length of the wrapped key;  pTemplate
points to the template for the new key; ulAttributeCount is the number of attributes in the
template; phKey points to the location that receives the handle of the recovered key.
<p>The CKA_UNWRAP attribute of the unwrapping key, which indicates whether the key
supports unwrapping, must be CK_TRUE.
<p>The new key will have the CKA_ALWAYS_SENSITIVE attribute set to CK_FALSE,
and the  CKA_NEVER_EXTRACTABLE attribute set to CK_FALSE. The
CKA_EXTRACTABLE attribute is by default set to CK_TRUE.
Some mechanisms may modify, or attempt to modify. the contents of the pMechanism
structure at the same time that the key is unwrapped.
If a call to C_UnwrapKey cannot support the precise template supplied to it, it will fail
and return without creating any key object.
The key object created by a successful call to  C_UnwrapKey will have its
CKA_LOCAL attribute set to CK_FALSE.
<p>To partition the unwrapping keys so they can only unwrap a subset of keys the attribute
CKA_UNWRAP_TEMPLATE can be used on the unwrapping key to specify an attribute
set that will be added to attributes of the key to be unwrapped. If the attributes do not
conflict with the user supplied attribute template, in 'pTemplate', then the unwrap will
proceed. The value of this attribute is an attribute template and the size is the number of
items in the template times the size of CK_ATTRIBUTE. If this attribute is not present
on the unwrapping key then no additional attributes will be added. If any attribute
conflict occurs on an attempt to unwrap  a key then the function shall return
CKR_TEMPLATE_INCONSISTENT.
     * @param hSession the session's handle
     * @param pMechanism unwrapping mechanism
     * @param hUnwrappingKey unwrapping key
     * @param pWrappedKey the wrapped key
     * @param ulWrappedKeyLen wrapped key len
     * @param pTemplate new key template
     * @param ulAttributeCount template length
     * @param phKey gets new handle
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_READ_ONLY},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#ATTRIBUTE_VALUE_INVALID},
{@link CKR#BUFFER_TOO_SMALL}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#DOMAIN_PARAMS_INVALID}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#MECHANISM_INVALID}, {@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SESSION_READ_ONLY},
{@link CKR#TEMPLATE_INCOMPLETE}, {@link CKR#TEMPLATE_INCONSISTENT},
{@link CKR#TOKEN_WRITE_PROTECTED},
{@link CKR#UNWRAPPING_KEY_HANDLE_INVALID},
{@link CKR#UNWRAPPING_KEY_SIZE_RANGE},
{@link CKR#UNWRAPPING_KEY_TYPE_INCONSISTENT},
{@link CKR#USER_NOT_LOGGED_IN}, {@link CKR#WRAPPED_KEY_INVALID},
{@link CKR#WRAPPED_KEY_LEN_RANGE}
     */
    long C_UnwrapKey(long hSession, CKM pMechanism, long hUnwrappingKey, byte[] pWrappedKey, long ulWrappedKeyLen, CKA[] pTemplate, long ulAttributeCount, LongRef phKey);

    /**
C_DeriveKey derives a key from a base key, creating a new key object. hSession is the
session's handle;  pMechanism points to a structure that specifies the key derivation
mechanism;  hBaseKey is the handle of the base key; pTemplate points to the template for
the new key;  ulAttributeCount is the number of  attributes in the template; and  phKey
points to the location that receives the handle of the derived key.
<p>The values of the  CK_SENSITIVE,  CK_ALWAYS_SENSITIVE,
CK_EXTRACTABLE, and CK_NEVER_EXTRACTABLE attributes for the base key
affect the values that these attributes can hold for the newly-derived key.  See the
description of each particular key-derivation mechanism in Section 11.17.2 for any
constraints of this type.
<p>If a call to C_DeriveKey cannot support the precise template supplied to it, it will fail
and return without creating any key object.
The key object created by a successful call to C_DeriveKey will have its CKA_LOCAL
attribute set to CK_FALSE.
     * @param hSession the session's handle
     * @param pMechanism key deriv. mech.
     * @param hBaseKey base key
     * @param pTemplate new key template
     * @param ulAttributeCount
     * @param phKey gets new handle
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#ATTRIBUTE_READ_ONLY},
{@link CKR#ATTRIBUTE_TYPE_INVALID}, {@link CKR#ATTRIBUTE_VALUE_INVALID},
{@link CKR#CRYPTOKI_NOT_INITIALIZED}, {@link CKR#DEVICE_ERROR},
{@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#DOMAIN_PARAMS_INVALID}, {@link CKR#FUNCTION_CANCELED},
{@link CKR#FUNCTION_FAILED}, {@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY},
{@link CKR#KEY_HANDLE_INVALID}, {@link CKR#KEY_SIZE_RANGE},
{@link CKR#KEY_TYPE_INCONSISTENT}, {@link CKR#MECHANISM_INVALID},
{@link CKR#MECHANISM_PARAM_INVALID}, {@link CKR#OK}, {@link CKR#OPERATION_ACTIVE},
{@link CKR#PIN_EXPIRED}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#SESSION_READ_ONLY},
{@link CKR#TEMPLATE_INCOMPLETE}, {@link CKR#TEMPLATE_INCONSISTENT},
{@link CKR#TOKEN_WRITE_PROTECTED}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_DeriveKey(long hSession, CKM pMechanism, long hBaseKey, CKA[] pTemplate, long ulAttributeCount, LongRef phKey);

    /**
C_SeedRandom mixes additional seed material into the token's random number
generator.  hSession is the session's handle;  pSeed points to the seed material; and
ulSeedLen is the length in bytes of the seed material.
     * @param hSession the session's handle
     * @param pSeed the seed material
     * @param ulSeedLen length of seed material
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#RANDOM_SEED_NOT_SUPPORTED},
{@link CKR#RANDOM_NO_RNG}, {@link CKR#SESSION_CLOSED},
{@link CKR#SESSION_HANDLE_INVALID}, {@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_SeedRandom(long hSession, byte[] pSeed, long ulSeedLen);

    /**
C_GenerateRandom generates random or pseudo-random data. hSession is the session's
handle;  pRandomData points to the location that receives the random data; and
ulRandomLen is the length in bytes of the random or pseudo-random data to be
generated.
     * @param hSession the session's handle
     * @param pRandomData receives the random data
     * @param ulRandomLen # of bytes to generate
     * @return {@link CKR#ARGUMENTS_BAD}, {@link CKR#CRYPTOKI_NOT_INITIALIZED},
{@link CKR#DEVICE_ERROR}, {@link CKR#DEVICE_MEMORY}, {@link CKR#DEVICE_REMOVED},
{@link CKR#FUNCTION_CANCELED}, {@link CKR#FUNCTION_FAILED},
{@link CKR#GENERAL_ERROR}, {@link CKR#HOST_MEMORY}, {@link CKR#OK},
{@link CKR#OPERATION_ACTIVE}, {@link CKR#RANDOM_NO_RNG},
{@link CKR#SESSION_CLOSED}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#USER_NOT_LOGGED_IN}
     */
    long C_GenerateRandom(long hSession, byte[] pRandomData, long ulRandomLen);

    /**
In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function
running in parallel with an application.  Now, however, C_GetFunctionStatus is a
legacy function which should simply return the value
CKR_FUNCTION_NOT_PARALLEL.
     * @param hSession the session's handle
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}}, {@link CKR#FUNCTION_FAILED},
{@link CKR#FUNCTION_NOT_PARALLEL}, {@link CKR#GENERAL_ERROR},
{@link CKR#HOST_MEMORY}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#SESSION_CLOSED}
     */
    long C_GetFunctionStatus(long hSession);

    /**
In previous versions of Cryptoki, C_CancelFunction cancelled a function running in
parallel with an application.  Now, however, C_CancelFunction is a legacy function
which should simply return the value CKR_FUNCTION_NOT_PARALLEL.
     * @param hSession the session's handle
     * @return {@link CKR#CRYPTOKI_NOT_INITIALIZED}}, {@link CKR#FUNCTION_FAILED},
{@link CKR#FUNCTION_NOT_PARALLEL}, {@link CKR#GENERAL_ERROR},
{@link CKR#HOST_MEMORY}, {@link CKR#SESSION_HANDLE_INVALID},
{@link CKR#SESSION_CLOSED}
     */
    long C_CancelFunction(long hSession);
}
