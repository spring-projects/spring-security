/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.concurrent;

import org.acegisecurity.AuthenticationException;


/**
 * Thrown by a <code>SessionRegistry</code> implementation if an attempt is made to create new session information
 * for an existing sessionId. The user should firstly clear the existing session from the
 * <code>ConcurrentSessionRegistry</code>.
 *
 * @author Ben Alex
 */
public class SessionAlreadyUsedException extends AuthenticationException {
    //~ Constructors ===================================================================================================

    public SessionAlreadyUsedException(String msg) {
        super(msg);
    }
}
