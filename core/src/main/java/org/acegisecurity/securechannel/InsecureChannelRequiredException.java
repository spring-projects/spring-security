/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.securechannel;

import net.sf.acegisecurity.AccessDeniedException;


/**
 * Thrown if a secure web channel is detected, but is not required.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InsecureChannelRequiredException extends AccessDeniedException {
    //~ Constructors ===========================================================

    /**
     * Constructs an <code>InsecureChannelRequiredException</code> with the
     * specified message.
     *
     * @param msg the detail message.
     */
    public InsecureChannelRequiredException(String msg) {
        super(msg);
    }

    /**
     * Constructs an <code>InsecureChannelRequiredException</code> with the
     * specified message and root cause.
     *
     * @param msg the detail message.
     * @param t root cause
     */
    public InsecureChannelRequiredException(String msg, Throwable t) {
        super(msg, t);
    }
}
