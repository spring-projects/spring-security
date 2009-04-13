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
package org.springframework.security.acls;

/**
 * Thrown if an {@link Acl} cannot perform an operation because it only loaded a subset of <code>Sid</code>s and
 * the caller has requested details for an unloaded <code>Sid</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UnloadedSidException extends AclException {
    //~ Constructors ===================================================================================================

    /**
     * Constructs an <code>NotFoundException</code> with the specified message.
     *
     * @param msg the detail message
     */
    public UnloadedSidException(String msg) {
        super(msg);
    }

    /**
     * Constructs an <code>NotFoundException</code> with the specified message
     * and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public UnloadedSidException(String msg, Throwable t) {
        super(msg, t);
    }
}
