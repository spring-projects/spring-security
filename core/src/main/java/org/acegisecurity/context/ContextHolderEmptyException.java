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

package net.sf.acegisecurity.context;

/**
 * Thrown if a {@link ContextHolder} object does not contain a valid  {@link
 * Context}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextHolderEmptyException extends ContextException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>ContextHolderEmptyException</code> with the specified
     * message.
     *
     * @param msg the detail message
     */
    public ContextHolderEmptyException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>ContextHolderEmptyException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public ContextHolderEmptyException(String msg, Throwable t) {
        super(msg, t);
    }
}
