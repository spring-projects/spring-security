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
 * Thrown if a {@link Context} is not valid, according to  {@link
 * Context#validate()}.
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see Context#validate()
 */
public class ContextInvalidException extends ContextException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>ContextInvalidException</code> with the specified
     * message.
     *
     * @param msg the detail message.
     */
    public ContextInvalidException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>ContextInvalidException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message.
     * @param t root cause
     */
    public ContextInvalidException(String msg, Throwable t) {
        super(msg, t);
    }
}
