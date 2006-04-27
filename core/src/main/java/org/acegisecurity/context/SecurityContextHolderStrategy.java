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

package org.acegisecurity.context;

/**
 * A strategy for storing security context information against a thread.
 * 
 * <p>
 * The preferred strategy is loaded by {@link
 * org.acegisecurity.context.SecurityContextHolder}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface SecurityContextHolderStrategy {
    //~ Methods ================================================================

    /**
     * Clears the current context.
     */
    public void clearContext();

    /**
     * Obtains the current context.
     *
     * @return a context (never <code>null</code> - create a default
     *         implementation if necessary)
     */
    public SecurityContext getContext();

    /**
     * Sets the current context.
     *
     * @param context to the new argument (should never be <code>null</code>,
     *        although implementations must check if <code>null</code> has
     *        been passed and throw an <code>IllegalArgumentException</code>
     *        in such cases)
     */
    public void setContext(SecurityContext context);
}
