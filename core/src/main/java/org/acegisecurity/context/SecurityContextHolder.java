/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

import org.springframework.util.Assert;


/**
 * Associates a given {@link SecurityContext} with the current execution
 * thread.
 * 
 * <p>
 * To guarantee that {@link #getContext()} never returns <code>null</code>, this
 * class defaults to returning <code>SecurityContextImpl</code> if no
 * <code>SecurityContext</code> has ever been associated with the current
 * thread of execution. Despite this behaviour, in general another class will
 * select the concrete <code>SecurityContext</code> implementation to use and
 * expressly set an instance of that implementation against the
 * <code>SecurityContextHolder</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see java.lang.ThreadLocal
 * @see org.acegisecurity.context.HttpSessionContextIntegrationFilter
 */
public class SecurityContextHolder {
    //~ Static fields/initializers =============================================

    private static ThreadLocal contextHolder = new ThreadLocal();

    //~ Methods ================================================================

    /**
     * Associates a new <code>SecurityContext</code> with the current thread of
     * execution.
     *
     * @param context the new <code>SecurityContext</code> (may not be
     *        <code>null</code>)
     */
    public static void setContext(SecurityContext context) {
        Assert.notNull(context,
            "Only non-null SecurityContext instances are permitted");
        contextHolder.set(context);
    }

    /**
     * Obtains the <code>SecurityContext</code> associated with the current
     * thread of execution. If no <code>SecurityContext</code> has been
     * associated with the current thread of execution, a new instance of
     * {@link SecurityContextImpl} is associated with the current thread and
     * then returned.
     *
     * @return the current <code>SecurityContext</code> (guaranteed to never be
     *         <code>null</code>)
     */
    public static SecurityContext getContext() {
        if (contextHolder.get() == null) {
            contextHolder.set(new SecurityContextImpl());
        }

        return (SecurityContext) contextHolder.get();
    }

    /**
     * Explicitly clears the context value from thread local storage.
     * Typically used on completion of a request to prevent potential
     * misuse of the associated context information if the thread is
     * reused. 
     */
    public static void clearContext() {
        // Internally set the context value to null. This is never visible
        // outside the class.
        contextHolder.set(null);
    }
}
