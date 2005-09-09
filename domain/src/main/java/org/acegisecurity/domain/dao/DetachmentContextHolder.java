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

package net.sf.acegisecurity.domain.dao;

import net.sf.acegisecurity.context.SecurityContextImpl;


/**
 * <code>InheritableThreadLocal</code> which indicates whether a {@link Dao}
 * implementation should be forced to return a detached instance.
 * 
 * <p>A detached instance is one which is no longer associated with the ORM
 * mapper and changes will therefore not be transparently persisted to the database.
 * 
 * <p>Not all <code>Dao</code> implementations support the concept of detached
 * instances.
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see java.lang.InheritableThreadLocal
 */
public class DetachmentContextHolder {
    //~ Static fields/initializers =============================================

    private static InheritableThreadLocal<Boolean> contextHolder = new InheritableThreadLocal<Boolean>();

    //~ Methods ================================================================

    /**
     * Specifies whether or not detached in <code>SecurityContext</code> with the current thread of
     * execution.
     *
     * @param 
     */
    public static void setForceReturnOfDetachedInstances(boolean alwaysReturnDetached) {
        contextHolder.set(alwaysReturnDetached);
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
    public static boolean isForceReturnOfDetachedInstances() {
        if (contextHolder.get() == null) {
            contextHolder.set(Boolean.FALSE);
        }

        return contextHolder.get();
    }
}
