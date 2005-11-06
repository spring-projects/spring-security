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
     * Sets whether or not detached domain object instances should be returned
     * within the current thread of execution.
     *
     * @param alwaysReturnDetached if true then detached instances should be returned.
     */
    public static void setForceReturnOfDetachedInstances(boolean alwaysReturnDetached) {
        contextHolder.set(alwaysReturnDetached);
    }

    /**
     * Returns the boolean value detachment policy which has been set for the current
     * thread (defaults to false).
     *
     */
    public static boolean isForceReturnOfDetachedInstances() {
        if (contextHolder.get() == null) {
            contextHolder.set(Boolean.FALSE);
        }

        return contextHolder.get();
    }
}
