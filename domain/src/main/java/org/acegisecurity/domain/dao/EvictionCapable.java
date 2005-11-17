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

package org.acegisecurity.domain.dao;

import org.acegisecurity.domain.PersistableEntity;


/**
 * Indicates an implementation capable of evicting {@link
 * org.acegisecurity.domain.PersistableEntity}s.
 * 
 * <p>
 * Structured as a separate interface (rather than a subclass of
 * <code>Dao</code>), as it is not required for all persistence strategies.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface EvictionCapable {
    //~ Methods ================================================================

    /**
     * Removes the indicated persistent instance from the DAO's internal
     * map/session.
     * 
     * <p>
     * If the passed object does not exist in the internal map/session, the
     * invocation has no effect.
     * </p>
     * 
     * <p>
     * May throw an exception if the implementation so desires.
     * </p>
     *
     * @param entity to remove from the internal map/session
     */
    public void evict(PersistableEntity entity);
}
