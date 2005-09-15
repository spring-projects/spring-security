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

package net.sf.acegisecurity.domain.service;

import net.sf.acegisecurity.domain.PersistableEntity;

/**
 * Adds update (but no delete) methods to the <code>CreatableManager</code>.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public interface UpdatableManager<E extends PersistableEntity> extends CreatableManager<E> {
    //~ Methods ================================================================

	/**
     * Saves an existing object to the persistence layer, or creates a new
     * object in the persistence layer. Implementations typically rely on
     * {@link PersistableEntity#getInternalId()} being non-<code>null</code>
     * to differentiate between persistence instances previous saved and those
     * requiring initial creation.
     *
     * @param value to save or update
     *
     * @return the saved or updated (as appropriate) value
     */
    public E createOrUpdate(E value);

    /**
     * Update an object.
     *
     * @param value to update, with the <code>PersistableEntity</code> having a
     *        non-<code>null</code> identifier
     *
     * @return the updated value
     */
    public E update(E value);
}
