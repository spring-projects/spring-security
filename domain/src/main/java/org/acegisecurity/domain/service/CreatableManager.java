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

package org.acegisecurity.domain.service;

import org.acegisecurity.domain.PersistableEntity;

/**
 * Adds a creation method to the <code>ImmutableManager</code>.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public interface CreatableManager<E extends PersistableEntity> extends ImmutableManager<E> {
    //~ Methods ================================================================

    /**
     * Create a new object, with the current {@link
     * PersistableEntity#getInternalId()} value being ignored.
     *
     * @param value (without the identity property initialized)
     *
     * @return the value created (with the identity property initialised)
     */
    public E create(E value);
}
