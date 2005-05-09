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

package net.sf.acegisecurity.domain.impl;

import java.io.Serializable;

import javax.persistence.Transient;

/**
 * A persistable entity that uses a <code>Long</code> based identity.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class PersistableEntityLong extends AbstractPersistableEntity {
    //~ Instance fields ========================================================

    protected Long id;

    //~ Methods ================================================================

    /**
     * DO NOT USE DIRECTLY.
     * 
     * <p>
     * Typically only used by the persistence layer, but provided with public
     * visibility to not limit flexibility.
     * </p>
     *
     * @param id the new instance identity
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Obtains the persistence identity of this instance.
     * 
     * <p>Marked as abstract to remind users to implement. They'll need to implement
     * so their annotations reflect the correct sequence name.
     */
	@Transient
    public abstract Long getId();

    /**
     * DO NOT USE DIRECTLY.
     * 
     * <p>
     * Use {@link #getId()} instead, as it provides the correct return type.
     * This method is only provided for use by the persistence layer and to
     * satisfy the {@link net.sf.acegisecurity.domain.PersistableEntity}
     * interface contract.
     * </p>
     * 
     * <p>
     * Internally delegates to {@link #getId()}.
     * </p>
     *
     * @return the instance's identity
     */
	@Transient
    public Serializable getInternalId() {
        return this.getId();
    }
}
