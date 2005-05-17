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

import javax.persistence.Column;
import javax.persistence.Transient;
import javax.persistence.Version;

import net.sf.acegisecurity.domain.PersistableEntity;

/**
 * An abstract implementation of {@link
 * net.sf.acegisecurity.domain.PersistableEntity}.
 *
 * @author Ben Alex
 * @version $Id$
 *
 * 
 */
public abstract class AbstractPersistableEntity extends BusinessObject
    implements PersistableEntity {
    //~ Static fields/initializers =============================================

    public static final int STARTING_VERSION = 0;

    //~ Instance fields ========================================================

    private int version = STARTING_VERSION;

    //~ Methods ================================================================

    /**
     * Indicates whether this persistable entity has been persisted yet.
     * Determine based on whether the {@link #getInternalId()} returns
     * <code>null</code> or a non-<code>null</code> value.
     *
     * @return <code>true</code> if the instance has not been persisted,
     *         <code>false</code> otherwise
     */
	@Transient
    public boolean isNew() {
        return (getInternalId() == null);
    }

    /**
     * Returns the version number, which should be managed by the persistence
     * layer.
     * 
     * <p>
     * Initially all <code>PersistableEntity</code>s will commence with the
     * version number defined by {@link #STARTING_VERSION}.
     * </p>
     *
     * @return the version
     */
    @Version
    @Column(name="version", nullable=false)
    public int getVersion() {
        return version;
    }

    /**
     * Sets the version numbers.
     *
     * @param version the new version number to use
     */
    public void setVersion(int version) {
        this.version = version;
    }
}
