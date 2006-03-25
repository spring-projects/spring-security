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

package org.acegisecurity.domain.impl;

import java.io.Serializable;


/**
 * A persistable entity that uses a <code>Long</code> based identity.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class PersistableEntityLong extends AbstractPersistableEntity {
    //~ Instance fields ========================================================

    private Long id;

    //~ Methods ================================================================

    /**
     * Obtains the persistence identity of this instance.
     */
    public Long getId() {
    	return this.id;
    }
    
    /**
     * Required solely because Hibernate
     */
    public Serializable getInternalId() {
    	return this.id;
    }


}
