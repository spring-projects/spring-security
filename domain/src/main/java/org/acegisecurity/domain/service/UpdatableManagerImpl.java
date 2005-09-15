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

import org.springframework.util.Assert;

/**
 * Base {@link UpdatableManager} implementation.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UpdatableManagerImpl<E extends PersistableEntity> extends CreatableManagerImpl<E> implements UpdatableManager<E> {

    public E update(E value) {
        Assert.notNull(value);
		if (logger.isDebugEnabled()) {
			logger.debug("Updating: " + value);
		}
        return dao.update(value);
    }
    
    /**
	 * Delegates to the appropriate services layer method (not the DAO).
	 */
    public E createOrUpdate(E value) {
        Assert.notNull(value);
		if (logger.isDebugEnabled()) {
			logger.debug("CreatingOrUpdating: " + value);
		}
		if (value.getInternalId() == null) {
			return create(value);
		} else {
			return update(value);
		}
    }
}
