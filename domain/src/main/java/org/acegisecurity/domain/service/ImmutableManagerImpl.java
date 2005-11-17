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

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import org.acegisecurity.domain.PersistableEntity;
import org.acegisecurity.domain.dao.Dao;
import org.acegisecurity.domain.dao.PaginatedList;
import org.acegisecurity.domain.util.GenericsUtils;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.support.ApplicationObjectSupport;
import org.springframework.util.Assert;

/**
 * Base {@link ImmutableManager} implementation.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ImmutableManagerImpl<E extends PersistableEntity> extends ApplicationObjectSupport implements ImmutableManager<E>, InitializingBean {
    //~ Instance fields ========================================================

    /** The class that this instance provides services for */
    private Class supportsClass;
	private String beanName;
	
	protected Dao<E> dao;

    //~ Methods ================================================================
	
	public ImmutableManagerImpl() {
		this.supportsClass = GenericsUtils.getGeneric(getClass());
		if (supportsClass == null) {
			if (logger.isWarnEnabled()) {
				logger.warn("Could not determine the generics type - you will need to set manually");
			}
		}
	}

    public void setSupportsClass(Class supportClass) {
        this.supportsClass = supportClass;
    }

    public Class getSupportsClass() {
        return supportsClass;
    }

    public Dao<E> getDao() {
		return dao;
	}

	public void setDao(Dao<E> dao) {
		this.dao = dao;
	}

	/**
	 * @return the sort order column to be used by default by the scroll methods
	 */
	protected String getDefaultSortOrder() {
		return "id";
	}
	
	/**
	 * Provides hook for custom subclasses to provide initialization behaviour
	 * 
	 * @throws Exception
	 */
	protected void doInitManager() throws Exception {}
	
	public final void afterPropertiesSet() throws Exception {
        Assert.notNull(supportsClass, "supportClass is required");
        Assert.isTrue(PersistableEntity.class.isAssignableFrom(supportsClass),
        "supportClass is not an implementation of PersistableEntity");
		Assert.notNull(dao, "Dao is null");
		Assert.isTrue(dao.supports(supportsClass), "Dao '" + dao + "' does not support '" + supportsClass + "'");
		doInitManager();
	}

    public List<E> findAll() {
        return dao.findAll();
    }

    public List<E> findId(Collection<Serializable> ids) {
        Assert.notNull(ids, "Collection of IDs cannot be null");
        Assert.notEmpty(ids, "There must be some values in the Collection list");
        return dao.findId(ids);
    }

    public E readId(Serializable id) {
        Assert.notNull(id);
        return dao.readId(id);
    }

    public E readPopulatedId(Serializable id) {
		Assert.notNull(id);
		return dao.readPopulatedId(id);
	}

	public PaginatedList<E> scroll(E value, int firstElement,
        int maxElements) {
        Assert.notNull(value);
		Assert.isInstanceOf(this.supportsClass, value, "Can only scroll with values this manager supports");

        return dao.scroll(value, firstElement, maxElements, getDefaultSortOrder());
    }

    public PaginatedList<E> scrollPopulated(E value, int firstElement, int maxElements) {
        Assert.notNull(value);
		Assert.isInstanceOf(this.supportsClass, value, "Can only scroll with values this manager supports");
		
		return dao.scrollPopulated(value, firstElement, maxElements, getDefaultSortOrder());
	}

	public PaginatedList<E> scrollWithSubclasses(E value, int firstElement,
	        int maxElements) {
	        Assert.notNull(value);
			Assert.isInstanceOf(this.supportsClass, value, "Can only scroll with values this manager supports");

	        return dao.scrollWithSubclasses(value, firstElement, maxElements, getDefaultSortOrder());
	    }

	public PaginatedList<E> scrollPopulatedWithSubclasses(E value, int firstElement, int maxElements) {
        Assert.notNull(value);
		Assert.isInstanceOf(this.supportsClass, value, "Can only scroll with values this manager supports");

		return dao.scrollPopulatedWithSubclasses(value, firstElement, maxElements, getDefaultSortOrder());
	}

	public boolean supports(Class clazz) {
        Assert.notNull(clazz);

        return this.supportsClass.equals(clazz);
    }

	public void setBeanName(String beanName) {
		this.beanName = beanName;
	}
}
