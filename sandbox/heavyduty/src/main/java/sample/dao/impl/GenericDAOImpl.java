/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.dao.impl;

import java.io.Serializable;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sample.dao.GenericDAO;


public class GenericDAOImpl<T extends Serializable, PK extends Serializable>
		implements GenericDAO<T, PK> {
	/** type */
	private Class<T> type;

	/** the logger */
	private static final Log LOG = LogFactory.getLog(GenericDAOImpl.class);

	@PersistenceContext
	private EntityManager entityManager;

	/**
	 * Minimal constructor
	 *
	 * @param t
	 *            type POJO hibernate
	 */
	public GenericDAOImpl(Class<T> t) {
		this.type = t;
	}

	/**
	 * read data
	 *
	 * @param id
	 *            data id
	 * @return data
	 */
	public T read(PK id) {
		if (id == null) {
			throw new IllegalArgumentException("Id cannot be null or empty");
		}

		// find() au lieu de getReference() pour forcer l'initialisation de
		// l'objet, sinon on ne recupère
		// qu'un proxy non-initialisé !
		return entityManager.find(type, id);

	}

	/**
	 * persist data
	 *
	 * @param transientInstance
	 *            data to persist
	 * @see sido.common.dao.GenericDAO#persist(T)
	 */
	public void persist(T transientInstance) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Persisting instance of "
					+ transientInstance.getClass().getSimpleName());
		}
		entityManager.persist(transientInstance);
	}

	/**
	 *
	 * attach clean
	 *
	 * @param instance
	 *            data to attach
	 * @see sido.common.dao.GenericDAO#refresh(T)
	 */
	public void refresh(T instance) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("refreshing instance of "
					+ instance.getClass().getSimpleName());
		}
		entityManager.refresh(instance);
	}

	/**
	 * delete
	 *
	 * @param persistentInstance
	 *            data to delete
	 * @see sido.common.dao.GenericDAO#delete(T)
	 */
	public void delete(T persistentInstance) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("deleting instance of "
					+ persistentInstance.getClass().getSimpleName());
		}
		entityManager.remove(persistentInstance);
	}

	/**
	 * merge
	 *
	 * @param detachedInstance
	 *            data to merge
	 * @return the merged data
	 * @see sido.common.dao.GenericDAO#merge(T)
	 */
	public T merge(T detachedInstance) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("merging instance of "
					+ detachedInstance.getClass().getSimpleName());
		}
		return entityManager.merge(detachedInstance);
	}

	/**
	 * @return the entityManager
	 */
	public EntityManager getEntityManager() {
		return entityManager;
	}


}
