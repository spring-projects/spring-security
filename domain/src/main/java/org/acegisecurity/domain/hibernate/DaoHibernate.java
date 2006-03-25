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

package org.acegisecurity.domain.hibernate;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import org.acegisecurity.domain.PersistableEntity;
import org.acegisecurity.domain.dao.Dao;
import org.acegisecurity.domain.dao.PaginatedList;
import org.acegisecurity.domain.util.GenericsUtils;
import org.hibernate.Criteria;
import org.hibernate.EntityMode;
import org.hibernate.Hibernate;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Expression;
import org.hibernate.criterion.Order;
import org.hibernate.metadata.ClassMetadata;
import org.hibernate.type.Type;
import org.springframework.orm.hibernate3.HibernateCallback;
import org.springframework.orm.hibernate3.support.HibernateDaoSupport;
import org.springframework.util.Assert;


/**
 * Generics supporting {@link Dao} implementation that uses Hibernate 3 for persistence.
 *
 * @author Ben Alex
 * @author Matthew Porter
 * @version $Id$
 */
public class DaoHibernate<E extends PersistableEntity> extends HibernateDaoSupport implements Dao<E> {
    //~ Instance fields ========================================================
	
    /** The class that this instance provides services for */
    private Class supportsClass;

	public DaoHibernate(SessionFactory sessionFactory) {
		Assert.notNull(sessionFactory, "Non-null Hibernate SessionFactory must be expressed as a constructor argument");
		super.setSessionFactory(sessionFactory);
		this.supportsClass = GenericsUtils.getGeneric(getClass());
		Assert.notNull(this.supportsClass, "Could not determine the generics type");
	}
	
    //~ Methods ================================================================

	public void create(E value) {
        Assert.notNull(value);
        super.getHibernateTemplate().save(value);
    }

    public void delete(E value) {
        Assert.notNull(value);
        super.getHibernateTemplate().delete(value);
    }

    @SuppressWarnings("unchecked")
	public List<E> findAll() {
        return super.getHibernateTemplate().loadAll(supportsClass);
    }

    @SuppressWarnings("unchecked")
	public List<E> findId(Collection<Serializable> ids) {
        Assert.notNull(ids, "Collection of IDs cannot be null");
        Assert.notEmpty(ids, "There must be some values in the Collection list");

        return (List) super.getHibernateTemplate().execute(getFindByIdCallback(ids));
    }

    @SuppressWarnings("unchecked")
	public E readId(Serializable id) {
        Assert.notNull(id);
        return (E) getHibernateTemplate().load(supportsClass, id);
    }

    @SuppressWarnings("unchecked")
	public PaginatedList<E> scroll(E value, int firstElement,
        int maxElements, String orderByAsc) {
		validateScrollMethod(value, firstElement, maxElements, orderByAsc);
        return (PaginatedList) super.getHibernateTemplate().execute(getFindByValueCallback(
                value.getClass(), value, firstElement, maxElements, Order.asc(orderByAsc)));
    }

    @SuppressWarnings("unchecked")
	public PaginatedList<E> scrollWithSubclasses(E value, int firstElement,
	        int maxElements, String orderByAsc) {
			validateScrollMethod(value, firstElement, maxElements, orderByAsc);
	        return (PaginatedList) super.getHibernateTemplate().execute(getFindByValueCallback(
	                this.supportsClass, value, firstElement, maxElements, Order.asc(orderByAsc)));
	    }

	private void validateScrollMethod(E value, int firstElement, int MaxElements, String orderByAsc) {
        Assert.notNull(value);
        Assert.hasText(orderByAsc,
            "An orderByAsc is required (why not use your identity property?)");
		Assert.isInstanceOf(this.supportsClass, value, "Can only scroll with values this DAO supports");
	}

	public boolean supports(Class clazz) {
        Assert.notNull(clazz);
        return this.supportsClass.equals(clazz);
    }

    public void update(E value) {
        Assert.notNull(value);
        super.getHibernateTemplate().update(value);
    }

	/**
     * Provides a <code>HibernateCallback</code> that will load a list of
     * objects by a <code>Collection</code> of identities.
     *
     * @param ids collection of identities to be loaded
     *
     * @return a <code>List</code> containing the matching objects
     */
    private HibernateCallback getFindByIdCallback(final Collection<Serializable> ids) {
        return new HibernateCallback() {
                public Object doInHibernate(Session session)
                    throws HibernateException {
                    Criteria criteria = session.createCriteria(supportsClass);

                    ClassMetadata classMetadata = getSessionFactory()
                                                      .getClassMetadata(supportsClass);

                    String idPropertyName = classMetadata
                        .getIdentifierPropertyName();
                    criteria.add(Expression.in(idPropertyName, ids));

                    return criteria.list();
                }
            };
    }

    /**
     * Get a new <code>HibernateCallback</code> for finding objects by a bean
     * property values, paginating the results. Properties with null values
     * and collections and empty Strings are ignored, as is any property with
     * the "version" name. If the property is mapped as String find a partial
     * match, otherwise find by exact match.
     *
     * @param whichClass the class (and subclasses) which results will be limited to including
     * @param bean bean with the values of the parameters
     * @param firstElement the first result, numbered from 0
     * @param count the maximum number of results
     * @param order DOCUMENT ME!
     *
     * @return a PaginatedList containing the requested objects
     */
    private HibernateCallback getFindByValueCallback(final Class whichClass, final Object bean, final int firstElement, final int count, final Order order) {
        return new HibernateCallback() {
                @SuppressWarnings("unchecked")
				public Object doInHibernate(Session session)
                    throws HibernateException {
                	int paramCount = 0;
                	
                	StringBuffer queryString = new StringBuffer("from ").append(bean.getClass().getName()).append(" as queryTarget");
                	
                	
                    ClassMetadata classMetadata = getSessionFactory()
                                                      .getClassMetadata(bean
                            .getClass());

					Assert.notNull(classMetadata, "ClassMetadata for " + bean.getClass() + " unavailable from Hibernate - have you mapped this class against the SessionFactory?");
					
                    /* get persistent properties */
                    Type[] propertyTypes = classMetadata.getPropertyTypes();
                    String[] propertyNames = classMetadata.getPropertyNames();

                    /* for each persistent property of the bean */
                    for (int i = 0; i < propertyNames.length; i++) {
                        String name = propertyNames[i];
                        // TODO: Check if EntityMode.POJO appropriate
                        Object value = classMetadata.getPropertyValue(bean, name, EntityMode.POJO);

                        if (value == null) {
                            continue;
                        }

                        // ignore empty Strings
                        if (value instanceof String) {
                            String string = (String) value;

                            if ("".equals(string)) {
                                continue;
                            }
                        }

                        // ignore any collections
                        if (propertyTypes[i].isCollectionType()) {
                            continue;
                        }

                        if (name.equals("version")) {
                            continue;
                        }

                        Type type = classMetadata.getPropertyType(name);

						if (type.equals(Hibernate.STRING)) {
                            // if the property is mapped as String, find partial match
                            if (paramCount == 0) {
                            	queryString.append(" where ");
                            } else {
                            	queryString.append(" and ");
                            }
                            paramCount++;
                            queryString.append("lower(queryTarget.").append(name).append(") like '%" + value.toString().toLowerCase() + "%'");
                        } else {
                            // find exact match
                            if (paramCount == 0) {
                            	queryString.append(" where ");
                            } else {
                            	queryString.append(" and ");
                            }
                            paramCount++;
                            queryString.append("queryTarget.").append(name).append(" = " + value);
                        }
                    }
                    
                    if (logger.isDebugEnabled()) {
	                    logger.debug(queryString.toString());
                    }
                    
            		// Determine number of rows
            		org.hibernate.Query countQuery = session.createQuery("select count(*) " + queryString.toString());
            		int size = ((Integer) countQuery.iterate().next()).intValue();
            		
            		// Obtain requested page of query
            		org.hibernate.Query query = session.createQuery(queryString.toString());
            		query.setMaxResults(count);
            		query.setFirstResult(firstElement);
                    
                    return new PaginatedList(query.list(), firstElement, count, size);
                }
            };
    }
}
