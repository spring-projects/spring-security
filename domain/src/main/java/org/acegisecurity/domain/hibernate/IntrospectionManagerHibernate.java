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

package net.sf.acegisecurity.domain.hibernate;

import net.sf.acegisecurity.domain.validation.IntrospectionManager;

import net.sf.hibernate.HibernateException;
import net.sf.hibernate.SessionFactory;
import net.sf.hibernate.metadata.ClassMetadata;
import net.sf.hibernate.type.Type;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.orm.hibernate.HibernateSystemException;

import org.springframework.util.Assert;

import java.util.List;


/**
 * {@link IntrospectionManager} that uses Hibernate metadata to locate
 * children.
 * 
 * <p>
 * Add children objects are added to the <code>List</code> of children objects
 * to validate, irrespective of whether a save/update/delete operation will
 * cascade to them. This is not a perfect solution, but addresses most
 * real-world validation requirements (you can always implement your own
 * <code>IntrospectionManager</code> if you prefer).
 * </p>
 * 
 * <p>
 * This implementation only adds properties of a parent object that have a
 * Hibernate {@link net.sf.hibernate.type.Type} that indicates it is an object
 * type (ie {@link net.sf.hibernate.type.Type#isObjectType()}).
 * </p>
 *
 * @author Matthew Porter
 * @author Ben Alex
 */
public class IntrospectionManagerHibernate implements IntrospectionManager,
    InitializingBean {
    //~ Instance fields ========================================================

    private SessionFactory sessionFactory;

    //~ Methods ================================================================

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public SessionFactory getSessionFactory() {
        return this.sessionFactory;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(sessionFactory, "SessionFactory is required");
    }

    public void obtainImmediateChildren(Object parentObject, List allObjects) {
        Assert.notNull(parentObject,
            "Violation of interface contract: parentObject null");
        Assert.notNull(allObjects,
            "Violation of interface contract: allObjects null");

        ClassMetadata classMetadata = null;

        try {
            classMetadata = sessionFactory.getClassMetadata(parentObject
                    .getClass());

            if (classMetadata != null) {
                String[] propertyNames = classMetadata.getPropertyNames();

                for (int i = 0; i < propertyNames.length; i++) {
                    Type propertyType = classMetadata.getPropertyType(propertyNames[i]);

                    if (propertyType.isObjectType()) {
                        allObjects.add(classMetadata.getPropertyValue(
                                parentObject, propertyNames[i]));
                    }
                }
            }
        } catch (HibernateException he) {
            throw new HibernateSystemException(he);
        }
    }
}
