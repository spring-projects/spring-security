/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity.domain.dao;

import org.acegisecurity.domain.PersistableEntity;

import org.springframework.util.Assert;

import java.lang.reflect.Method;

import java.util.Collection;
import java.util.Iterator;


/**
 * Convenience methods that support eviction of <code>PersistableEntity</code>s from  those objects that implement
 * {@link EvictionCapable}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EvictionUtils {
    //~ Methods ========================================================================================================

    /**
     * Evicts the <code>PersistableEntity</code> using the passed <code>Object</code> (provided that the passed
     * <code>Object</code> implements <code>EvictionCapable</code>).
     *
     * @param daoOrServices the potential source for <code>EvictionCapable</code> services (never <code>null</code>)
     * @param entity to evict (can be <code>null</code>)
     */
    public static void evictIfRequired(Object daoOrServices, PersistableEntity entity) {
        EvictionCapable evictor = getEvictionCapable(daoOrServices);

        if ((evictor != null) && (entity != null)) {
            evictor.evict(entity);
        }
    }

    /**
     * Evicts each <code>PersistableEntity</code> element of the passed <code>Collection</code> using the
     * passed <code>Object</code> (provided that the passed <code>Object</code> implements
     * <code>EvictionCapable</code>).
     *
     * @param daoOrServices the potential source for <code>EvictionCapable</code> services (never <code>null</code>)
     * @param collection whose members to evict (never <code>null</code>)
     */
    public static void evictIfRequired(Object daoOrServices, Collection<?extends Object> collection) {
        Assert.notNull(collection, "Cannot evict a null Collection");

        if (getEvictionCapable(daoOrServices) == null) {
            // save expense of iterating collection
            return;
        }

        Iterator<?extends Object> iter = collection.iterator();

        while (iter.hasNext()) {
            Object obj = iter.next();

            if (obj instanceof PersistableEntity) {
                evictIfRequired(daoOrServices, (PersistableEntity) obj);
            }
        }
    }

    /**
     * Evicts the <code>PersistableEntity</code> using the passed <code>Object</code> (provided that the passed
     * <code>Object</code> implements <code>EvictionCapable</code>), along with expressly evicting every
     * <code>PersistableEntity</code> returned by the <code>PersistableEntity</code>'s getters.
     *
     * @param daoOrServices the potential source for <code>EvictionCapable</code> services (never <code>null</code>)
     * @param entity to evict includnig its getter results (can be <code>null</code>)
     */
    public static void evictPopulatedIfRequired(Object daoOrServices, PersistableEntity entity) {
        EvictionCapable evictor = getEvictionCapable(daoOrServices);

        if ((evictor != null) && (entity != null)) {
            evictor.evict(entity);

            Method[] methods = entity.getClass().getMethods();

            for (int i = 0; i < methods.length; i++) {
                if (methods[i].getName().startsWith("get") && (methods[i].getParameterTypes().length == 0)) {
                    try {
                        Object result = methods[i].invoke(entity, new Object[] {});

                        if (result instanceof PersistableEntity) {
                            evictor.evict((PersistableEntity) result);
                        }
                    } catch (Exception ignored) {}
                }
            }
        }
    }

    /**
     * Obtain the <code>EvictionCapable</code> from the passed argument, or <code>null</code>.
     *
     * @param daoOrServices to check if provides eviction services
     *
     * @return the <code>EvictionCapable</code> object or <code>null</code> if the object does not provide eviction
     *         services
     */
    private static EvictionCapable getEvictionCapable(Object daoOrServices) {
        Assert.notNull(daoOrServices, "Cannot evict if the object that may provide EvictionCapable is null");

        if (daoOrServices instanceof EvictionCapable) {
            return (EvictionCapable) daoOrServices;
        } else {
            return null;
        }
    }
}
