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

package net.sf.acegisecurity.domain.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;


/**
 * Some utility methods to use <code>Collection</code>s.
 *
 * @author Carlos Sanchez
 * @version $Id$
 */
public class CollectionUtils {
    //~ Methods ================================================================

    public static boolean isCollection(Class theClass) {
        return Collection.class.isAssignableFrom(theClass);
    }

    public static boolean isMap(Class theClass) {
        return Map.class.isAssignableFrom(theClass);
    }

    /**
     * Add an object to a <code>Set</code> and return the result.
     *
     * @param set
     * @param object
     *
     * @return
     */
    public static Set add(Set set, Object object) {
        set.add(object);

        return set;
    }

    /**
     * Add an object to a <code>List</code> and return the result.
     *
     * @param list
     * @param object
     *
     * @return
     */
    public static List add(List list, Object object) {
        list.add(object);

        return list;
    }

    /**
     * Clone a Collection copying all its elements to a new one. If map is
     * <code>null</code> return <code>null</code>.
     *
     * @param collection
     *
     * @return
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public static Collection clone(Collection collection) {
        if (collection == null) {
            return null;
        }

        Class clazz = collection.getClass();
        Collection clone = null;

        if (List.class.isAssignableFrom(clazz)) {
            clone = new ArrayList(collection);
        } else if (SortedSet.class.isAssignableFrom(clazz)) {
            clone = new TreeSet(collection);
        } else if (Set.class.isAssignableFrom(clazz)) {
            clone = new HashSet(collection);
        } else {
            throw new IllegalArgumentException("Unknown collection class: "
                + clazz);
        }

        return clone;
    }

    /**
     * Clone a <code>Map</code> copying all its elements to a new one. If the
     * passed argument is <code>null</code>, the method will return
     * <code>null</code>.
     *
     * @param map to copy
     *
     * @return a copy of the <code>Map</code> passed as an argument
     *
     * @throws IllegalArgumentException if the <code>Map</code> implementation
     *         is not supported by this method
     */
    public static Map clone(Map map) {
        if (map == null) {
            return null;
        }

        Class clazz = map.getClass();
        Map clone = null;

        if (SortedMap.class.isAssignableFrom(clazz)) {
            clone = new TreeMap(map);
        } else if (Map.class.isAssignableFrom(clazz)) {
            clone = new HashMap(map);
        } else {
            throw new IllegalArgumentException("Unknown map class: " + clazz);
        }

        return clone;
    }

    /**
     * Return a <code>List</code> (actually an {@link ArrayList}) with only
     * that object.
     *
     * @param object
     *
     * @return
     */
    public static List newList(Object object) {
        return add(new ArrayList(1), object);
    }

    /**
     * Return a <code>Set</code> (actually a {@link HashSet}) with only that
     * object.
     *
     * @param object
     *
     * @return
     */
    public static Set newSet(Object object) {
        return add(new HashSet(), object);
    }
}
