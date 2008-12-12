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

package org.springframework.security.acls.afterinvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * A filter used to filter Collections.
 *
 * @author Ben Alex
 * @author Paulo Neves
 * @version $Id$
 */
class CollectionFilterer<T> implements Filterer<T> {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(CollectionFilterer.class);

    //~ Instance fields ================================================================================================

    private Collection<T> collection;

    // collectionIter offers significant performance optimisations (as
    // per security-developer mailing list conversation 19/5/05)
    private Iterator<T> collectionIter;
    private Set<T> removeList;

    //~ Constructors ===================================================================================================

    CollectionFilterer(Collection<T> collection) {
        this.collection = collection;

        // We create a Set of objects to be removed from the Collection,
        // as ConcurrentModificationException prevents removal during
        // iteration, and making a new Collection to be returned is
        // problematic as the original Collection implementation passed
        // to the method may not necessarily be re-constructable (as
        // the Collection(collection) constructor is not guaranteed and
        // manually adding may lose sort order or other capabilities)
        removeList = new HashSet<T>();
    }

    //~ Methods ========================================================================================================

    /**
     *
     * @see org.springframework.security.acls.afterinvocation.Filterer#getFilteredObject()
     */
    public Object getFilteredObject() {
        // Now the Iterator has ended, remove Objects from Collection
        Iterator<T> removeIter = removeList.iterator();

        int originalSize = collection.size();

        while (removeIter.hasNext()) {
            collection.remove(removeIter.next());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Original collection contained " + originalSize + " elements; now contains "
                + collection.size() + " elements");
        }

        return collection;
    }

    /**
     *
     * @see org.springframework.security.acls.afterinvocation.Filterer#iterator()
     */
    public Iterator<T> iterator() {
        collectionIter = collection.iterator();

        return collectionIter;
    }

    /**
     *
     * @see org.springframework.security.acls.afterinvocation.Filterer#remove(java.lang.Object)
     */
    public void remove(T object) {
        removeList.add(object);
    }
}
