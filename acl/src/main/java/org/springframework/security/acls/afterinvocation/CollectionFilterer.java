/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.acls.afterinvocation;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A filter used to filter Collections.
 *
 * @author Ben Alex
 * @author Paulo Neves
 */
class CollectionFilterer<T> implements Filterer<T> {

	protected static final Log logger = LogFactory.getLog(CollectionFilterer.class);

	private final Collection<T> collection;

	private final Set<T> removeList;

	CollectionFilterer(Collection<T> collection) {
		this.collection = collection;

		// We create a Set of objects to be removed from the Collection,
		// as ConcurrentModificationException prevents removal during
		// iteration, and making a new Collection to be returned is
		// problematic as the original Collection implementation passed
		// to the method may not necessarily be re-constructable (as
		// the Collection(collection) constructor is not guaranteed and
		// manually adding may lose sort order or other capabilities)
		removeList = new HashSet<>();
	}

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
		return collection.iterator();
	}

	/**
	 *
	 * @see org.springframework.security.acls.afterinvocation.Filterer#remove(java.lang.Object)
	 */
	public void remove(T object) {
		removeList.add(object);
	}

}
