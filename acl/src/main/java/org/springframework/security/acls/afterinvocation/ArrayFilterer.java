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

import java.lang.reflect.Array;
import java.util.HashSet;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A filter used to filter arrays.
 *
 * @author Ben Alex
 * @author Paulo Neves
 */
class ArrayFilterer<T> implements Filterer<T> {
	// ~ Static fields/initializers
	// =====================================================================================

	protected static final Log logger = LogFactory.getLog(ArrayFilterer.class);

	// ~ Instance fields
	// ================================================================================================

	private final Set<T> removeList;
	private final T[] list;

	// ~ Constructors
	// ===================================================================================================

	ArrayFilterer(T[] list) {
		this.list = list;

		// Collect the removed objects to a HashSet so that
		// it is fast to lookup them when a filtered array
		// is constructed.
		removeList = new HashSet<T>();
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 *
	 * @see org.springframework.security.acls.afterinvocation.Filterer#getFilteredObject()
	 */
	@SuppressWarnings("unchecked")
	public T[] getFilteredObject() {
		// Recreate an array of same type and filter the removed objects.
		int originalSize = list.length;
		int sizeOfResultingList = originalSize - removeList.size();
		T[] filtered = (T[]) Array.newInstance(list.getClass().getComponentType(),
				sizeOfResultingList);

		for (int i = 0, j = 0; i < list.length; i++) {
			T object = list[i];

			if (!removeList.contains(object)) {
				filtered[j] = object;
				j++;
			}
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Original array contained " + originalSize
					+ " elements; now contains " + sizeOfResultingList + " elements");
		}

		return filtered;
	}

	/**
	 *
	 * @see org.springframework.security.acls.afterinvocation.Filterer#iterator()
	 */
	public Iterator<T> iterator() {
		return new Iterator<T>() {
			private int index = 0;

			public boolean hasNext() {
				return index < list.length;
			}

			public T next() {
				if (!hasNext()) {
					throw new NoSuchElementException();
				}
				return list[index++];
			}

			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	/**
	 *
	 * @see org.springframework.security.acls.afterinvocation.Filterer#remove(java.lang.Object)
	 */
	public void remove(T object) {
		removeList.add(object);
	}
}
