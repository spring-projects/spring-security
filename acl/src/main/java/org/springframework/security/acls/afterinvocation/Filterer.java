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

import java.util.Iterator;

/**
 * Filterer strategy interface.
 *
 * @author Ben Alex
 * @author Paulo Neves
 */
interface Filterer<T> extends Iterable<T> {

	// ~ Methods
	// ========================================================================================================

	/**
	 * Gets the filtered collection or array.
	 * @return the filtered collection or array
	 */
	Object getFilteredObject();

	/**
	 * Returns an iterator over the filtered collection or array.
	 * @return an Iterator
	 */
	Iterator<T> iterator();

	/**
	 * Removes the given object from the resulting list.
	 * @param object the object to be removed
	 */
	void remove(T object);

}
