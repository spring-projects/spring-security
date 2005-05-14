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

package net.sf.acegisecurity.domain.dao;

import org.springframework.util.Assert;



/**
 * Convenience methods that support initialization of lazily loaded collections
 * and associations using DAOs and other objects that implement
 * {@link net.sf.acegisecurity.domain.dao.InitializationCapable}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InitializationUtils {
    //~ Methods ================================================================

    /**
     * Initializes the passed entity using the passed
     * DAO or services layer <code>Object</code> (provided that the passed
     * <code>Object</code> implements <code>InitializationCapable</code>).
     *
     * @param daoOrServices the potential source for
     *        <code>InitializationCapable</code> services (never <code>null</code>)
     * @param entity to evict (can be <code>null</code>)
     */
    public static void initializeIfRequired(Object daoOrServices,
        Object entity) {
		Assert.notNull(daoOrServices);
		if (daoOrServices instanceof InitializationCapable) {
			((InitializationCapable) daoOrServices).initialize(entity);
		}
    }
	
	/**
	 * Indicates whether the passed entity has been initialized, by delegating
	 * to the passed daoOrServices (provided that the passed daoOrServices
	 * implements <code>InitializationCapable</code>.
	 * 
	 * @param entity to determine whether initialized or not
	 * @return <code>true</code> if initialized, <code>false</code> if it is
	 * 			uninitialized or the passed daoOrServices does not provide
	 * 			initialization querying support
	 */
	public static boolean isInitialized(Object daoOrServices, Object entity) {
		Assert.notNull(daoOrServices);
		if (daoOrServices instanceof InitializationCapable) {
			return ((InitializationCapable) daoOrServices).isInitialized(entity);
		}
		return false;
	}
}
