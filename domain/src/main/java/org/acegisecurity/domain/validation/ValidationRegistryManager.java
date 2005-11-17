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

package org.acegisecurity.domain.validation;

import org.springframework.validation.Validator;


/**
 * <code>ValidationRegistryManager</code> implementations are able to
 * authoritatively return a <code>Validator</code> instance that is suitable
 * for a given domain object.
 * 
 * <p>
 * Implementations are free to implement their own strategy for maintaining the
 * list of <code>Validator</code>s, or create them on-demand if preferred.
 * This interface is non-prescriptive.
 * </p>
 *
 * @author Matthew E. Porter
 * @author Ben Alex
 * @version $Id$
 */
public interface ValidationRegistryManager {
    //~ Methods ================================================================

    /**
     * Obtains the <code>Validator</code> that applies for a given domain
     * object class.
     *
     * @param domainClass that a <code>Validator</code> is required for
     *
     * @return the <code>Validator</code>, or <code>null</code> if no
     *         <code>Validator</code> is known for the indicated
     *         <code>domainClass</code>
     */
    public Validator findValidator(Class domainClass);
}
