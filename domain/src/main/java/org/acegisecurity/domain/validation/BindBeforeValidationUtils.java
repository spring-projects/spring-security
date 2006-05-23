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

package org.acegisecurity.domain.validation;

import org.springframework.util.Assert;

import org.springframework.validation.BindException;


/**
 * Convenience class that invokes the {@link BindBeforeValidation} interface if the passed domain object has
 * requested it.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BindBeforeValidationUtils {
    //~ Methods ========================================================================================================

    /**
     * Call {@link BindBeforeValidation#bindSupport()} if the domain object requests it.
     *
     * @param domainObject to attempt to bind (never <code>null</code>)
     *
     * @throws BindException if the binding failed
     */
    public static void bindIfRequired(Object domainObject)
        throws BindException {
        Assert.notNull(domainObject);

        if (BindBeforeValidation.class.isAssignableFrom(domainObject.getClass())) {
            BindBeforeValidation bbv = (BindBeforeValidation) domainObject;
            bbv.bindSupport();
        }
    }
}
