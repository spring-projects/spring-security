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

import org.springframework.validation.BindException;


/**
 * Indicates a domain object wishes to perform additional binding before the
 * <code>Validator</code> is called.
 * 
 * <p>
 * Typically this type of binding sets up private or protected properties that
 * the end user is not responsible for modifying. Whilst generally this can be
 * done by adding a hook to every property setter, the
 * <code>BindBeforeValidation</code> interface provides an AOP-style approach
 * that ensures missing hooks do not cause invalid object state.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface BindBeforeValidation {
    //~ Methods ================================================================

    /**
     * This method will be called by infrastructure code before attempting to
     * validate the object. Given this method is called prior to validation,
     * implementations of this method should <b>not</b> assume the object is
     * in a valid state.
     * 
     * <p>
     * Implementations should modify the object as required so that the
     * <code>Validator</code> will succeed if user-controllable properties are
     * correct.
     * </p>
     *
     * @throws BindException if there are problems that the method wish to
     *         advise (note that the <code>Validator</code> should be allowed
     *         to determine errors in most cases, rather than this method
     *         doing so)
     */
    public void bindSupport() throws BindException;
}
