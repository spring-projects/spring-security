/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept;

/**
 * Allows the {@link AbstractSecurityInterceptor} to continue the secure object
 * invocation at the appropriate time.
 * 
 * <P>
 * Concrete <code>AbstractSecurityInterceptor</code> subclasses are required to
 * provide a <code>SecurityInterceptorCallback</code>. This is called by the
 * <code>AbstractSecurityInterceptor</code> at the exact time the secure
 * object should have its processing continued. The exact way processing is
 * continued is specific to the type of secure object. For example, it may
 * involve proceeding with a method invocation, servicing a request, or
 * continuing a filter chain.
 * </p>
 * 
 * <P>
 * The result from processing the secure object should be returned to the
 * <code>AbstractSecurityInterceptor</code>, which in turn will ultimately
 * return it to the calling class.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface SecurityInterceptorCallback {
    //~ Methods ================================================================

    /**
     * Continues to process the secured object.
     *
     * @return the result (if any) from calling the secured object
     */
    public Object proceedWithObject(Object object) throws Throwable;
}
