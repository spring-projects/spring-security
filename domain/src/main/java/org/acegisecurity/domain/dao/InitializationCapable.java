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

/**
 * Indicates an implementation capable of initializing an object, such that
 * any lazy loading is guaranteed to have been completed.
 * 
 * <p>
 * Structured as a separate interface (rather than a subclass of
 * <code>Dao</code>), as it is not required for all persistence strategies.
 * </p>
 * 
 * <p>In general the recommended approach to lazy initialization is as follows:
 * 
 * <ul>
 * 
 * <li>Do not use OpenSessionInView. You can use it if you like, but you'll have
 * less difficulty in the long-run if you plan your use cases and adopt the other
 * recommendations below.</li>
 * 
 * <li>Set your mapping documents to use lazy initialization where possible. Only
 * mark an association as eager loaded if <b>every</b> single use case requires it
 * and you are happy with this eager loading being reflected in a mapping document
 * instead of Java code.</li>
 * 
 * <li>Subclass the <code>Dao</code> implementation and add use case specific finder/read
 * methods that will use the persistence engine's eager loading capabilities. <b>Generally
 * this approach will deliver the best overall application performance</b>, as you will
 * (i) only be eager loading if and when required and (ii) you are directly using the
 * persistence engine capabilities to do so. It also places the eager loading management
 * in the <code>Dao</code>, which is an ideal location to standardise it.</li>
 * 
 * <li>If you would prefer to achieve persistence engine independence and/or reduce
 * the number of <code>Dao</code> subclasses that exist in your application, you may
 * prefer to modify your services layer so that it uses the <code>InitializationCapable</code>
 * interface. However, this interface should be used judiciously given that it does
 * not allow the persistence engine to optimise eager loading for given use cases
 * and (probably) will lead to a mixture of places where fetching logic can be obtained.</li>
 * 
 * <p>Generally your best strategy is subclassing the <code>Dao</code>. It means the
 * most code, but it's also by far the most efficient and offers flexibility to further
 * fine-tune specific use cases. Whichever way you go, try to be consistent throughout
 * your application (this will ease your future migration and troubleshooting needs).
 * 
 * @author Ben Alex
 * @version $Id$
 */
public interface InitializationCapable {
    //~ Methods ================================================================

    /**
     * Initializes the indicated object.
     * 
     * <p>
     * May throw an exception if the implementation so desires.
     * </p>
     *
     * @param entity to initialize
     */
    public void initialize(Object entity);
}
