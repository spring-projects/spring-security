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

package net.sf.acegisecurity;

import org.aopalliance.intercept.MethodInvocation;

import java.util.Iterator;


/**
 * Implemented by classes that store {@link ConfigAttributeDefinition}s and can
 * identify the appropriate <code>ConfigAttributeDefinition</code> that
 * applies for the current method call.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface MethodDefinitionSource {
    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @param invocation the method being called
     *
     * @return the <code>ConfigAttributeDefinition</code> that applies to the
     *         passed method call
     */
    public ConfigAttributeDefinition getAttributes(MethodInvocation invocation);

    /**
     * If available, all of the <code>ConfigAttributeDefinition</code>s defined
     * by the implementing class.
     *
     * @return an iterator over all the <code>ConfigAttributeDefinition</code>s
     *         or <code>null</code> if unsupported
     */
    public Iterator getConfigAttributeDefinitions();
}
