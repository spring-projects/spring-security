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

import java.util.List;


/**
 * Indicates a concrete class capable of introspecting a domain object for its
 * immediate children.
 * 
 * <p>
 * Implementations may use a choice of reflective introspection or querying a
 * persistence metadata API to locate the internal children.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface IntrospectionManager {
    //~ Methods ========================================================================================================

    /**
     * Locates any direct children of a domain object.<p>Typically used with a {@link ValidationManager} to
     * validate each of the located children.</p>
     *  <P>Implementations should only add the <b>immediate layer of children</b>. Grandchildren,
     * great-grandchildren etc should not be added.</p>
     *
     * @param parentObject the immediate parent which all children should share (guaranteed to never be
     *        <code>null</code>)
     * @param allObjects the list to which this method should append each immediate child (guaranteed to never be
     *        <code>null</code>)
     */
    public void obtainImmediateChildren(Object parentObject, List<Object> allObjects);
}
