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

package net.sf.acegisecurity.domain.util;

import java.lang.reflect.Field;


/**
 * A <code>toString()</code> builder that ignores collections.
 *
 * @author Carlos Sanchez
 * @version $Id$
 *
 * @see org.apache.commons.lang.builder.ReflectionToStringBuilder
 */
public class CollectionIgnoringReflectionToStringBuilder
    extends ReflectionToStringBuilder {
    //~ Constructors ===========================================================

    public CollectionIgnoringReflectionToStringBuilder(Object object) {
        super(object);
    }

    //~ Methods ================================================================

    /**
     * Check if the field is a collection and return false in that case.
     *
     * @see org.apache.commons.lang.builder.ReflectionToStringBuilder#accept(java.lang.reflect.Field)
     */
    protected boolean accept(Field field) {
        if (CollectionUtils.isCollection(field.getType())) {
            return false;
        }

        return super.accept(field);
    }
}
