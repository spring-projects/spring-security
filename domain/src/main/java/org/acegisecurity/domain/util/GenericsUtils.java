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

package org.acegisecurity.domain.util;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;


/**
 * Provides a helper that locates the declarated generics type of a class.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class GenericsUtils {
    //~ Methods ========================================================================================================

    /**
     * Locates the first generic declaration on a class.
     *
     * @param clazz The class to introspect
     *
     * @return the first generic declaration, or <code>null</code> if cannot be determined
     */
    public static Class getGeneric(Class clazz) {
        Type genType = clazz.getGenericSuperclass();

        if (genType instanceof ParameterizedType) {
            Type[] params = ((ParameterizedType) genType).getActualTypeArguments();

            if ((params != null) && (params.length == 1)) {
                return (Class) params[0];
            }
        }

        return null;
    }
}
