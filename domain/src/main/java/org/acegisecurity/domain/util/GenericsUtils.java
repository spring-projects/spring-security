package net.sf.acegisecurity.domain.util;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;


/**
 * Provides a helper that locates the declarated generics type of a class.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class GenericsUtils {
    /**
     * Locates the first generic declaration on a class.
     *
     * @param clazz The class to introspect
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
