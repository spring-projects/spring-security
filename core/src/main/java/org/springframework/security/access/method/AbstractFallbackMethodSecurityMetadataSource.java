package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.util.ClassUtils;

/**
 * Abstract implementation of {@link MethodSecurityMetadataSource} that supports both Spring AOP and AspectJ and
 * performs attribute resolution from: 1. specific target method; 2. target class;  3. declaring method;
 * 4. declaring class/interface. Use with {@link DelegatingMethodSecurityMetadataSource} for caching support.
 * <p>
 * This class mimics the behaviour of Spring's <tt>AbstractFallbackTransactionAttributeSource</tt> class.
 * <p>
 * Note that this class cannot extract security metadata where that metadata is expressed by way of
 * a target method/class (i.e. #1 and #2 above) AND the target method/class is encapsulated in another
 * proxy object. Spring Security does not walk a proxy chain to locate the concrete/final target object.
 * Consider making Spring Security your final advisor (so it advises the final target, as opposed to
 * another proxy), move the metadata to declared methods or interfaces the proxy implements, or provide
 * your own replacement <tt>MethodSecurityMetadataSource</tt>.
 *
 * @author Ben Alex
 * @author Luke taylor
 * @since 2.0
 */
public abstract class AbstractFallbackMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {

    public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
        // The method may be on an interface, but we need attributes from the target class.
        // If the target class is null, the method will be unchanged.
        Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
        // First try is the method in the target class.
        Collection<ConfigAttribute> attr = findAttributes(specificMethod, targetClass);
        if (attr != null) {
            return attr;
        }

        // Second try is the config attribute on the target class.
        attr = findAttributes(specificMethod.getDeclaringClass());
        if (attr != null) {
            return attr;
        }

        if (specificMethod != method || targetClass == null) {
            // Fallback is to look at the original method.
            attr = findAttributes(method, method.getDeclaringClass());
            if (attr != null) {
                return attr;
            }
            // Last fallback is the class of the original method.
            return findAttributes(method.getDeclaringClass());
        }
        return null;
    }

    /**
     * Obtains the security metadata applicable to the specified method invocation.
     *
     * <p>
     * Note that the {@link Method#getDeclaringClass()} may not equal the <code>targetClass</code>.
     * Both parameters are provided to assist subclasses which may wish to provide advanced
     * capabilities related to method metadata being "registered" against a method even if the
     * target class does not declare the method (i.e. the subclass may only inherit the method).
     *
     * @param method the method for the current invocation (never <code>null</code>)
     * @param targetClass the target class for the invocation (may be <code>null</code>)
     * @return the security metadata (or null if no metadata applies)
     */
    protected abstract Collection<ConfigAttribute> findAttributes(Method method, Class<?> targetClass);

    /**
     * Obtains the security metadata registered against the specified class.
     *
     * <p>
     * Subclasses should only return metadata expressed at a class level. Subclasses should NOT
     * aggregate metadata for each method registered against a class, as the abstract superclass
     * will separate invoke {@link #findAttributes(Method, Class)} for individual methods as
     * appropriate.
     *
     * @param clazz the target class for the invocation (never <code>null</code>)
     * @return the security metadata (or null if no metadata applies)
     */
    protected abstract Collection<ConfigAttribute> findAttributes(Class<?> clazz);


}
