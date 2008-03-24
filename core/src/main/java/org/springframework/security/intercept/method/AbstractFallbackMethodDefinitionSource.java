package org.springframework.security.intercept.method;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.CodeSignature;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ObjectUtils;

/**
 * Abstract implementation of {@link MethodDefinitionSource} that supports both Spring AOP and AspectJ and
 * caches configuration attribute resolution from: 1. specific target method; 2. target class;  3. declaring method;
 * 4. declaring class/interface.
 * 
 * <p>
 * This class mimics the behaviour of Spring's AbstractFallbackTransactionAttributeSource class.
 * </p>
 * 
 * <p>
 * Note that this class cannot extract security metadata where that metadata is expressed by way of
 * a target method/class (ie #1 and #2 above) AND the target method/class is encapsulated in another
 * proxy object. Spring Security does not walk a proxy chain to locate the concrete/final target object.
 * Consider making Spring Security your final advisor (so it advises the final target, as opposed to
 * another proxy), move the metadata to declared methods or interfaces the proxy implements, or provide
 * your own replacement <tt>MethodDefinitionSource</tt>.
 * </p>
 * 
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractFallbackMethodDefinitionSource implements MethodDefinitionSource {

    private static final Log logger = LogFactory.getLog(AbstractFallbackMethodDefinitionSource.class);
	private final static Object NULL_CONFIG_ATTRIBUTE = new Object();
    private final Map attributeCache = new HashMap();

    public ConfigAttributeDefinition getAttributes(Object object) throws IllegalArgumentException {
        Assert.notNull(object, "Object cannot be null");

        if (object instanceof MethodInvocation) {
        	MethodInvocation mi = (MethodInvocation) object;
            return getAttributes(mi.getMethod(), mi.getThis().getClass());
        }

        if (object instanceof JoinPoint) {
            JoinPoint jp = (JoinPoint) object;
            Class targetClass = jp.getTarget().getClass();
            String targetMethodName = jp.getStaticPart().getSignature().getName();
            Class[] types = ((CodeSignature) jp.getStaticPart().getSignature()).getParameterTypes();
            Class declaringType = ((CodeSignature) jp.getStaticPart().getSignature()).getDeclaringType();

            Method method = ClassUtils.getMethodIfAvailable(declaringType, targetMethodName, types);
            Assert.notNull(method, "Could not obtain target method from JoinPoint: '"+ jp + "'");
            
            return getAttributes(method, targetClass);
        }

        throw new IllegalArgumentException("Object must be a MethodInvocation or JoinPoint");
    }
    
    public final boolean supports(Class clazz) {
        return (MethodInvocation.class.isAssignableFrom(clazz) || JoinPoint.class.isAssignableFrom(clazz));
    }
    
    public ConfigAttributeDefinition getAttributes(Method method, Class targetClass) {
		// First, see if we have a cached value.
		Object cacheKey = new DefaultCacheKey(method, targetClass);
		synchronized (this.attributeCache) {
			Object cached = this.attributeCache.get(cacheKey);
			if (cached != null) {
				// Value will either be canonical value indicating there is no config attribute,
				// or an actual config attribute.
				if (cached == NULL_CONFIG_ATTRIBUTE) {
					return null;
				}
				else {
					return (ConfigAttributeDefinition) cached;
				}
			}
			else {
				// We need to work it out.
				ConfigAttributeDefinition cfgAtt = computeAttributes(method, targetClass);
				// Put it in the cache.
				if (cfgAtt == null) {
					this.attributeCache.put(cacheKey, NULL_CONFIG_ATTRIBUTE);
				}
				else {
					if (logger.isDebugEnabled()) {
						logger.debug("Adding security method [" + cacheKey + "] with attribute [" + cfgAtt + "]");
					}
					this.attributeCache.put(cacheKey, cfgAtt);
				}
				return cfgAtt;
			}
		}
    }
    
    /**
     * 
	 * @param method the method for the current invocation (never <code>null</code>)
	 * @param targetClass the target class for this invocation (may be <code>null</code>)
     * @return
     */
    private ConfigAttributeDefinition computeAttributes(Method method, Class targetClass) {
    	// The method may be on an interface, but we need attributes from the target class.
		// If the target class is null, the method will be unchanged.
		Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
		// First try is the method in the target class.
		ConfigAttributeDefinition attr = findAttributes(specificMethod, targetClass);
		if (attr != null) {
			return attr;
		}

		// Second try is the config attribute on the target class.
		attr = findAttributes(specificMethod.getDeclaringClass());
		if (attr != null) {
			return attr;
		}

		if (specificMethod != method) {
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
     * target class does not declare the method (ie the subclass may only inherit the method).
     * 
     * @param method the method for the current invocation (never <code>null</code>)
     * @param targetClass the target class for the invocation (may be <code>null</code>)
     * @return the security metadata (or null if no metadata applies)
     */
    protected abstract ConfigAttributeDefinition findAttributes(Method method, Class targetClass);
    
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
    protected abstract ConfigAttributeDefinition findAttributes(Class clazz);
    
	private static class DefaultCacheKey {

		private final Method method;
		private final Class targetClass;

		public DefaultCacheKey(Method method, Class targetClass) {
			this.method = method;
			this.targetClass = targetClass;
		}

		public boolean equals(Object other) {
			if (this == other) {
				return true;
			}
			if (!(other instanceof DefaultCacheKey)) {
				return false;
			}
			DefaultCacheKey otherKey = (DefaultCacheKey) other;
			return (this.method.equals(otherKey.method) &&
					ObjectUtils.nullSafeEquals(this.targetClass, otherKey.targetClass));
		}

		public int hashCode() {
			return this.method.hashCode() * 21 + (this.targetClass != null ? this.targetClass.hashCode() : 0);
		}

		public String toString() {
			return "CacheKey[" + (targetClass == null ? "-" : targetClass.getName()) + "; " + method + "]";
		}
}
    
}
