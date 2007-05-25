package org.acegisecurity.util;

import java.lang.reflect.Method;
import java.util.Map;

import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

/**
 * Proivdes common logic for manipulating classes implementing the Spring
 * {@link Ordered} interface.
 * 
 * @author Ben Alex
 */
public abstract class OrderedUtils {
	/**
	 * Introspects the application context for a single instance of <code>sourceClass</code>. If found, the order from the source
	 * class instance is copied into the <code>destinationObject</code>. If more than one instance of <code>sourceClass</code>
	 * is found, the method throws <code>IllegalStateException</code>.
	 * 
	 * <p>The <code>destinationObject</code> is required to provide a public <code>setOrder(int)</code> method to permit
	 * mutation of the order property.
	 * 
	 * @param sourceClass to locate in the application context (must be assignable to Ordered)
	 * @param applicationContext to locate the class
	 * @param destinationObject to copy the order into (must provide public setOrder(int) method)
	 * @param skipIfMoreThanOneCandidateSourceClassInstance if the application context provides more than one potential source, skip modifications (if false, the first located matching source will be used)
	 * @return whether or not the destination class was updated
	 */
	public static boolean copyOrderFromOtherClass(Class sourceClass, ApplicationContext applicationContext, Object destinationObject, boolean skipIfMoreThanOneCandidateSourceClassInstance) {
		Assert.notNull(sourceClass, "Source class required");
		Assert.notNull(applicationContext, "ApplicationContext required");
		Assert.notNull(destinationObject, "Destination object required");
		Assert.isAssignable(Ordered.class, sourceClass, "Source class " + sourceClass + " must be assignable to Ordered");
		Map map = applicationContext.getBeansOfType(sourceClass);
		if (map.size() == 0) {
			return false;
		} else if (map.size() > 1 && skipIfMoreThanOneCandidateSourceClassInstance) {
			return false;
		} else {
			copyOrderFromOtherObject((Ordered)map.values().iterator().next(), destinationObject);
			return true;
		}
	}
	
	/**
	 * Copies the order property from the <code>sourceObject</code> into the <code>destinationObject</code>.
	 * 
	 * <p>The <code>destinationObject</code> is required to provide a public <code>setOrder(int)</code> method to permit
	 * mutation of the order property.
	 * 
	 * @param sourceObject to copy the order from
	 * @param destinationObject to copy the order into (must provide public setOrder(int) method)
	 */
	public static void copyOrderFromOtherObject(Ordered sourceObject, Object destinationObject) {
		Assert.notNull(sourceObject, "Source object required");
		Assert.notNull(destinationObject, "Destination object required");
		Method m = ReflectionUtils.findMethod(destinationObject.getClass(), "setOrder", new Class[] {int.class});
		Assert.notNull(m, "Method setOrder(int) not found on " + destinationObject.getClass());
		ReflectionUtils.invokeMethod(m, destinationObject, new Object[] {new Integer(sourceObject.getOrder())});
	}
	
}
