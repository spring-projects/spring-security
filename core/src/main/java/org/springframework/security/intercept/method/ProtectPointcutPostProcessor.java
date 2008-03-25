package org.springframework.security.intercept.method;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.weaver.tools.PointcutExpression;
import org.aspectj.weaver.tools.PointcutParser;
import org.aspectj.weaver.tools.PointcutPrimitive;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.method.aopalliance.MethodDefinitionSourceAdvisor;
import org.springframework.util.Assert;

/**
 * Parses AspectJ pointcut expressions, registering methods that match the pointcut with a
 * traditional {@link MapBasedMethodDefinitionSource}.
 * 
 * <p>
 * This class provides a convenient way of declaring a list of pointcuts, and then
 * having every method of every bean defined in the Spring application context compared with
 * those pointcuts. Where a match is found, the matching method will be registered with the
 * {@link MapBasedMethodDefinitionSource}.
 * </p>
 * 
 * <p>
 * It is very important to understand that only the <b>first</b> pointcut that matches a given
 * method will be taken as authoritative for that method. This is why pointcuts should be provided
 * as a <tt>LinkedHashMap</tt>, because their order is very important.
 * </p>
 * 
 * <p>
 * Note also that only beans defined in the Spring application context will be examined by this
 * class. 
 * </p>
 * 
 * <p>
 * Because this class registers method security metadata with {@link MapBasedMethodDefinitionSource},
 * normal Spring Security capabilities such as {@link MethodDefinitionSourceAdvisor} can be used.
 * It does not matter the fact the method metadata was originally obtained from an AspectJ pointcut
 * expression evaluation.
 * </p>
 *
 * @author Ben Alex
 * @verion $Id$
 *
 */
public final class ProtectPointcutPostProcessor implements BeanPostProcessor {

    private static final Log logger = LogFactory.getLog(ProtectPointcutPostProcessor.class);

    private Map pointcutMap = new LinkedHashMap(); /** Key: string-based pointcut, value: ConfigAttributeDefinition */
	private MapBasedMethodDefinitionSource mapBasedMethodDefinitionSource;
	private PointcutParser parser;
	
	public ProtectPointcutPostProcessor(MapBasedMethodDefinitionSource mapBasedMethodDefinitionSource) {
		Assert.notNull(mapBasedMethodDefinitionSource, "MapBasedMethodDefinitionSource to populate is required");
		this.mapBasedMethodDefinitionSource = mapBasedMethodDefinitionSource;
		
		// Setup AspectJ pointcut expression parser
		Set supportedPrimitives = new HashSet();
		supportedPrimitives.add(PointcutPrimitive.EXECUTION);
		supportedPrimitives.add(PointcutPrimitive.ARGS);
		supportedPrimitives.add(PointcutPrimitive.REFERENCE);
//		supportedPrimitives.add(PointcutPrimitive.THIS);
//		supportedPrimitives.add(PointcutPrimitive.TARGET);
//		supportedPrimitives.add(PointcutPrimitive.WITHIN);
//		supportedPrimitives.add(PointcutPrimitive.AT_ANNOTATION);
//		supportedPrimitives.add(PointcutPrimitive.AT_WITHIN);
//		supportedPrimitives.add(PointcutPrimitive.AT_ARGS);
//		supportedPrimitives.add(PointcutPrimitive.AT_TARGET);
		parser = PointcutParser.getPointcutParserSupportingSpecifiedPrimitivesAndUsingContextClassloaderForResolution(supportedPrimitives);
	}

	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		// Obtain methods for the present bean
		Method[] methods;
		try {
			methods = bean.getClass().getMethods();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
		
		// Check to see if any of those methods are compatible with our pointcut expressions
		for (int i = 0; i < methods.length; i++) {
			Iterator iter = pointcutMap.keySet().iterator();
			while (iter.hasNext()) {
				String ex = iter.next().toString();
				
				// Parse the presented AspectJ pointcut expression
				PointcutExpression expression = parser.parsePointcutExpression(ex);

				// Try for the bean class directly
				if (attemptMatch(bean.getClass(), methods[i], expression, beanName)) {
					// We've found the first expression that matches this method, so move onto the next method now
					break; // the "while" loop, not the "for" loop
				}
			}
		}
		
		return bean;
	}
	
	private boolean attemptMatch(Class targetClass, Method method, PointcutExpression expression, String beanName) {
		// Determine if the presented AspectJ pointcut expression matches this method
		boolean matches = expression.matchesMethodExecution(method).alwaysMatches();
		
		// Handle accordingly
		if (matches) {
			ConfigAttributeDefinition attr = (ConfigAttributeDefinition) pointcutMap.get(expression.getPointcutExpression());
			
			if (logger.isDebugEnabled()) {
				logger.debug("AspectJ pointcut expression '" + expression.getPointcutExpression() + "' matches target class '" + targetClass.getName() + "' (bean ID '" + beanName + "') for method '" + method + "'; registering security configuration attribute '" + attr + "'");
			}
			
			mapBasedMethodDefinitionSource.addSecureMethod(targetClass, method.getName(), attr);
		}
		
		return matches;
	}
	
	public void setPointcutMap(Map map) {
		Assert.notEmpty(map);
		Iterator i = map.keySet().iterator();
		while (i.hasNext()) {
			String expression = i.next().toString();
			Object value = map.get(expression);
			Assert.isInstanceOf(ConfigAttributeDefinition.class, value, "Map keys must be instances of ConfigAttributeDefinition");
			addPointcut(expression, (ConfigAttributeDefinition) value);
		}
	}

	public void addPointcut(String pointcutExpression, ConfigAttributeDefinition definition) {
		Assert.hasText(pointcutExpression, "An AspecTJ pointcut expression is required");
		Assert.notNull(definition, "ConfigAttributeDefinition required");
		pointcutMap.put(pointcutExpression, definition);
		
		if (logger.isDebugEnabled()) {
			logger.debug("AspectJ pointcut expression '" + pointcutExpression + "' registered for security configuration attribute '" + definition + "'");
		}
	}
	
}
