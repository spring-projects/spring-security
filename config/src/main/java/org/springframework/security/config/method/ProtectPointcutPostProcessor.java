package org.springframework.security.config.method;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.weaver.tools.PointcutExpression;
import org.aspectj.weaver.tools.PointcutParser;
import org.aspectj.weaver.tools.PointcutPrimitive;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Parses AspectJ pointcut expressions, registering methods that match the pointcut with a
 * traditional {@link MapBasedMethodSecurityMetadataSource}.
 *
 * <p>
 * This class provides a convenient way of declaring a list of pointcuts, and then
 * having every method of every bean defined in the Spring application context compared with
 * those pointcuts. Where a match is found, the matching method will be registered with the
 * {@link MapBasedMethodSecurityMetadataSource}.
 * <p>
 * It is very important to understand that only the <b>first</b> pointcut that matches a given
 * method will be taken as authoritative for that method. This is why pointcuts should be provided
 * as a <tt>LinkedHashMap</tt>, because their order is very important.
 * <p>
 * Note also that only beans defined in the Spring application context will be examined by this
 * class.
 * <p>
 * Because this class registers method security metadata with {@link MapBasedMethodSecurityMetadataSource},
 * normal Spring Security capabilities such as {@link MethodSecurityMetadataSourceAdvisor} can be used.
 * It does not matter the fact the method metadata was originally obtained from an AspectJ pointcut
 * expression evaluation.
 *
 * @author Ben Alex
 * @since 2.0
 */
final class ProtectPointcutPostProcessor implements BeanPostProcessor {

    private static final Log logger = LogFactory.getLog(ProtectPointcutPostProcessor.class);

    private Map<String,List<ConfigAttribute>> pointcutMap = new LinkedHashMap<String,List<ConfigAttribute>>();
    private MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource;
    private Set<PointcutExpression> pointCutExpressions = new LinkedHashSet<PointcutExpression>();
    private PointcutParser parser;

    public ProtectPointcutPostProcessor(MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource) {
        Assert.notNull(mapBasedMethodSecurityMetadataSource, "MapBasedMethodSecurityMetadataSource to populate is required");
        this.mapBasedMethodSecurityMetadataSource = mapBasedMethodSecurityMetadataSource;

        // Set up AspectJ pointcut expression parser
        Set<PointcutPrimitive> supportedPrimitives = new HashSet<PointcutPrimitive>(3);
        supportedPrimitives.add(PointcutPrimitive.EXECUTION);
        supportedPrimitives.add(PointcutPrimitive.ARGS);
        supportedPrimitives.add(PointcutPrimitive.REFERENCE);
//        supportedPrimitives.add(PointcutPrimitive.THIS);
//        supportedPrimitives.add(PointcutPrimitive.TARGET);
//        supportedPrimitives.add(PointcutPrimitive.WITHIN);
//        supportedPrimitives.add(PointcutPrimitive.AT_ANNOTATION);
//        supportedPrimitives.add(PointcutPrimitive.AT_WITHIN);
//        supportedPrimitives.add(PointcutPrimitive.AT_ARGS);
//        supportedPrimitives.add(PointcutPrimitive.AT_TARGET);
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
            throw new IllegalStateException(e.getMessage());
        }

        // Check to see if any of those methods are compatible with our pointcut expressions
        for (int i = 0; i < methods.length; i++) {
            for (PointcutExpression expression : pointCutExpressions) {
                // Try for the bean class directly
                if (attemptMatch(bean.getClass(), methods[i], expression, beanName)) {
                    // We've found the first expression that matches this method, so move onto the next method now
                    break; // the "while" loop, not the "for" loop
                }
            }
        }

        return bean;
    }

    private boolean attemptMatch(Class<?> targetClass, Method method, PointcutExpression expression, String beanName) {
        // Determine if the presented AspectJ pointcut expression matches this method
        boolean matches = expression.matchesMethodExecution(method).alwaysMatches();

        // Handle accordingly
        if (matches) {
            List<ConfigAttribute> attr = pointcutMap.get(expression.getPointcutExpression());

            if (logger.isDebugEnabled()) {
                logger.debug("AspectJ pointcut expression '" + expression.getPointcutExpression() + "' matches target class '" + targetClass.getName() + "' (bean ID '" + beanName + "') for method '" + method + "'; registering security configuration attribute '" + attr + "'");
            }

            mapBasedMethodSecurityMetadataSource.addSecureMethod(targetClass, method, attr);
        }

        return matches;
    }

    public void setPointcutMap(Map<String, List<ConfigAttribute>> map) {
        Assert.notEmpty(map);
        for (String expression : map.keySet()) {
            List<ConfigAttribute> value = map.get(expression);
            addPointcut(expression, value);
        }
    }

    private void addPointcut(String pointcutExpression, List<ConfigAttribute> definition) {
        Assert.hasText(pointcutExpression, "An AspectJ pointcut expression is required");
        Assert.notNull(definition, "A List of ConfigAttributes is required");
        pointcutExpression = replaceBooleanOperators(pointcutExpression);
        pointcutMap.put(pointcutExpression, definition);
     // Parse the presented AspectJ pointcut expression and add it to the cache
        pointCutExpressions.add(parser.parsePointcutExpression(pointcutExpression));

        if (logger.isDebugEnabled()) {
            logger.debug("AspectJ pointcut expression '" + pointcutExpression + "' registered for security configuration attribute '" + definition + "'");
        }
    }

    /**
     * @see org.springframework.aop.aspectj.AspectJExpressionPointcut#replaceBooleanOperators
     */
    private String replaceBooleanOperators(String pcExpr) {
        pcExpr = StringUtils.replace(pcExpr," and "," && ");
        pcExpr = StringUtils.replace(pcExpr, " or ", " || ");
        pcExpr = StringUtils.replace(pcExpr, " not ", " ! ");
        return pcExpr;
    }

}
