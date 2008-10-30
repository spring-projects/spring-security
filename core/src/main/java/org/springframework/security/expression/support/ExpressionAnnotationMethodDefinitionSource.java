package org.springframework.security.expression.support;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.ParseException;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.config.SecurityConfigurationException;
import org.springframework.security.expression.annotation.PostAuthorize;
import org.springframework.security.expression.annotation.PostFilter;
import org.springframework.security.expression.annotation.PreAuthorize;
import org.springframework.security.expression.annotation.PreFilter;
import org.springframework.security.intercept.method.AbstractMethodDefinitionSource;
import org.springframework.util.ClassUtils;

/**
 * MethodDefinitionSource which extracts metadata from the @PreFilter and @PreAuthorize annotations
 * placed on a method. The metadata is encapsulated in a {@link AbstractExpressionBasedMethodConfigAttribute} instance.
 * <p>
 * Annotations may be specified on classes or methods, and method-specific annotations will take precedence.
 * If you use any annotation and do not specify a pre-authorization condition, then the method will be
 * allowed as if a @PreAuthorize("permitAll") were present.
 * <p>
 * Since we are handling multiple annotations here, it's possible that we may have to combine annotations defined in
 * multiple locations for a single method - they may be defined on the method itself, or at interface or class level.
 *
 * @see MethodExpressionVoter
 *
 * @author Luke Taylor
 * @since 2.5
 * @version $Id$
 */
public class ExpressionAnnotationMethodDefinitionSource extends AbstractMethodDefinitionSource {

    public List<ConfigAttribute> getAttributes(Method method, Class targetClass) {
        if (method.getDeclaringClass() == Object.class) {
            return null;
        }

        logger.debug("Looking for expression annotations for method '" +
                method.getName() + "' on target class '" + targetClass + "'");
        PreFilter preFilter = findAnnotation(method, targetClass, PreFilter.class);
        PreAuthorize preAuthorize = findAnnotation(method, targetClass, PreAuthorize.class);
        PostFilter postFilter = findAnnotation(method, targetClass, PostFilter.class);
     // TODO: Can we check for void methods and throw an exception here?
        PostAuthorize postAuthorize = findAnnotation(method, targetClass, PostAuthorize.class);

        if (preFilter == null && preAuthorize == null && postFilter == null && postAuthorize == null ) {
            // There is no meta-data so return
            logger.debug("No expression annotations found");
            return null;
        }

        return createAttributeList(preFilter, preAuthorize, postFilter, postAuthorize);
    }

    /**
     * See {@link org.springframework.security.intercept.method.AbstractFallbackMethodDefinitionSource#getAttributes(Method, Class)}
     * for the logic of this method. The ordering here is slightly different in that we consider method-specific
     * annotations on an interface before class-level ones.
     */
    private <A  extends Annotation> A findAnnotation(Method method, Class targetClass, Class<A> annotationClass) {
        // The method may be on an interface, but we need attributes from the target class.
        // If the target class is null, the method will be unchanged.
        Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
        A annotation = AnnotationUtils.findAnnotation(specificMethod, annotationClass);

        if (annotation != null) {
            logger.debug(annotation + " found on specific method: " + specificMethod);
            return annotation;
        }

        // Check the original (e.g. interface) method
        if (specificMethod != method) {
            annotation = AnnotationUtils.findAnnotation(method, annotationClass);

            if (annotation != null) {
                logger.debug(annotation + " found on: " + method);
                return annotation;
            }
        }

        // Check the class-level (note declaringClass, not targetClass, which may not actually implement the method)
        annotation = specificMethod.getDeclaringClass().getAnnotation(annotationClass);

        if (annotation != null) {
            logger.debug(annotation + " found on: " + specificMethod.getDeclaringClass().getName());
            return annotation;
        }

        // Check for a possible interface annotation which would not be inherited by the declaring class
        if (specificMethod != method) {
            annotation = method.getDeclaringClass().getAnnotation(annotationClass);

            if (annotation != null) {
                logger.debug(annotation + " found on: " + method.getDeclaringClass().getName());
                return annotation;
            }
        }

        return null;
    }

    public Collection<List<? extends ConfigAttribute>> getAllConfigAttributes() {
        return null;
    }

    private List<ConfigAttribute> createAttributeList(PreFilter preFilter, PreAuthorize preAuthorize,
            PostFilter postFilter, PostAuthorize postAuthorize) {
        ConfigAttribute pre = null;
        ConfigAttribute post = null;

        // TODO: Optimization of permitAll
        String preAuthorizeExpression = preAuthorize == null ? "permitAll" : preAuthorize.value();
        String preFilterExpression = preFilter == null ? null : preFilter.value();
        String filterObject = preFilter == null ? null : preFilter.filterTarget();
        String postAuthorizeExpression = postAuthorize == null ? null : postAuthorize.value();
        String postFilterExpression = postFilter == null ? null : postFilter.value();

        try {
            pre = new PreInvocationExpressionConfigAttribute(preFilterExpression, filterObject, preAuthorizeExpression);
            if (postFilterExpression != null || postAuthorizeExpression != null) {
                post = new PostInvocationExpressionConfigAttribute(postFilterExpression, postAuthorizeExpression);
            }
        } catch (ParseException e) {
            throw new SecurityConfigurationException("Failed to parse expression '" + e.getExpressionString() + "'", e);
        }

        List<ConfigAttribute> attrs = new ArrayList<ConfigAttribute>(2);
        if (pre != null) {
            attrs.add(pre);
        }

        if (post != null) {
            attrs.add(post);
        }

        return attrs;
    }
}
