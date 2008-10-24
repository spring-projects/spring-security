package org.springframework.security.expression.support;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.ParseException;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.config.SecurityConfigurationException;
import org.springframework.security.expression.annotation.PostAuthorize;
import org.springframework.security.expression.annotation.PostFilter;
import org.springframework.security.expression.annotation.PreAuthorize;
import org.springframework.security.expression.annotation.PreFilter;
import org.springframework.security.intercept.method.AbstractFallbackMethodDefinitionSource;

/**
 * MethodDefinitionSource which extracts metadata from the @PreFilter and @PreAuthorize annotations
 * placed on a method. The metadata is encapsulated in a {@link AbstractExpressionBasedMethodConfigAttribute} instance.
 *
 * @see MethodExpressionVoter
 *
 * @author Luke Taylor
 * @since 2.5
 * @version $Id$
 */
public class ExpressionAnnotationMethodDefinitionSource extends AbstractFallbackMethodDefinitionSource {

    @Override
    protected List<ConfigAttribute> findAttributes(Method method, Class targetClass) {
        ConfigAttribute pre = processPreInvocationAnnotations(AnnotationUtils.findAnnotation(method, PreFilter.class),
                AnnotationUtils.findAnnotation(method, PreAuthorize.class));
        ConfigAttribute post = processPostInvocationAnnotations(AnnotationUtils.findAnnotation(method, PostFilter.class),
                AnnotationUtils.findAnnotation(method, PostAuthorize.class));

        if (pre == null && post == null) {
            return null;
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

    @Override
    protected List<ConfigAttribute> findAttributes(Class targetClass) {
        ConfigAttribute pre = processPreInvocationAnnotations((PreFilter)targetClass.getAnnotation(PreFilter.class),
                (PreAuthorize)targetClass.getAnnotation(PreAuthorize.class));
        ConfigAttribute post = processPostInvocationAnnotations((PostFilter)targetClass.getAnnotation(PostFilter.class),
                (PostAuthorize)targetClass.getAnnotation(PostAuthorize.class));

        if (pre == null && post == null) {
            return null;
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

    public Collection getConfigAttributeDefinitions() {
        return null;
    }

    private ConfigAttribute processPreInvocationAnnotations(PreFilter preFilter, PreAuthorize preAuthz) {
        if (preFilter == null && preAuthz == null) {
            return null;
        }

        String preAuthorizeExpression = preAuthz == null ? null : preAuthz.value();
        String preFilterExpression = preFilter == null ? null : preFilter.value();
        String filterObject = preFilter == null ? null : preFilter.filterTarget();

        try {
            return new PreInvocationExpressionBasedMethodConfigAttribute(preFilterExpression, filterObject, preAuthorizeExpression);
        } catch (ParseException e) {
            throw new SecurityConfigurationException("Failed to parse expression '" + e.getExpressionString() + "'", e);
        }
    }

    private ConfigAttribute processPostInvocationAnnotations(PostFilter postFilter, PostAuthorize postAuthz) {
        if (postFilter == null && postAuthz == null) {
            return null;
        }

        String postAuthorizeExpression = postAuthz == null ? null : postAuthz.value();
        String postFilterExpression = postFilter == null ? null : postFilter.value();

        try {
            return new PostInvocationExpressionBasedMethodConfigAttribute(postFilterExpression, postAuthorizeExpression);
        } catch (ParseException e) {
            throw new SecurityConfigurationException("Failed to parse expression '" + e.getExpressionString() + "'", e);
        }
    }
}
