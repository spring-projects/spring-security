package org.springframework.security.expression.support;

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
import org.springframework.security.intercept.method.AbstractFallbackMethodDefinitionSource;

/**
 * MethodDefinitionSource which extracts metadata from the @PreFilter and @PreAuthorize annotations
 * placed on a method. The metadata is encapsulated in a {@link AbstractExpressionBasedMethodConfigAttribute} instance.
 * <p>
 * Annotations may be specified on classes or methods, and method-specific annotations will take precedence.
 * If you use any annotation and do not specify a pre-authorization condition, then the method will be
 * allowed as if a @PreAuthorize("permitAll") were present.
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
        PreFilter preFilter = AnnotationUtils.findAnnotation(method, PreFilter.class);
        PreAuthorize preAuthorize = AnnotationUtils.findAnnotation(method, PreAuthorize.class);
        PostFilter postFilter = AnnotationUtils.findAnnotation(method, PostFilter.class);
        PostAuthorize postAuthorize = AnnotationUtils.findAnnotation(method, PostAuthorize.class);

        if (preFilter == null && preAuthorize == null && postFilter == null && postAuthorize == null ) {
            // There is no method level meta-data so return and allow parent to query at class-level
            return null;
        }

        // There is at least one non-null value, so the parent class will not query for class-specific annotations
        // and we have to locate them here as appropriate.

        if (preAuthorize == null) {
            preAuthorize = (PreAuthorize)targetClass.getAnnotation(PreAuthorize.class);
        }

        if (preFilter == null) {
            preFilter = (PreFilter)targetClass.getAnnotation(PreFilter.class);
        }

        if (postFilter == null) {
            // TODO: Can we check for void methods and throw an exception here?
            postFilter = (PostFilter)targetClass.getAnnotation(PostFilter.class);
        }

        if (postAuthorize == null) {
            postAuthorize = (PostAuthorize)targetClass.getAnnotation(PostAuthorize.class);
        }

        return createAttributeList(preFilter, preAuthorize, postFilter, postAuthorize);
    }

    @Override
    protected List<ConfigAttribute> findAttributes(Class targetClass) {
        PreFilter preFilter = (PreFilter)targetClass.getAnnotation(PreFilter.class);
        PreAuthorize preAuthorize = (PreAuthorize)targetClass.getAnnotation(PreAuthorize.class);
        PostFilter postFilter = (PostFilter)targetClass.getAnnotation(PostFilter.class);
        PostAuthorize postAuthorize = (PostAuthorize)targetClass.getAnnotation(PostAuthorize.class);

        if (preFilter == null && preAuthorize == null && postFilter == null && postAuthorize == null ) {
            // There is no class level meta-data (and by implication no meta-data at all)
            return null;
        }

        return createAttributeList(preFilter, preAuthorize, postFilter, postAuthorize);
    }

    public Collection<List<? extends ConfigAttribute>> getConfigAttributeDefinitions() {
        return null;
    }

    private List<ConfigAttribute> createAttributeList(PreFilter preFilter, PreAuthorize preAuthorize,
            PostFilter postFilter, PostAuthorize postAuthorize) {
        ConfigAttribute pre = null;
        ConfigAttribute post = null;

        // TODO: Optimization of permitAll
        String preAuthorizeExpression = preAuthorize == null ? "permitAll()" : preAuthorize.value();
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
