package org.springframework.security.access.prepost;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.*;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource;
import org.springframework.util.ClassUtils;

/**
 * <tt>MethodSecurityMetadataSource</tt> which extracts metadata from the @PreFilter and @PreAuthorize annotations
 * placed on a method. This class is merely responsible for locating the relevant annotations (if any). It delegates
 * the actual <tt>ConfigAttribute</tt> creation to its {@link PrePostInvocationAttributeFactory}, thus
 * decoupling itself from the mechanism which will enforce the annotations' behaviour.
 * <p>
 * Annotations may be specified on classes or methods, and method-specific annotations will take precedence.
 * If you use any annotation and do not specify a pre-authorization condition, then the method will be
 * allowed as if a @PreAuthorize("permitAll") were present.
 * <p>
 * Since we are handling multiple annotations here, it's possible that we may have to combine annotations defined in
 * multiple locations for a single method - they may be defined on the method itself, or at interface or class level.
 *
 * @see PreInvocationAuthorizationAdviceVoter
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PrePostAnnotationSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {

    private final PrePostInvocationAttributeFactory attributeFactory;

    public PrePostAnnotationSecurityMetadataSource(PrePostInvocationAttributeFactory attributeFactory) {
        this.attributeFactory = attributeFactory;
    }

    public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
        if (method.getDeclaringClass() == Object.class) {
            return Collections.emptyList();
        }

        logger.trace("Looking for Pre/Post annotations for method '" +
                method.getName() + "' on target class '" + targetClass + "'");
        PreFilter preFilter = findAnnotation(method, targetClass, PreFilter.class);
        PreAuthorize preAuthorize = findAnnotation(method, targetClass, PreAuthorize.class);
        PostFilter postFilter = findAnnotation(method, targetClass, PostFilter.class);
     // TODO: Can we check for void methods and throw an exception here?
        PostAuthorize postAuthorize = findAnnotation(method, targetClass, PostAuthorize.class);

        if (preFilter == null && preAuthorize == null && postFilter == null && postAuthorize == null ) {
            // There is no meta-data so return
            logger.trace("No expression annotations found");
            return Collections.emptyList();
        }

        String preFilterAttribute = preFilter == null ? null : preFilter.value();
        String filterObject = preFilter == null ? null : preFilter.filterTarget();
        String preAuthorizeAttribute = preAuthorize == null ? null : preAuthorize.value();
        String postFilterAttribute = postFilter == null ? null : postFilter.value();
        String postAuthorizeAttribute = postAuthorize == null ? null : postAuthorize.value();

        ArrayList<ConfigAttribute> attrs = new ArrayList<ConfigAttribute>(2);

        PreInvocationAttribute pre = attributeFactory.createPreInvocationAttribute(preFilterAttribute, filterObject, preAuthorizeAttribute);

        if (pre != null) {
            attrs.add(pre);
        }

        PostInvocationAttribute post = attributeFactory.createPostInvocationAttribute(postFilterAttribute, postAuthorizeAttribute);

        if (post != null) {
            attrs.add(post);
        }

        attrs.trimToSize();

        return attrs;
    }

    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    /**
     * See {@link org.springframework.security.access.method.AbstractFallbackMethodSecurityMetadataSource#getAttributes(Method, Class)}
     * for the logic of this method. The ordering here is slightly different in that we consider method-specific
     * annotations on an interface before class-level ones.
     */
    private <A  extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationClass) {
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
        annotation = AnnotationUtils.findAnnotation(specificMethod.getDeclaringClass(), annotationClass);

        if (annotation != null) {
            logger.debug(annotation + " found on: " + specificMethod.getDeclaringClass().getName());
            return annotation;
        }

        return null;
    }

}
