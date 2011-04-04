package org.springframework.security.access.annotation;

import org.springframework.security.access.ConfigAttribute;

import java.lang.annotation.Annotation;
import java.util.*;

/**
 * Strategy to process a custom security annotation to extract the relevant {@code ConfigAttribute}s for
 * securing a method.
 * <p>
 * Used by {@code SecuredAnnotationSecurityMetadataSource}.
 *
 * @author Luke Taylor
 */
public interface AnnotationMetadataExtractor<A extends Annotation> {

    Collection<? extends ConfigAttribute> extractAttributes(A securityAnnotation);
}
