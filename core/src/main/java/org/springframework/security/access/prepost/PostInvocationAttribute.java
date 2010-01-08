package org.springframework.security.access.prepost;

import org.springframework.security.access.ConfigAttribute;

/**
 * Marker interface for attributes which are created from combined @PostFilter and @PostAuthorize annotations.
 * <p>
 * Consumed by a {@link PostInvocationAuthorizationAdvice}.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface PostInvocationAttribute extends ConfigAttribute {

}
