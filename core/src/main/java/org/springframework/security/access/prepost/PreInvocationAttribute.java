package org.springframework.security.access.prepost;

import org.springframework.security.access.ConfigAttribute;

/**
 * Marker interface for attributes which are created from combined @PreFilter and @PreAuthorize annotations.
 * <p>
 * Consumed by a {@link PreInvocationAuthorizationAdvice}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public interface PreInvocationAttribute extends ConfigAttribute{

}
