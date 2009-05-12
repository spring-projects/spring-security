package org.springframework.security.web.authentication;

/**
 * Renamed class, retained for backwards compatibility.
 * <p>
 * See {@link AbstractAuthenticationProcessingFilter}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @deprecated Use AbstractAuthenticationProcessingFilter instead.
 */
@Deprecated
public abstract class AbstractProcessingFilter extends AbstractAuthenticationProcessingFilter {

    protected AbstractProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }
}
