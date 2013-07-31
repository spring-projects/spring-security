package org.springframework.security.web.header.writers.frameoptions;

import java.util.Collection;

import org.springframework.util.Assert;

/**
 * Implementation which checks the supplied origin against a list of allowed origins.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public final class WhiteListedAllowFromStrategy extends AbstractRequestParameterAllowFromStrategy {

    private final Collection<String> allowed;

    /**
     * Creates a new instance
     * @param allowed the origins that are allowed.
     */
    public WhiteListedAllowFromStrategy(Collection<String> allowed) {
        Assert.notEmpty(allowed, "Allowed origins cannot be empty.");
        this.allowed = allowed;
    }

    @Override
    protected boolean allowed(String allowFromOrigin) {
        return allowed.contains(allowFromOrigin);
    }
}
