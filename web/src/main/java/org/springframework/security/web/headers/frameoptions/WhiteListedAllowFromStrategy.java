package org.springframework.security.web.headers.frameoptions;

import org.springframework.util.Assert;

import java.util.Collection;
import java.util.List;

/**
 * Implementation which checks the supplied origin against a list of allowed origins.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class WhiteListedAllowFromStrategy extends RequestParameterAllowFromStrategy {

    private final Collection<String> allowed;

    public WhiteListedAllowFromStrategy(Collection<String> allowed) {
        Assert.notEmpty(allowed, "Allowed origins cannot be empty.");
        this.allowed = allowed;
    }

    @Override
    protected boolean allowed(String from) {
        return allowed.contains(from);
    }
}
