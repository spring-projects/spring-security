package org.springframework.security.expression.support;

import java.util.List;

import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.vote.AccessDecisionVoter;

public class WebExpressionVoter implements AccessDecisionVoter {

    public boolean supports(ConfigAttribute attribute) {
        return false;
    }

    public boolean supports(Class clazz) {
        return clazz.isAssignableFrom(FilterInvocation.class);
    }

    public int vote(Authentication authentication, Object object,
            List<ConfigAttribute> attributes) {
        // TODO Auto-generated method stub
        return 0;
    }

}
