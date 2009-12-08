package sample;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.core.Authentication;

public class TestVoter implements AccessDecisionVoter {

    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    public boolean supports(Class<?> clazz) {
        return MethodInvocation.class.isAssignableFrom(clazz);
    }

    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> config) {
        MethodInvocation mi = (MethodInvocation) object;

        mi.getMethod().getParameterAnnotations();


        return ACCESS_GRANTED;
    }

}
