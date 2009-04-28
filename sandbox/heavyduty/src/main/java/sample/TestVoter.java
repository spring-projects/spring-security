package sample;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AccessDecisionVoter;
import org.springframework.security.core.Authentication;

public class TestVoter implements AccessDecisionVoter {

    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    public boolean supports(Class<?> clazz) {
        return MethodInvocation.class.isAssignableFrom(clazz);
    }

    public int vote(Authentication authentication, Object object, List<ConfigAttribute> config) {
        MethodInvocation mi = (MethodInvocation) object;

        mi.getMethod().getParameterAnnotations();


        return ACCESS_GRANTED;
    }

}
