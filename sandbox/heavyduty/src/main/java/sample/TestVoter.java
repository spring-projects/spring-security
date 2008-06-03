package sample;

import java.lang.annotation.Annotation;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.vote.AccessDecisionVoter;

public class TestVoter implements AccessDecisionVoter {

	public boolean supports(ConfigAttribute attribute) {
		return true;
	}

	public boolean supports(Class clazz) {
		return MethodInvocation.class.isAssignableFrom(clazz);
	}

	public int vote(Authentication authentication, Object object, ConfigAttributeDefinition config) {
		MethodInvocation mi = (MethodInvocation) object;
		
		Annotation[][] annotations = mi.getMethod().getParameterAnnotations();
		

		return ACCESS_GRANTED;
	}

}
