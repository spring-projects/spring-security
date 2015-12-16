package org.springframework.security.access.vote;

import static org.assertj.core.api.Assertions.*;

import java.util.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.util.MethodInvocationUtils;

/**
 *
 * @author Luke Taylor
 */
public class AbstractAclVoterTests {
	private AbstractAclVoter voter = new AbstractAclVoter() {
		public boolean supports(ConfigAttribute attribute) {
			return false;
		}

		public int vote(Authentication authentication, MethodInvocation object,
				Collection<ConfigAttribute> attributes) {
			return 0;
		}
	};

	@Test
	public void supportsMethodInvocations() throws Exception {
		assertThat(voter.supports(MethodInvocation.class)).isTrue();
		assertThat(voter.supports(String.class)).isFalse();
	}

	@Test
	public void expectedDomainObjectArgumentIsReturnedFromMethodInvocation()
			throws Exception {
		voter.setProcessDomainObjectClass(String.class);
		MethodInvocation mi = MethodInvocationUtils.create(new TestClass(),
				"methodTakingAString", "The Argument");
		assertThat(voter.getDomainObjectInstance(mi)).isEqualTo("The Argument");
	}

	@Test
	public void correctArgumentIsSelectedFromMultipleArgs() throws Exception {
		voter.setProcessDomainObjectClass(String.class);
		MethodInvocation mi = MethodInvocationUtils.create(new TestClass(),
				"methodTakingAListAndAString", new ArrayList<Object>(), "The Argument");
		assertThat(voter.getDomainObjectInstance(mi)).isEqualTo("The Argument");
	}

	@SuppressWarnings("unused")
	private static class TestClass {
		public void methodTakingAString(String arg) {
		}

		public void methodTaking2Strings(String arg1, String arg2) {
		}

		public void methodTakingAListAndAString(ArrayList<Object> arg1, String arg2) {
		}
	}

}
