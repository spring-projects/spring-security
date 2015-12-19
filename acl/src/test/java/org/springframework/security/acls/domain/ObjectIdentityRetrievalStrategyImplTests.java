
package org.springframework.security.acls.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;

/**
 * Tests for {@link ObjectIdentityRetrievalStrategyImpl}
 *
 * @author Andrei Stefan
 */
public class ObjectIdentityRetrievalStrategyImplTests {

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testObjectIdentityCreation() throws Exception {
		MockIdDomainObject domain = new MockIdDomainObject();
		domain.setId(Integer.valueOf(1));

		ObjectIdentityRetrievalStrategy retStrategy = new ObjectIdentityRetrievalStrategyImpl();
		ObjectIdentity identity = retStrategy.getObjectIdentity(domain);

		assertThat(identity).isNotNull();
		assertThat(new ObjectIdentityImpl(domain)).isEqualTo(identity);
	}

	// ~ Inner Classes
	// ==================================================================================================
	@SuppressWarnings("unused")
	private class MockIdDomainObject {

		private Object id;

		public Object getId() {
			return id;
		}

		public void setId(Object id) {
			this.id = id;
		}
	}
}
