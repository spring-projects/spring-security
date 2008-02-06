package org.springframework.security.acls.objectidentity;

import junit.framework.TestCase;

/**
 * Tests for {@link ObjectIdentityRetrievalStrategyImpl}
 *
 * @author Andrei Stefan
 */
public class ObjectIdentityRetrievalStrategyImplTests extends TestCase {
    //~ Methods ========================================================================================================
    
    public void testObjectIdentityCreation() throws Exception {
        MockIdDomainObject domain = new MockIdDomainObject();
        domain.setId(new Integer(1));
        
        ObjectIdentityRetrievalStrategy retStrategy = new ObjectIdentityRetrievalStrategyImpl();
        ObjectIdentity identity = retStrategy.getObjectIdentity(domain);
        
        assertNotNull(identity);
        assertEquals(identity, new ObjectIdentityImpl(domain));
    }
    
    //~ Inner Classes ==================================================================================================
    
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
