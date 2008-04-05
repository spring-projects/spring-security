package org.springframework.security.acls.jdbc;

import java.io.IOException;

import junit.framework.TestCase;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;

import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.GrantedAuthoritySid;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

public class AclPermissionInheritanceTests extends TestCase {

	private JdbcMutableAclService aclService;
	private JdbcTemplate jdbcTemplate;
	private DriverManagerDataSource dataSource;
	private DataSourceTransactionManager txManager;
	private TransactionStatus txStatus;

	protected void setUp() throws Exception {
		
		dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
		dataSource.setUrl("jdbc:hsqldb:mem:permissiontest");
		dataSource.setUsername("sa");
		dataSource.setPassword("");

		jdbcTemplate = new JdbcTemplate(dataSource);
		
		txManager = new DataSourceTransactionManager();
		txManager.setDataSource(dataSource);
		
		txStatus = txManager.getTransaction(new DefaultTransactionDefinition());
		
		aclService = createAclService(dataSource);
		
        Authentication auth = new UsernamePasswordAuthenticationToken(
        		"system", "secret", new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_IGNORED")});
        SecurityContextHolder.getContext().setAuthentication(auth);
	}

	protected void tearDown() throws Exception {
		txManager.rollback(txStatus);
		SecurityContextHolder.clearContext();
	}

	public void test1() throws Exception {

		createAclSchema(jdbcTemplate);

		ObjectIdentityImpl rootObject = 
			new ObjectIdentityImpl(TestDomainObject.class, new Long(1));

		MutableAcl parent = aclService.createAcl(rootObject);
		MutableAcl child = aclService.createAcl(new ObjectIdentityImpl(TestDomainObject.class, new Long(2)));
		child.setParent(parent);
		aclService.updateAcl(child);

		parent = (AclImpl) aclService.readAclById(rootObject);
		parent.insertAce(null, BasePermission.READ, 
				new PrincipalSid("john"), true);
		aclService.updateAcl(parent);

		parent = (AclImpl) aclService.readAclById(rootObject);
		parent.insertAce(null, BasePermission.READ, 
				new PrincipalSid("joe"), true);
		aclService.updateAcl(parent);

		child = (MutableAcl) aclService.readAclById(
				new ObjectIdentityImpl(TestDomainObject.class, new Long(2)));

		parent = (MutableAcl) child.getParentAcl();

		assertEquals("Fails because child has a stale reference to its parent", 
				2, parent.getEntries().length);
		assertEquals(1, parent.getEntries()[0].getPermission().getMask());
		assertEquals(new PrincipalSid("john"), parent.getEntries()[0].getSid());
		assertEquals(1, parent.getEntries()[1].getPermission().getMask());
		assertEquals(new PrincipalSid("joe"), parent.getEntries()[1].getSid());

	}
	public void test2() throws Exception {

		createAclSchema(jdbcTemplate);

		ObjectIdentityImpl rootObject = 
			new ObjectIdentityImpl(TestDomainObject.class, new Long(1));

		MutableAcl parent = aclService.createAcl(rootObject);
		MutableAcl child = aclService.createAcl(new ObjectIdentityImpl(TestDomainObject.class, new Long(2)));
		child.setParent(parent);
		aclService.updateAcl(child);

		parent.insertAce(null, BasePermission.ADMINISTRATION, 
				new GrantedAuthoritySid("ROLE_ADMINISTRATOR"), true);
		aclService.updateAcl(parent);

		parent.insertAce(null, BasePermission.DELETE, new PrincipalSid("terry"), true);
		aclService.updateAcl(parent);

		child = (MutableAcl) aclService.readAclById(
				new ObjectIdentityImpl(TestDomainObject.class, new Long(2)));

		parent = (MutableAcl) child.getParentAcl();

		assertEquals(2, parent.getEntries().length);
		assertEquals(16, parent.getEntries()[0].getPermission().getMask());
		assertEquals(new GrantedAuthoritySid("ROLE_ADMINISTRATOR"), parent.getEntries()[0].getSid());
		assertEquals(8, parent.getEntries()[1].getPermission().getMask());
		assertEquals(new PrincipalSid("terry"), parent.getEntries()[1].getSid());

	}

	private JdbcMutableAclService createAclService(DriverManagerDataSource ds)
		throws IOException {

		GrantedAuthorityImpl adminAuthority = new GrantedAuthorityImpl("ROLE_ADMINISTRATOR");
		AclAuthorizationStrategyImpl authStrategy = new AclAuthorizationStrategyImpl(
        		new GrantedAuthorityImpl[]{adminAuthority,adminAuthority,adminAuthority});

		EhCacheManagerFactoryBean ehCacheManagerFactoryBean = new EhCacheManagerFactoryBean();
		ehCacheManagerFactoryBean.afterPropertiesSet();
		CacheManager cacheManager = (CacheManager) ehCacheManagerFactoryBean.getObject();
		
		EhCacheFactoryBean ehCacheFactoryBean = new EhCacheFactoryBean();
		ehCacheFactoryBean.setCacheName("aclAche");
		ehCacheFactoryBean.setCacheManager(cacheManager);
		ehCacheFactoryBean.afterPropertiesSet();
		Ehcache ehCache = (Ehcache) ehCacheFactoryBean.getObject();
		
		AclCache aclAche = new EhCacheBasedAclCache(ehCache);
		
		BasicLookupStrategy lookupStrategy = 
			new BasicLookupStrategy(ds, aclAche, authStrategy, new ConsoleAuditLogger());
	
		return new JdbcMutableAclService(ds,lookupStrategy, aclAche);
	}

	private void createAclSchema(JdbcTemplate jdbcTemplate) {
		
		jdbcTemplate.execute("DROP TABLE ACL_ENTRY IF EXISTS;");
		jdbcTemplate.execute("DROP TABLE ACL_OBJECT_IDENTITY IF EXISTS;");
		jdbcTemplate.execute("DROP TABLE ACL_CLASS IF EXISTS");
		jdbcTemplate.execute("DROP TABLE ACL_SID IF EXISTS");
		
		jdbcTemplate.execute(
                "CREATE TABLE ACL_SID(" +
                        "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY," +
                        "PRINCIPAL BOOLEAN NOT NULL," +
                        "SID VARCHAR_IGNORECASE(100) NOT NULL," +
                        "CONSTRAINT UNIQUE_UK_1 UNIQUE(SID,PRINCIPAL));");
            jdbcTemplate.execute(
                "CREATE TABLE ACL_CLASS(" +
                        "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY," +
                        "CLASS VARCHAR_IGNORECASE(100) NOT NULL," +
                        "CONSTRAINT UNIQUE_UK_2 UNIQUE(CLASS));");
            jdbcTemplate.execute(
                "CREATE TABLE ACL_OBJECT_IDENTITY(" +
                        "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY," +
                        "OBJECT_ID_CLASS BIGINT NOT NULL," +
                        "OBJECT_ID_IDENTITY BIGINT NOT NULL," +
                        "PARENT_OBJECT BIGINT," +
                        "OWNER_SID BIGINT," +
                        "ENTRIES_INHERITING BOOLEAN NOT NULL," +
                        "CONSTRAINT UNIQUE_UK_3 UNIQUE(OBJECT_ID_CLASS,OBJECT_ID_IDENTITY)," +
                        "CONSTRAINT FOREIGN_FK_1 FOREIGN KEY(PARENT_OBJECT)REFERENCES ACL_OBJECT_IDENTITY(ID)," +
                        "CONSTRAINT FOREIGN_FK_2 FOREIGN KEY(OBJECT_ID_CLASS)REFERENCES ACL_CLASS(ID)," +
                        "CONSTRAINT FOREIGN_FK_3 FOREIGN KEY(OWNER_SID)REFERENCES ACL_SID(ID));");
            jdbcTemplate.execute(
                "CREATE TABLE ACL_ENTRY(" +
                        "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY," +
                        "ACL_OBJECT_IDENTITY BIGINT NOT NULL,ACE_ORDER INT NOT NULL,SID BIGINT NOT NULL," +
                        "MASK INTEGER NOT NULL,GRANTING BOOLEAN NOT NULL,AUDIT_SUCCESS BOOLEAN NOT NULL," +
                        "AUDIT_FAILURE BOOLEAN NOT NULL,CONSTRAINT UNIQUE_UK_4 UNIQUE(ACL_OBJECT_IDENTITY,ACE_ORDER)," +
                        "CONSTRAINT FOREIGN_FK_4 FOREIGN KEY(ACL_OBJECT_IDENTITY) REFERENCES ACL_OBJECT_IDENTITY(ID)," +
                        "CONSTRAINT FOREIGN_FK_5 FOREIGN KEY(SID) REFERENCES ACL_SID(ID));");
	}

	public static class TestDomainObject {
		
		private Long id;

		public Long getId() {
			return id;
		}
		
		public void setId(Long id) {
			this.id = id;
		}
	}
}