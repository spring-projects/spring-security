package net.sf.acegisecurity.annotation;

@Secured ({"ROLE_USER"})
public interface BusinessService {
	
	@Secured ({"ROLE_USER"})
	public void someUserMethod1();

	@Secured ({"ROLE_USER"})
	public void someUserMethod2();	
	
	@Secured ({"ROLE_USER","ROLE_ADMIN"})
	public void someUserAndAdminMethod();
	
	@Secured ({"ROLE_ADMIN"})
	public void someAdminMethod();
	
}
