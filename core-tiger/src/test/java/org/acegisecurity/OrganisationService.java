package org.acegisecurity;

public interface OrganisationService extends Service<Organisation> {
	public void deactive(Organisation org);
}
