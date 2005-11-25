package org.acegisecurity;

public class OrganisationServiceImpl extends ServiceImpl<Organisation> implements OrganisationService {

	public void deactive(Organisation org) {
		org.deactive();
	}

}
