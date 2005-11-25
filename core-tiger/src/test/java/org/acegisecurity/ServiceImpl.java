package org.acegisecurity;

import java.util.Collection;

public class ServiceImpl<E extends Entity> implements Service<E> {

	public int countElements(Collection<E> ids) {
		return 0;
	}

	public void makeLowerCase(E input) {
		input.makeLowercase();
	}

	public void makeUpperCase(E input) {
		input.makeUppercase();
	}

	public void publicMakeLowerCase(E input) {
		input.makeUppercase();
	}

}
