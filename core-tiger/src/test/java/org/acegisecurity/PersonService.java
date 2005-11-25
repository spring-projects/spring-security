package org.acegisecurity;

public interface PersonService extends Service<Person> {
	public void deactive(Person person);
}
