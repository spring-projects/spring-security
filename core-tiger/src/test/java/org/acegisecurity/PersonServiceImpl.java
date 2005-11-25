package org.acegisecurity;

public class PersonServiceImpl extends ServiceImpl<Person> implements PersonService {

	public void deactive(Person person) {
		person.deactive();
	}

}
