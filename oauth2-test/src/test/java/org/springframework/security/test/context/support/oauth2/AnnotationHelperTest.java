package org.springframework.security.test.context.support.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.context.support.oauth2.AnnotationHelper.nullIfEmpty;
import static org.springframework.security.test.context.support.oauth2.AnnotationHelper.putIfNotEmpty;
import static org.springframework.security.test.context.support.oauth2.AnnotationHelper.stringStream;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Stream;

import org.junit.Test;

public class AnnotationHelperTest {

	@Test
	public void nullIfEmptyReturnsNullForNullString() {
		assertThat(nullIfEmpty(null)).isNull();
	}

	@Test
	public void nullIfEmptyReturnsNullForEmptyString() {
		assertThat(nullIfEmpty("")).isNull();
	}

	@Test
	public void nullIfEmptyReturnsNonNullForSpace() {
		assertThat(nullIfEmpty(" ")).isEqualTo(" ");
	}

	@Test
	public void nullIfEmptyReturnsNonNullForToto() {
		assertThat(nullIfEmpty("Toto")).isEqualTo("Toto");
	}

	@Test
	public void putIfNotEmptyDoesNothingForNullString() {
		assertThat(putIfNotEmpty("foo", (String) null, new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyDoesNothingForEmptyString() {
		assertThat(putIfNotEmpty("foo", "", new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyInsertsSpace() {
		assertThat(putIfNotEmpty("foo", " ", new HashMap<>()).get("foo")).isEqualTo(" ");
	}

	@Test
	public void putIfNotEmptyInsertsToto() {
		assertThat(putIfNotEmpty("foo", "Toto", new HashMap<>()).get("foo")).isEqualTo("Toto");
	}

	@Test
	public void putIfNotEmptyDoesNothingForNullList() {
		assertThat(putIfNotEmpty("foo", (List<String>) null, new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyDoesNothingForEmptyList() {
		assertThat(putIfNotEmpty("foo", Collections.emptyList(), new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyInsertsNonEmptyList() {
		@SuppressWarnings("unchecked")
		final List<String> actual =
				(List<String>) (putIfNotEmpty("foo", Collections.singletonList("Toto"), new HashMap<>()).get("foo"));
		assertThat(actual).hasSize(1);
		assertThat(actual).contains("Toto");
	}

	@Test
	public void stringStreamReturnsEmptyStreamForNullArray() {
		final Stream<String> actual = stringStream((String[]) null);
		assertThat(actual).isEmpty();
	}

	@Test
	public void stringStreamReturnsEmptyStreamForEmptyArray() {
		final Stream<String> actual = stringStream(new String[] {});
		assertThat(actual).isEmpty();
	}

	@Test
	public void stringStreamSkipsNullAndEmptyStrings() {
		final Stream<String> actual = stringStream(new String[] { null, "", "Toto" });
		assertThat(actual).allMatch("Toto"::equals);
	}

}
