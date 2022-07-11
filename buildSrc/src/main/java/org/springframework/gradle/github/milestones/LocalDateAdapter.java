package org.springframework.gradle.github.milestones;

import java.io.IOException;
import java.time.LocalDate;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

/**
 * @author Steve Riesenberg
 */
class LocalDateAdapter extends TypeAdapter<LocalDate> {
	@Override
	public void write(JsonWriter jsonWriter, LocalDate localDate) throws IOException {
		jsonWriter.value(localDate.toString());
	}

	@Override
	public LocalDate read(JsonReader jsonReader) throws IOException {
		return LocalDate.parse(jsonReader.nextString());
	}
}
