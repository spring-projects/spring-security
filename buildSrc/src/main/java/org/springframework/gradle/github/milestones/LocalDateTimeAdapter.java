package org.springframework.gradle.github.milestones;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

/**
 * @author Steve Riesenberg
 */
class LocalDateTimeAdapter extends TypeAdapter<LocalDateTime> {
	@Override
	public void write(JsonWriter jsonWriter, LocalDateTime localDateTime) throws IOException {
		jsonWriter.value(localDateTime.atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_ZONED_DATE_TIME));
	}

	@Override
	public LocalDateTime read(JsonReader jsonReader) throws IOException {
		return LocalDateTime.parse(jsonReader.nextString(), DateTimeFormatter.ISO_ZONED_DATE_TIME);
	}
}
