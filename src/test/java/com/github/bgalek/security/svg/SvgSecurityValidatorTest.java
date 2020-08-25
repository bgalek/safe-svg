package com.github.bgalek.security.svg;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SvgSecurityValidatorTest {

    @ParameterizedTest(name = "validate {0} svg")
    @MethodSource("evilUseCases")
    void shouldDetectXssInFiles(String file, String expectedOffendingElements) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertTrue(detect.hasViolations());
        assertEquals(expectedOffendingElements, String.join(",", detect.getOffendingElements()));
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"original/valid.svg"})
    void shouldNotDetectAnythingInValidFiles(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertFalse(detect.hasViolations());
        assertEquals(Collections.emptySet(), detect.getOffendingElements());
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"original/valid.svg"})
    void shouldNotDetectAnythingInValidFilesUsingBytes(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file).getBytes());
        assertFalse(detect.hasViolations());
        assertEquals(Collections.emptySet(), detect.getOffendingElements());
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"broken/broken.csv.svg"})
    void shouldThrowExceptionWhenInputIsNotValidXml(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertFalse(detect.hasViolations());
        assertEquals(Collections.emptySet(), detect.getOffendingElements());
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"broken/broken.png.svg"})
    void shouldThrowExceptionWhenInputIsBinaryType(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file).getBytes());
        assertFalse(detect.hasViolations());
        assertEquals(Collections.emptySet(), detect.getOffendingElements());
    }

    private static Stream<Arguments> evilUseCases() {
        return Stream.of(
                Arguments.of("hacked/with-onclick-attribute.svg", "onclick"),
                Arguments.of("hacked/with-script-tag.svg", "script"),
                Arguments.of("hacked/with-script-tag-in-styles.svg", "script"),
                Arguments.of("hacked/with-css-url-syntax.svg", "style"),
                Arguments.of("hacked/with-xlink-injection.svg", "script")
        );
    }

    private String loadFile(String fileName) {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource(fileName)).getFile());
        try {
            return new String(Files.readAllBytes(file.toPath()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}