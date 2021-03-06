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

    @MethodSource("evilUseCases")
    @ParameterizedTest(name = "validate {0} svg")
    void shouldDetectXssInFiles(String file, String expectedOffendingElements) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertEquals(expectedOffendingElements, String.join(",", detect.getOffendingElements()));
        assertTrue(detect.hasViolations());
    }

    @MethodSource("safeUseCases")
    @ParameterizedTest(name = "validate {0} svg")
    void shouldNotDetectAnythingInValidFiles(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertEquals(Collections.emptySet(), detect.getOffendingElements());
        assertFalse(detect.hasViolations());
    }

    @MethodSource("safeUseCases")
    @ParameterizedTest(name = "validate {0} svg")
    void shouldNotDetectAnythingInValidFilesUsingBytes(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file).getBytes());
        assertEquals(Collections.emptySet(), detect.getOffendingElements());
        assertFalse(detect.hasViolations());
    }

    @MethodSource("brokenUseCases")
    @ParameterizedTest(name = "validate {0} svg")
    void shouldThrowExceptionWhenInputIsNotValidXml(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertEquals(Collections.emptySet(), detect.getOffendingElements());
        assertFalse(detect.hasViolations());
    }

    private static Stream<Arguments> safeUseCases() {
        return Stream.of(
                Arguments.of("safe/valid1.svg"),
                Arguments.of("safe/valid2.svg"),
                Arguments.of("safe/valid3.svg")
        );
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

    private static Stream<Arguments> brokenUseCases() {
        return Stream.of(
                Arguments.of("broken/broken.csv.svg"),
                Arguments.of("broken/broken.png.svg")
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