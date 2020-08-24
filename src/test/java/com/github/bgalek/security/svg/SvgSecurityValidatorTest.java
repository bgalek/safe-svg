package com.github.bgalek.security.svg;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SvgSecurityValidatorTest {

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"hacked/with-onclick-attribute.svg", "hacked/with-script-tag.svg", "hacked/with-script-tag-in-styles.svg"})
    void shouldDetectXssInFiles(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertEquals(1, detect.getOffendingElements().size());
        assertTrue(detect.hasViolations());
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"original/valid.svg"})
    void shouldNotDetectAnythingInValidFiles(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertEquals(0, detect.getOffendingElements().size());
        assertFalse(detect.hasViolations());
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"original/valid.svg"})
    void shouldNotDetectAnythingInValidFilesUsingBytes(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file).getBytes());
        assertEquals(0, detect.getOffendingElements().size());
        assertFalse(detect.hasViolations());
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"broken/broken.csv.svg"})
    void shouldThrowExceptionWhenInputIsNotValidXml(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file));
        assertEquals(0, detect.getOffendingElements().size());
        assertFalse(detect.hasViolations());
    }

    @ParameterizedTest(name = "validate {0} svg")
    @ValueSource(strings = {"broken/broken.png.svg"})
    void shouldThrowExceptionWhenInputIsBinaryType(String file) {
        ValidationResult detect = new SvgSecurityValidator().validate(loadFile(file).getBytes());
        assertEquals(0, detect.getOffendingElements().size());
        assertFalse(detect.hasViolations());
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