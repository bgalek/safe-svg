package com.github.bgalek.security.svg;

interface XssDetector {
    ValidationResult validate(String input);

    ValidationResult validate(byte[] input);
}
