package com.github.bgalek.security.svg;

import org.owasp.html.HtmlChangeListener;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import javax.xml.parsers.DocumentBuilder;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * SVG Safe is a very simple and lightweight library that helps
 * to validate SVG files in security manners.
 * It will help you in detecting malicious content inside uploaded SVGs.
 *
 * @author Bartosz Gałek
 * @see <a href="https://github.com/bgalek/safe-svg">safe-svg</a>
 */
public class SvgSecurityValidator implements XssDetector {

    private static final Pattern JAVASCRIPT_PROTOCOL_IN_CSS_URL = Pattern.compile("url\\(.?javascript");
    private static final Pattern SCRIPT_TAG = Pattern.compile("</?\\s*(?)script\\s*[a-zA-Z=/\"]*\\s*>", Pattern.CASE_INSENSITIVE);

    private final String[] svgElements;
    private final String[] svgAttributes;
    private final DocumentBuilder xmlParser;

    /**
     * Use builder SvgSecurityValidator.builder()
     */
    @Deprecated
    public SvgSecurityValidator() {
        this.svgElements = SvgElements.DEFAULT_SVG_ELEMENTS;
        this.svgAttributes = SvgAttributes.DEFAULT_SVG_ATTRIBUTES;
        this.xmlParser = null;
    }

    SvgSecurityValidator(String[] elements, String[] attributes, DocumentBuilder xmlParser) {
        this.svgElements = elements;
        this.svgAttributes = attributes;
        this.xmlParser = xmlParser;
    }

    public static SvgSecurityValidatorBuilder builder() {
        return new SvgSecurityValidatorBuilder();
    }

    /**
     * This is the main method that handles svg file validation
     *
     * @param input svg file content to validate
     * @return {@link ValidationResult}
     * @since 1.0
     */
    @Override
    public ValidationResult validate(String input) {
        if (xmlParser != null) validateXMLSchema(input);
        Set<String> offendingElements = getOffendingElements(input);
        if (offendingElements.isEmpty()) return new NegativeValidationResult();
        return new PositiveValidationResult(offendingElements);
    }

    @Override
    public ValidationResult validate(byte[] input) {
        return validate(new String(input, StandardCharsets.UTF_8));
    }

    private void validateXMLSchema(String input) {
        try {
            assert xmlParser != null;
            xmlParser.parse(new ByteArrayInputStream(input.getBytes()));
        } catch (Exception e) {
            throw new InvalidXMLSyntaxException(e);
        }
    }

    private Set<String> getOffendingElements(String xml) {
        if (JAVASCRIPT_PROTOCOL_IN_CSS_URL.matcher(xml).find()) return Collections.singleton("style");
        if (SCRIPT_TAG.matcher(xml).find()) return Collections.singleton("script");
        PolicyFactory policy = new HtmlPolicyBuilder()
                .allowElements(this.svgElements)
                .allowAttributes(this.svgAttributes).globally()
                .allowUrlProtocols("https")
                .toFactory();
        Set<String> violations = new HashSet<>();
        policy.sanitize(xml, violationsCollector(), violations);
        return violations;
    }

    private static HtmlChangeListener<Set<String>> violationsCollector() {
        return new ListHtmlChangeListener();
    }

    private static class ListHtmlChangeListener implements HtmlChangeListener<Set<String>> {
        @Override
        public void discardedTag(Set<String> context, String elementName) {
            Objects.requireNonNull(context).add(elementName);
        }

        @Override
        public void discardedAttributes(Set<String> context, String tagName, String... attributeNames) {
            Objects.requireNonNull(context).addAll(Arrays.asList(attributeNames));
        }
    }
}
