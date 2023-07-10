# SVG SECURITY

> Simple and lightweight library that helps to validate SVG files in security manners.

[![Build](https://github.com/bgalek/safe-svg/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/bgalek/safe-svg/actions/workflows/build.yml)
![Codecov](https://img.shields.io/codecov/c/github/bgalek/safe-svg.svg?style=flat-square)
![GitHub Release Date](https://img.shields.io/github/release-date/bgalek/safe-svg.svg?style=flat-square)
![Maven Central](https://img.shields.io/maven-central/v/com.github.bgalek.security.svg/safe-svg?style=flat-square)
![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/bgalek/safe-svg.svg?style=flat-square)
![Scrutinizer code quality](https://img.shields.io/scrutinizer/g/bgalek/safe-svg.svg?style=flat-square)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bgalek_safe-svg&metric=alert_status)](https://sonarcloud.io/dashboard?id=bgalek_safe-svg?style=flat-square)

It will help you in detecting malicious content inside uploaded SVGs.

## Are you aware that SVG can cause XSS?

Read [https://sekurak.pl/pozwalasz-ladowac-pliki-svg-masz-xss-a/](https://sekurak.pl/pozwalasz-ladowac-pliki-svg-masz-xss-a/) for more details.

## Example

Try to upload this SVG into your application, if it passes through and user can browse this file - probably You are vulnerable to XSS attack.

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
<script type="text/javascript">
alert('Hello, world!');
</script>
</svg>
```

## Usage

Add library dependency:

```groovy
compile "com.github.bgalek.security.svg:safe-svg:1.1.4"
```

You can use this library to check uploaded svg files

```java
SvgSecurityValidator svgSecurityValidator = SvgSecurityValidator.builder().build();
String svg = "<?xml version=\"1.0\" standalone=\"no\"?>\n" +
                "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n" +
                "<svg version=\"1.1\" baseProfile=\"full\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                "<polygon id=\"triangle\" points=\"0,0 0,50 50,0\" fill=\"#009900\" stroke=\"#004400\"/>\n" +
                "<script type=\"text/javascript\">\n" +
                "alert('Hello, world!');\n" +
                "</script>\n" +
                "</svg>";
        ValidationResult validation = svgSecurityValidator.validate(svg);
        if (validation.hasViolations()) {
            throw new RuntimeException("this file is suspicious" + validation.getOffendingElements());
        }
```

If you want to allow other (possibly non-safe) elements/attributes use

```java
ValidationResult detect = SvgSecurityValidator.builder()
    .withAdditionalElements(elements)
    .withAdditionalAttributes(attributes)
    .build()
    .validate(testFile);
```
