# HTML Code Review Guide

> Review guide for HTML, covering XSS prevention, CSRF protection, accessibility (a11y), SEO, forms, iframes, mixed content, and performance. Applicable to server-rendered templates (Jinja2, Blade, ERB, ASP) and static HTML.

## Table of Contents

- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [CSRF Protection](#csrf-protection)
- [Content Security Policy](#content-security-policy)
- [Accessibility (a11y)](#accessibility-a11y)
- [SEO](#seo)
- [Forms & Input Validation](#forms--input-validation)
- [Iframes](#iframes)
- [Links & Navigation](#links--navigation)
- [Mixed Content](#mixed-content)
- [Performance](#performance)
- [Semantic HTML](#semantic-html)
- [Review Checklist](#review-checklist)

---

## Cross-Site Scripting (XSS)

### innerHTML and DOM Injection

```html
<!-- ❌ innerHTML with user input — XSS vector [blocking] -->
<script>
  document.getElementById('greeting').innerHTML = userInput;
  // If userInput = '<img src=x onerror=alert(1)>' → XSS
</script>

<!-- ✅ Use textContent for plain text -->
<script>
  document.getElementById('greeting').textContent = userInput;
  // HTML entities are not interpreted — safe
</script>

<!-- ❌ document.write with user input [blocking] -->
<script>
  document.write('<p>Hello ' + userName + '</p>');
</script>

<!-- ✅ Use DOM API -->
<script>
  const p = document.createElement('p');
  p.textContent = 'Hello ' + userName;
  document.body.appendChild(p);
</script>
```

### Template Injection

```html
<!-- ❌ Unescaped output in server-side templates [blocking] -->
<!-- Jinja2 -->
<p>{{ user_input | safe }}</p>

<!-- ERB -->
<p><%= raw user_input %></p>

<!-- Blade -->
<p>{!! $userInput !!}</p>

<!-- ✅ Use default (escaped) output -->
<!-- Jinja2 (auto-escaping on by default) -->
<p>{{ user_input }}</p>

<!-- ERB -->
<p><%= user_input %></p>

<!-- Blade -->
<p>{{ $userInput }}</p>
```

### JavaScript Context

```html
<!-- ❌ User input in inline JavaScript [blocking] -->
<script>
  var config = { name: '{{ user_name }}' };
  // If user_name = "'; alert(1);//" → code injection
</script>

<!-- ✅ Use data attributes and parse in JS -->
<div id="config" data-name="{{ user_name | escape }}"></div>
<script>
  var config = { name: document.getElementById('config').dataset.name };
</script>

<!-- ✅ Or use JSON serialization with proper escaping -->
<script>
  var config = JSON.parse('{{ config | tojson | safe }}');
  // tojson escapes quotes and special characters
</script>
```

### Event Handler Injection

```html
<!-- ❌ User input in event handlers [blocking] -->
<button onclick="doAction('{{ user_input }}')">Click</button>
<!-- user_input = "'); alert(1);//" → XSS -->

<!-- ✅ Bind events in JavaScript, pass data via attributes -->
<button id="actionBtn" data-action="{{ user_input | escape }}">Click</button>
<script>
  document.getElementById('actionBtn').addEventListener('click', function() {
    doAction(this.dataset.action);
  });
</script>
```

---

## CSRF Protection

### Form Tokens

```html
<!-- ❌ State-changing form without CSRF token [blocking] -->
<form method="POST" action="/api/transfer">
  <input name="amount" type="number">
  <button type="submit">Transfer</button>
</form>

<!-- ✅ Include CSRF token in all POST/PUT/DELETE forms -->
<form method="POST" action="/api/transfer">
  <input type="hidden" name="_csrf" value="{{ csrf_token }}">
  <input name="amount" type="number">
  <button type="submit">Transfer</button>
</form>

<!-- ✅ For AJAX requests, send token in header -->
<meta name="csrf-token" content="{{ csrf_token }}">
<script>
  fetch('/api/transfer', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ amount: 100 }),
  });
</script>
```

### SameSite Cookie Attribute

```html
<!-- ❌ No SameSite attribute — vulnerable to cross-site requests [important] -->
<!-- Set-Cookie: session=abc123; Path=/; HttpOnly -->

<!-- ✅ SameSite cookie configuration (server-side, but reviewable in HTML headers) -->
<!-- Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax -->
<!-- SameSite=Strict for maximum protection (breaks legitimate cross-site navigation) -->
<!-- SameSite=Lax for balance (allows GET from external links, blocks POST) -->
```

---

## Content Security Policy

### CSP Header Configuration

```html
<!-- ❌ No CSP — any script source allowed [important] -->

<!-- ❌ Overly permissive CSP -->
<meta http-equiv="Content-Security-Policy"
      content="default-src *; script-src * 'unsafe-inline' 'unsafe-eval'">

<!-- ✅ Restrictive CSP via HTTP header (preferred over meta tag) -->
<!-- Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' -->

<!-- ✅ CSP via meta tag (fallback when headers not configurable) -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:">

<!-- ✅ Use nonce for inline scripts when needed -->
<script nonce="{{ csp_nonce }}">
  // Inline script allowed by nonce
</script>
<!-- Header: Content-Security-Policy: script-src 'nonce-abc123' -->
```

### Reporting

```html
<!-- ✅ CSP reporting to catch violations in production -->
<!-- Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report -->
<!-- Use Report-Only first to test without breaking functionality -->
```

---

## Accessibility (a11y)

### ARIA Roles and Labels

```html
<!-- ❌ Clickable div without keyboard or screen reader support [important] -->
<div class="button" onclick="submit()">Submit</div>

<!-- ✅ Use semantic button element -->
<button type="submit" onclick="submit()">Submit</button>

<!-- ✅ If custom element required, add ARIA and keyboard support -->
<div role="button" tabindex="0" onclick="submit()"
     onkeydown="if(event.key==='Enter')submit()">Submit</div>

<!-- ❌ Image without alt text [important] -->
<img src="patient-photo.jpg">

<!-- ✅ Descriptive alt text for informative images -->
<img src="patient-photo.jpg" alt="Patient identification photo">

<!-- ✅ Empty alt for decorative images (screen readers skip them) -->
<img src="decorative-border.png" alt="">

<!-- ❌ Icon-only button without accessible label [important] -->
<button><i class="icon-delete"></i></button>

<!-- ✅ Add aria-label for icon-only buttons -->
<button aria-label="Delete patient record"><i class="icon-delete"></i></button>
```

### Form Labels

```html
<!-- ❌ Input without associated label [important] -->
<input type="text" name="patient_name" placeholder="Patient name">
<!-- Placeholder disappears on focus — not a label substitute -->

<!-- ✅ Explicit label association via for/id -->
<label for="patient_name">Patient name</label>
<input type="text" id="patient_name" name="patient_name">

<!-- ✅ Or implicit association via wrapping -->
<label>
  Patient name
  <input type="text" name="patient_name">
</label>

<!-- ❌ Required field without indication [nit] -->
<input type="text" name="bsn" required>

<!-- ✅ Required field with visual and programmatic indication -->
<label for="bsn">BSN <span aria-hidden="true">*</span></label>
<input type="text" id="bsn" name="bsn" required aria-required="true">
```

### Focus Management and Tab Order

```html
<!-- ❌ Positive tabindex — breaks natural tab order [important] -->
<input tabindex="3" name="field1">
<input tabindex="1" name="field2">
<input tabindex="2" name="field3">

<!-- ✅ Use tabindex="0" to include in natural order, or "-1" for programmatic focus only -->
<input name="field1">  <!-- Natural order -->
<input name="field2">
<div tabindex="0">Focusable custom element</div>
<div tabindex="-1" id="error-summary">Only focused via JavaScript</div>
```

### Landmark Roles

```html
<!-- ❌ Generic div-based layout without landmarks [nit] -->
<div class="header">...</div>
<div class="sidebar">...</div>
<div class="content">...</div>
<div class="footer">...</div>

<!-- ✅ Semantic landmark elements -->
<header>...</header>
<nav aria-label="Main navigation">...</nav>
<main>...</main>
<aside aria-label="Related information">...</aside>
<footer>...</footer>
```

---

## SEO

### Meta Tags

```html
<!-- ❌ Missing or duplicate meta tags [nit] -->
<head>
  <title></title>
  <!-- No description, no viewport -->
</head>

<!-- ✅ Complete meta tags -->
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Patient Dashboard - MarQed Healthcare</title>
  <meta name="description" content="Manage patient records and appointments securely.">
  <link rel="canonical" href="https://app.marqed.ai/dashboard">
</head>
```

### Heading Hierarchy

```html
<!-- ❌ Skipped heading levels [nit] -->
<h1>Patient Records</h1>
<h3>Recent Admissions</h3>  <!-- Skips h2 -->
<h5>Today</h5>              <!-- Skips h4 -->

<!-- ✅ Sequential heading hierarchy -->
<h1>Patient Records</h1>
<h2>Recent Admissions</h2>
<h3>Today</h3>
<h3>This Week</h3>
<h2>Search Results</h2>
```

### Structured Data

```html
<!-- ✅ JSON-LD structured data for search engines -->
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "MedicalOrganization",
  "name": "MarQed Healthcare",
  "url": "https://marqed.ai"
}
</script>
```

---

## Forms & Input Validation

### Client-Side vs Server-Side Validation

```html
<!-- ❌ Client-side validation only — trivially bypassed [blocking] -->
<form onsubmit="return validateForm()">
  <input type="text" name="bsn" pattern="[0-9]{9}">
</form>
<!-- Attacker bypasses JS validation via dev tools or direct HTTP request -->

<!-- ✅ Client-side validation for UX + server-side validation for security -->
<form method="POST" action="/api/patient" novalidate>
  <input type="text" name="bsn" pattern="[0-9]{9}" required
         title="BSN must be exactly 9 digits">
  <!-- Server MUST re-validate: never trust client input -->
</form>
```

### Autocomplete Attributes

```html
<!-- ❌ No autocomplete hints — poor UX, potential security issue [nit] -->
<input type="text" name="cc_number">

<!-- ✅ Explicit autocomplete attributes -->
<input type="text" name="name" autocomplete="name">
<input type="email" name="email" autocomplete="email">
<input type="tel" name="phone" autocomplete="tel">

<!-- ✅ Disable autocomplete for sensitive fields -->
<input type="text" name="bsn" autocomplete="off">
<input type="password" name="password" autocomplete="new-password">
```

### Input Types

```html
<!-- ❌ Generic text input for structured data [nit] -->
<input type="text" name="email">
<input type="text" name="phone">
<input type="text" name="dob">

<!-- ✅ Semantic input types — better mobile keyboards, basic validation -->
<input type="email" name="email">
<input type="tel" name="phone">
<input type="date" name="dob">
<input type="number" name="age" min="0" max="150">
<input type="url" name="website">
```

---

## Iframes

### Sandbox Attribute

```html
<!-- ❌ Unsandboxed iframe loading external content [blocking] -->
<iframe src="https://external-site.com/widget"></iframe>
<!-- External content has full access to parent page APIs -->

<!-- ✅ Sandboxed iframe with minimum permissions -->
<iframe src="https://external-site.com/widget"
        sandbox="allow-scripts allow-same-origin"
        loading="lazy"
        title="External widget">
</iframe>
<!-- Only grant permissions actually needed:
     allow-scripts: run JavaScript
     allow-same-origin: access same-origin APIs
     allow-forms: submit forms
     allow-popups: open new windows
-->
```

### Frame Protection

```html
<!-- ✅ Prevent your page from being framed (clickjacking protection) -->
<!-- HTTP header: X-Frame-Options: DENY -->
<!-- Or CSP: frame-ancestors 'none' -->

<!-- ✅ If framing is needed, restrict to specific origins -->
<!-- X-Frame-Options: ALLOW-FROM https://trusted-partner.com -->
<!-- CSP: frame-ancestors 'self' https://trusted-partner.com -->
```

---

## Links & Navigation

### target="_blank" Security

```html
<!-- ❌ target="_blank" without rel — opener vulnerability [important] -->
<a href="https://external-site.com" target="_blank">Visit Site</a>
<!-- Opened page can access window.opener and redirect your page -->

<!-- ✅ Add rel="noopener noreferrer" -->
<a href="https://external-site.com" target="_blank" rel="noopener noreferrer">Visit Site</a>
<!-- noopener: prevents window.opener access -->
<!-- noreferrer: prevents Referer header leak -->

<!-- Note: Modern browsers (2021+) default to noopener for target="_blank",
     but explicit is safer for older browser support -->
```

### Open Redirect

```html
<!-- ❌ Unvalidated redirect URL in link [blocking] -->
<a href="/redirect?url={{ user_provided_url }}">Continue</a>
<!-- Attacker: /redirect?url=https://phishing-site.com -->

<!-- ✅ Validate redirect URLs server-side against whitelist -->
<!-- Only allow relative paths or whitelisted domains -->
```

---

## Mixed Content

### HTTP Resources on HTTPS Pages

```html
<!-- ❌ HTTP resources on HTTPS page — blocked by browsers [blocking] -->
<script src="http://cdn.example.com/lib.js"></script>
<img src="http://images.example.com/photo.jpg">
<link rel="stylesheet" href="http://cdn.example.com/style.css">

<!-- ✅ Use protocol-relative or HTTPS URLs -->
<script src="https://cdn.example.com/lib.js"></script>
<img src="https://images.example.com/photo.jpg">

<!-- ✅ Or use protocol-relative URLs (less common now) -->
<script src="//cdn.example.com/lib.js"></script>

<!-- ✅ Enforce HTTPS via meta tag -->
<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
```

---

## Performance

### Resource Loading

```html
<!-- ❌ Render-blocking scripts in <head> [important] -->
<head>
  <script src="analytics.js"></script>  <!-- Blocks parsing -->
  <script src="app.js"></script>        <!-- Blocks parsing -->
</head>

<!-- ✅ defer for scripts that need DOM, async for independent scripts -->
<head>
  <script src="analytics.js" async></script>  <!-- Loads independently -->
  <script src="app.js" defer></script>         <!-- Runs after DOM parsed -->
</head>

<!-- ✅ Preload critical resources -->
<head>
  <link rel="preload" href="critical-font.woff2" as="font" type="font/woff2" crossorigin>
  <link rel="preload" href="hero-image.webp" as="image">
</head>

<!-- ✅ Prefetch resources for likely next navigation -->
<link rel="prefetch" href="/next-page.html">
<link rel="dns-prefetch" href="//api.external-service.com">
```

### Image Optimization

```html
<!-- ❌ Large unoptimized images without dimensions [important] -->
<img src="hero.png">
<!-- No width/height → layout shift (CLS), no lazy loading -->

<!-- ✅ Specify dimensions, use modern formats, lazy-load below fold -->
<img src="hero.webp"
     width="1200" height="600"
     alt="Dashboard overview"
     loading="lazy"
     decoding="async">

<!-- ✅ Responsive images with srcset -->
<img srcset="hero-400.webp 400w,
             hero-800.webp 800w,
             hero-1200.webp 1200w"
     sizes="(max-width: 600px) 400px, (max-width: 1000px) 800px, 1200px"
     src="hero-800.webp"
     alt="Dashboard overview"
     width="1200" height="600"
     loading="lazy">

<!-- ✅ Use <picture> for format fallback -->
<picture>
  <source srcset="hero.avif" type="image/avif">
  <source srcset="hero.webp" type="image/webp">
  <img src="hero.jpg" alt="Dashboard overview" width="1200" height="600" loading="lazy">
</picture>
```

### Inline Critical CSS

```html
<!-- ❌ Large external CSS blocking first paint [nit] -->
<head>
  <link rel="stylesheet" href="all-styles.css">  <!-- 200KB blocks render -->
</head>

<!-- ✅ Inline critical CSS, defer non-critical -->
<head>
  <style>
    /* Critical above-the-fold styles only */
    body { margin: 0; font-family: system-ui; }
    .header { background: #1a1a2e; color: white; }
  </style>
  <link rel="preload" href="full-styles.css" as="style" onload="this.rel='stylesheet'">
  <noscript><link rel="stylesheet" href="full-styles.css"></noscript>
</head>
```

---

## Semantic HTML

### Meaningful Structure

```html
<!-- ❌ Generic div soup [nit] -->
<div class="article">
  <div class="title">Patient Report</div>
  <div class="date">2026-05-23</div>
  <div class="content">...</div>
</div>

<!-- ✅ Semantic elements convey meaning to assistive technology and search engines -->
<article>
  <header>
    <h2>Patient Report</h2>
    <time datetime="2026-05-23">May 23, 2026</time>
  </header>
  <section>...</section>
</article>
```

### Tables

```html
<!-- ❌ Table without headers or caption [important] -->
<table>
  <tr><td>Jan de Vries</td><td>1990-01-15</td><td>Active</td></tr>
  <tr><td>Marie Jansen</td><td>1985-03-22</td><td>Discharged</td></tr>
</table>

<!-- ✅ Accessible table with headers, caption, and scope -->
<table>
  <caption>Patient Overview</caption>
  <thead>
    <tr>
      <th scope="col">Name</th>
      <th scope="col">Date of Birth</th>
      <th scope="col">Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Jan de Vries</td>
      <td><time datetime="1990-01-15">15 Jan 1990</time></td>
      <td>Active</td>
    </tr>
  </tbody>
</table>
```

---

## Review Checklist

### Security (Severity: blocking)
- [ ] No `innerHTML` / `document.write` with user input
- [ ] Template output escaped by default (no `| safe`, `{!! !!}`, `raw`)
- [ ] No user input in inline `<script>` blocks or event handlers
- [ ] CSRF tokens on all POST/PUT/DELETE forms
- [ ] Client-side validation backed by server-side validation
- [ ] No unvalidated redirect URLs
- [ ] No HTTP resources on HTTPS pages (mixed content)

### Content Security Policy (Severity: important)
- [ ] CSP header configured (at minimum `default-src 'self'`)
- [ ] `'unsafe-inline'` and `'unsafe-eval'` avoided or nonce-based
- [ ] `frame-ancestors` set to prevent clickjacking

### Accessibility (Severity: important)
- [ ] All images have `alt` attributes (descriptive or empty for decorative)
- [ ] All form inputs have associated `<label>` elements
- [ ] Buttons and interactive elements are keyboard accessible
- [ ] Heading levels are sequential (`h1` > `h2` > `h3`)
- [ ] No positive `tabindex` values
- [ ] ARIA roles used only when semantic HTML is insufficient
- [ ] Color is not the sole means of conveying information

### Iframes (Severity: important)
- [ ] External iframes have `sandbox` attribute
- [ ] Iframes have `title` attribute for accessibility
- [ ] `X-Frame-Options` or CSP `frame-ancestors` set for own pages

### Links (Severity: important)
- [ ] `target="_blank"` links have `rel="noopener noreferrer"`

### Performance (Severity: nit)
- [ ] Scripts use `defer` or `async` (not render-blocking in `<head>`)
- [ ] Images have `width` and `height` attributes (prevent layout shift)
- [ ] Below-fold images use `loading="lazy"`
- [ ] Critical resources use `<link rel="preload">`
- [ ] Modern image formats (WebP/AVIF) used with fallback

### SEO (Severity: nit)
- [ ] Unique `<title>` and `<meta name="description">` per page
- [ ] `<meta name="viewport">` present
- [ ] Canonical URL specified
- [ ] Heading hierarchy is logical and sequential

### Semantic HTML (Severity: nit)
- [ ] Semantic elements used (`<article>`, `<section>`, `<nav>`, `<main>`, etc.)
- [ ] Tables have `<thead>`, `<th>`, and `scope` attributes
- [ ] Dates wrapped in `<time>` with `datetime` attribute
