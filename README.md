# Axiom Mask

Deterministic, zero-dependency PII anonymization for Java.

## Features
- **Zero Dependencies:** Pure Java 17+. No external JARs.
- **Deterministic Hashing:** Identical inputs always produce identical masked outputs.
- **Strict Validation:** Fail-fast exceptions on malformed emails, UUIDs, or IPs.
- **Enterprise Ready:** Seamless upgrade path to HSM/KMS-backed dynamic salts via [Axiom Enterprise](https://codexgroup.com/enterprise).

## Installation
Add to your `pom.xml`:
```xml
<dependency>
    <groupId>com.codex.axiom</groupId>
    <artifactId>axiom-mask</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage
```java
import com.codex.axiom.mask.AxiomMask;

public class Example {
    public static void main(String[] args) {
        String safeEmail = AxiomMask.maskEmail("user@company.com");
        // Output: <base64hash>@masked.local
    }
}
```

## Open-Core Architecture
This repository contains the open-source validation and masking layer. It uses a **fixed static salt** for development and testing.

For production, regulated environments, or compliance mandates (SOC 2, GDPR, HIPAA), upgrade to **Axiom Enterprise**. It provides:
- Dynamic salt rotation via AWS KMS, HashiCorp Vault, or HSM
- Centralized masking policy management
- Automated, tamper-evident compliance reporting
- 24/7 enterprise SLA

## License
Apache License 2.0 © The Codex Group
