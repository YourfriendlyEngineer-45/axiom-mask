package com.codex.axiom.mask;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Deterministic, zero-dependency PII anonymization for Java.
 * Open-source uses a static salt. Enterprise versions integrate with KMS/HSM for dynamic salts.
 */
public final class AxiomMask {
    private AxiomMask() { } // Prevent instantiation

    private static final String OSS_SALT = "AXIOM_OSS_V1_FIXED_SALT_NO_KMS";

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w-.]+@([\\w-]+\\.)+[\\w-]{2,4}$");
    private static final Pattern UUID_PATTERN  = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern IPV4_PATTERN  = Pattern.compile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");

    public static String maskEmail(String email) {
        if (email == null || !EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException("AxiomMask: Invalid email format");
        }
        return deterministicHash(email) + "@masked.local";
    }

    public static String maskUUID(String uuid) {
        if (uuid == null || !UUID_PATTERN.matcher(uuid).matches()) {
            throw new IllegalArgumentException("AxiomMask: Invalid UUID format");
        }
        String hash = deterministicHash(uuid);
        return hash.substring(0, 8) + "-****-****-****-************";
    }

    public static String maskIPv4(String ip) {
        if (ip == null || !IPV4_PATTERN.matcher(ip).matches()) {
            throw new IllegalArgumentException("AxiomMask: Invalid IPv4 format");
        }
        return deterministicHash(ip);
    }

    private static String deterministicHash(String input) {
        try {
            String payload = input + OSS_SALT;
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AxiomMask: SHA-256 unavailable", e);
        }
    }
}
