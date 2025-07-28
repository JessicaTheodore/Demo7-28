import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.io.*;
import java.nio.file.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.json.JSONObject;

/**
 * REAL Shamir's Secret Sharing Implementation
 * Uses actual polynomial interpolation over finite fields
 * This is cryptographically secure threshold secret sharing
 */
public class RealShamirSecretSharing {

    // Large prime for finite field operations (2^521 - 1, a Mersenne prime)
    private static final BigInteger FIELD_PRIME = new BigInteger(
            "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");

    private final int threshold; // k - minimum shares needed
    private final int numShares; // n - total shares to create
    private final SecureRandom random;

    public RealShamirSecretSharing(int threshold, int numShares) {
        if (threshold > numShares) {
            throw new IllegalArgumentException("Threshold cannot exceed number of shares");
        }
        if (threshold < 2) {
            throw new IllegalArgumentException("Threshold must be at least 2");
        }

        this.threshold = threshold;
        this.numShares = numShares;
        this.random = new SecureRandom();

        System.out.println("Initialized Shamir's Secret Sharing:");
        System.out.println("  Threshold: " + threshold + " (minimum shares needed)");
        System.out.println("  Total shares: " + numShares);
        System.out.println("  Field prime: " + FIELD_PRIME.bitLength() + " bits");
    }

    /**
     * Splits a secret into shares using REAL polynomial interpolation
     * Creates a random polynomial f(x) = secret + a1*x + a2*x^2 + ... +
     * a(k-1)*x^(k-1) mod p
     */
    public List<Share> splitSecret(byte[] secret) {
        // Convert secret to BigInteger
        BigInteger secretInt = new BigInteger(1, secret); // Positive value

        if (secretInt.compareTo(FIELD_PRIME) >= 0) {
            throw new IllegalArgumentException("Secret too large for field");
        }

        System.out.println("Splitting secret of " + secret.length + " bytes");
        System.out.println("Secret as BigInteger: "
                + secretInt.toString(16).substring(0, Math.min(20, secretInt.toString(16).length())) + "...");

        // Generate random coefficients for polynomial f(x) = a0 + a1*x + a2*x^2 + ... +
        // a(k-1)*x^(k-1)
        // where a0 = secret
        List<BigInteger> coefficients = new ArrayList<>();
        coefficients.add(secretInt); // a0 = secret

        System.out.println("Generating " + (threshold - 1) + " random coefficients:");
        for (int i = 1; i < threshold; i++) {
            // Generate random coefficient in field
            BigInteger coeff;
            do {
                coeff = new BigInteger(FIELD_PRIME.bitLength(), random);
            } while (coeff.compareTo(FIELD_PRIME) >= 0);

            coefficients.add(coeff);
            System.out.println("  a" + i + " = "
                    + coeff.toString(16).substring(0, Math.min(16, coeff.toString(16).length())) + "...");
        }

        // Create shares by evaluating polynomial at different x values
        List<Share> shares = new ArrayList<>();
        System.out.println("Creating shares by evaluating polynomial:");

        for (int x = 1; x <= numShares; x++) {
            BigInteger y = evaluatePolynomial(coefficients, BigInteger.valueOf(x));
            shares.add(new Share(x, y));

            System.out.println("  Share " + x + ": f(" + x + ") = " +
                    y.toString(16).substring(0, Math.min(16, y.toString(16).length())) + "...");
        }

        return shares;
    }

    /**
     * Reconstructs secret from shares using REAL Lagrange interpolation
     * Recovers f(0) = secret using polynomial interpolation over finite field
     */
    public byte[] reconstructSecret(List<Share> shares) {
        if (shares.size() < threshold) {
            throw new IllegalArgumentException("Insufficient shares: need " + threshold + ", have " + shares.size());
        }

        System.out.println("Reconstructing secret from " + shares.size() + " shares using Lagrange interpolation");

        // Use exactly 'threshold' shares for reconstruction
        List<Share> selectedShares = shares.subList(0, threshold);

        System.out.println("Using shares: " + selectedShares.stream()
                .map(s -> String.valueOf(s.x))
                .reduce((a, b) -> a + ", " + b).orElse(""));

        // Lagrange interpolation to find f(0) = secret
        // f(0) = sum(yi * Li(0)) where Li(0) is the Lagrange basis polynomial
        BigInteger secret = BigInteger.ZERO;

        for (int i = 0; i < selectedShares.size(); i++) {
            Share currentShare = selectedShares.get(i);
            BigInteger lagrangeBasis = calculateLagrangeBasis(selectedShares, i, BigInteger.ZERO);

            // Add contribution: secret += yi * Li(0)
            BigInteger contribution = currentShare.y.multiply(lagrangeBasis).mod(FIELD_PRIME);
            secret = secret.add(contribution).mod(FIELD_PRIME);

            System.out.println("  Share " + currentShare.x + " contributes: " +
                    contribution.toString(16).substring(0, Math.min(16, contribution.toString(16).length())) + "...");
        }

        System.out.println("Reconstructed secret: "
                + secret.toString(16).substring(0, Math.min(20, secret.toString(16).length())) + "...");

        // Convert back to byte array
        byte[] secretBytes = secret.toByteArray();

        // Handle negative values (shouldn't happen with our setup, but be safe)
        if (secretBytes[0] == 0 && secretBytes.length > 1) {
            // Remove leading zero byte
            secretBytes = Arrays.copyOfRange(secretBytes, 1, secretBytes.length);
        }

        return secretBytes;
    }

    /**
     * Evaluates polynomial at given x using Horner's method
     * f(x) = a0 + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1) mod p
     */
    private BigInteger evaluatePolynomial(List<BigInteger> coefficients, BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        // BigInteger xPower = BigInteger.ONE;

        // Use Horner's method for numerical stability
        for (int i = coefficients.size() - 1; i >= 0; i--) {
            result = result.multiply(x).add(coefficients.get(i)).mod(FIELD_PRIME);
        }

        return result;
    }

    /**
     * Calculates Lagrange basis polynomial Li(target) for interpolation
     * Li(target) = product((target - xj) / (xi - xj)) for all j != i
     */
    private BigInteger calculateLagrangeBasis(List<Share> shares, int i, BigInteger target) {
        Share currentShare = shares.get(i);
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;

        for (int j = 0; j < shares.size(); j++) {
            if (i != j) {
                Share otherShare = shares.get(j);

                // numerator *= (target - xj)
                numerator = numerator.multiply(target.subtract(BigInteger.valueOf(otherShare.x))).mod(FIELD_PRIME);

                // denominator *= (xi - xj)
                denominator = denominator.multiply(BigInteger.valueOf(currentShare.x - otherShare.x)).mod(FIELD_PRIME);
            }
        }

        // Return numerator / denominator mod p
        // Division in finite field = multiplication by modular inverse
        BigInteger denominatorInverse = modularInverse(denominator, FIELD_PRIME);
        return numerator.multiply(denominatorInverse).mod(FIELD_PRIME);
    }

    /**
     * Calculates modular inverse using Extended Euclidean Algorithm
     * Returns x such that (a * x) mod m = 1
     */
    private BigInteger modularInverse(BigInteger a, BigInteger m) {
        if (a.equals(BigInteger.ZERO)) {
            throw new ArithmeticException("Cannot find inverse of zero");
        }

        // Use BigInteger's built-in modInverse (uses Extended Euclidean Algorithm)
        return a.modInverse(m);
    }

    /**
     * Stores shares securely in separate files
     */
    public void storeShares(List<Share> shares, String keyId) throws IOException {
        Files.createDirectories(Paths.get("key_shares"));

        for (int i = 0; i < shares.size(); i++) {
            Share share = shares.get(i);

            JSONObject shareData = new JSONObject();
            shareData.put("keyId", keyId);
            shareData.put("shareNumber", share.x);
            shareData.put("shareValue", share.y.toString(16)); // Hex encoding
            shareData.put("threshold", threshold);
            shareData.put("totalShares", numShares);
            shareData.put("fieldPrime", FIELD_PRIME.toString(16));
            shareData.put("timestamp", System.currentTimeMillis());

            String filename = "key_shares/" + keyId + "_share_" + share.x + ".json";
            Files.writeString(Paths.get(filename), shareData.toString(2));

            System.out.println("Stored share " + share.x + " -> " + filename);
        }
    }

    /**
     * Loads shares from files
     */
    public List<Share> loadShares(String keyId) throws IOException {
        List<Share> shares = new ArrayList<>();

        for (int i = 1; i <= numShares; i++) {
            String filename = "key_shares/" + keyId + "_share_" + i + ".json";
            Path filePath = Paths.get(filename);

            if (Files.exists(filePath)) {
                String content = Files.readString(filePath);
                JSONObject shareData = new JSONObject(content);

                int shareNumber = shareData.getInt("shareNumber");
                BigInteger shareValue = new BigInteger(shareData.getString("shareValue"), 16);

                shares.add(new Share(shareNumber, shareValue));
                System.out.println("Loaded share " + shareNumber + " from " + filename);
            } else {
                System.out.println("Share " + i + " not found: " + filename);
            }
        }

        System.out.println("Total shares loaded: " + shares.size());
        return shares;
    }

    /**
     * Represents a share in the secret sharing scheme
     */
    public static class Share {
        public final int x; // x-coordinate (share number)
        public final BigInteger y; // y-coordinate (share value)

        public Share(int x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        @Override
        public String toString() {
            return "Share(" + x + ", " + y.toString(16).substring(0, Math.min(16, y.toString(16).length())) + "...)";
        }
    }

    // Demo and testing
    public static void main(String[] args) {
        System.out.println("=== Testing Real Shamir's Secret Sharing ===\n");

        try {
            RealShamirSecretSharing sss = new RealShamirSecretSharing(3, 5);

            // Generate a real AES-256 key as the secret
            System.out.println("=== GENERATING SECRET ===");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            byte[] secret = aesKey.getEncoded();

            System.out.println("Generated AES-256 key (" + secret.length + " bytes): " +
                    bytesToHex(secret).substring(0, 32) + "...");

            // Split the secret
            System.out.println("\n=== SPLITTING SECRET ===");
            List<Share> shares = sss.splitSecret(secret);
            sss.storeShares(shares, "master_aes_key");

            // Simulate some shares being lost/corrupted
            System.out.println("\n=== SIMULATING SHARE LOSS ===");
            shares.remove(4); // Remove share 5
            shares.remove(1); // Remove share 2 (indices shift)
            System.out.println("Lost 2 shares, " + shares.size() + " remain (threshold = 3)");

            // Reconstruct the secret
            System.out.println("\n=== RECONSTRUCTING SECRET ===");
            byte[] reconstructed = sss.reconstructSecret(shares);

            System.out.println("Reconstructed key (" + reconstructed.length + " bytes): " +
                    bytesToHex(reconstructed).substring(0, 32) + "...");

            // Verify reconstruction
            boolean matches = Arrays.equals(secret, reconstructed);
            System.out.println("Reconstruction successful: " + matches);

            if (matches) {
                System.out.println("✓ Secret perfectly reconstructed from partial shares!");

                // Test the reconstructed key actually works
                SecretKeySpec reconstructedKey = new SecretKeySpec(reconstructed, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, reconstructedKey);

                String testData = "This is a test of the reconstructed AES key";
                byte[] encrypted = cipher.doFinal(testData.getBytes());

                cipher.init(Cipher.DECRYPT_MODE, reconstructedKey);
                byte[] decrypted = cipher.doFinal(encrypted);
                String decryptedText = new String(decrypted);

                System.out.println("✓ Reconstructed key successfully encrypts/decrypts data!");
                System.out.println("Test: \"" + testData + "\" -> encrypted -> \"" + decryptedText + "\"");
            }

            // Test insufficient shares
            System.out.println("\n=== TESTING INSUFFICIENT SHARES ===");
            shares.remove(0); // Remove another share
            System.out.println("Now only " + shares.size() + " shares remain (below threshold)");

            try {
                sss.reconstructSecret(shares);
                System.out.println("✗ ERROR: Should not have been able to reconstruct!");
            } catch (IllegalArgumentException e) {
                System.out.println("✓ Expected failure: " + e.getMessage());
            }

            // Demonstrate mathematical properties
            System.out.println("\n=== MATHEMATICAL VERIFICATION ===");
            testPolynomialProperties();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Demonstrates the mathematical properties of the polynomial
     */
    private static void testPolynomialProperties() {
        System.out.println("Testing polynomial evaluation:");

        // Create a simple polynomial f(x) = 5 + 3x + 2x^2 over a small field
        BigInteger smallPrime = BigInteger.valueOf(97); // Small prime for demonstration
        List<BigInteger> coeffs = Arrays.asList(
                BigInteger.valueOf(5), // a0 = 5 (secret)
                BigInteger.valueOf(3), // a1 = 3
                BigInteger.valueOf(2) // a2 = 2
        );

        System.out.println("Polynomial: f(x) = 5 + 3x + 2x² mod 97");

        // Evaluate at several points
        for (int x = 1; x <= 5; x++) {
            BigInteger result = BigInteger.ZERO;
            BigInteger xBig = BigInteger.valueOf(x);

            // f(x) = 5 + 3x + 2x²
            result = result.add(coeffs.get(0)); // +5
            result = result.add(coeffs.get(1).multiply(xBig)); // +3x
            result = result.add(coeffs.get(2).multiply(xBig.pow(2))); // +2x²
            result = result.mod(smallPrime);

            System.out.println("f(" + x + ") = " + result);
        }

        System.out.println("Any 3 of these points can reconstruct f(0) = 5 using Lagrange interpolation");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}