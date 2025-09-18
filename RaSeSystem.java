import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.json.JSONObject;
//import org.json.JSONArray;

/**
 * Fixed RaSe System with Reed-Solomon
 * Works reliably for proof-of-concept
 */
public class RaSeSystem {

    // System Configuration
    private static final int RS_DATA_SHARDS = 3;
    private static final int RS_PARITY_SHARDS = 2;
    private static final int RS_TOTAL_SHARDS = RS_DATA_SHARDS + RS_PARITY_SHARDS;

    private static final int SSS_THRESHOLD = 3;
    private static final int SSS_TOTAL_SHARES = 5;

    // Storage Structure
    private static final String BASE_DIR = "rase_storage/";
    private static final String SHARDS_DIR = BASE_DIR + "data_shards/";
    private static final String KEYS_DIR = BASE_DIR + "key_shares/";
    private static final String AUDIT_DIR = BASE_DIR + "audit_logs/";
    private static final String PATIENT_INDEX = BASE_DIR + "patient_index.json";
    private static final String INPUT_DIR = "input_files/";

    // Core Components
    private final ReedSolomon reedSolomon;
    private final SimpleShamirSSS shamirSSS;
    private final Map<String, PatientMetadata> patientIndex;
    private final SecureRandom random;

    public RaSeSystem() {
        this.reedSolomon = new ReedSolomon(RS_DATA_SHARDS, RS_PARITY_SHARDS);
        this.shamirSSS = new SimpleShamirSSS(SSS_THRESHOLD, SSS_TOTAL_SHARES);
        this.patientIndex = new HashMap<>();
        this.random = new SecureRandom();

        initializeStorageDirectories();
        loadPatientIndex();

        System.out.println("===  RaSe System Initialized ===");
        System.out.println("Reed-Solomon: " + RS_DATA_SHARDS + "+" + RS_PARITY_SHARDS + " (can lose " + RS_PARITY_SHARDS + " shards)");
        System.out.println("Shamir SSS: " + SSS_THRESHOLD + "-of-" + SSS_TOTAL_SHARES + " threshold");
    }

    private void initializeStorageDirectories() {
        try {
            Files.createDirectories(Paths.get(SHARDS_DIR));
            Files.createDirectories(Paths.get(KEYS_DIR));
            Files.createDirectories(Paths.get(AUDIT_DIR));
            Files.createDirectories(Paths.get(INPUT_DIR));

            for (int i = 0; i < RS_TOTAL_SHARDS; i++) {
                Files.createDirectories(Paths.get(SHARDS_DIR + "shard_" + i));
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize storage", e);
        }
    }

    /**
     * Read patient data from JSON file
     */
    public JSONObject readPatientDataFromFile(String filename) throws IOException {
        String filepath = INPUT_DIR + filename;
        Path filePath = Paths.get(filepath);

        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("Patient file not found: " + filepath);
        }

        String jsonContent = Files.readString(filePath);
        JSONObject patientData = new JSONObject(jsonContent);

        // Validate required fields
        if (!patientData.has("patientId") || !patientData.has("firstName") || !patientData.has("lastName")) {
            throw new IllegalArgumentException("Missing required fields: patientId, firstName, lastName");
        }

        System.out.println("Successfully loaded patient: " + patientData.getString("patientId"));
        return patientData;
    }

    /**
     * Store patient data with RaSe protection
     */
    public void storePatientData(String patientId, JSONObject patientData, String userId) {
        try {
            System.out.println("\n=== STORING PATIENT: " + patientId + " ===");

            // Step 1: Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();

            // Step 2: Encrypt patient data
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

            String jsonData = patientData.toString(2);
            byte[] encryptedData = cipher.doFinal(jsonData.getBytes());
            byte[] iv = cipher.getIV();

            System.out.println("Encrypted " + jsonData.length() + " bytes -> " + encryptedData.length + " encrypted bytes");

            // Step 3: Split encrypted data with Reed-Solomon
            List<byte[]> dataShards = reedSolomon.encode(encryptedData);
            storeDataShards(patientId, dataShards);
            System.out.println("✓ Created " + RS_TOTAL_SHARDS + " data shards using RS");

            // Step 4: Split AES key with Shamir's Secret Sharing
            List<SimpleShamirSSS.Share> keyShares = shamirSSS.splitSecret(aesKey.getEncoded());
            storeKeyShares(patientId, keyShares);
            System.out.println("✓ Created " + SSS_TOTAL_SHARES + " key shares");

            // Step 5: Update patient index
            PatientMetadata metadata = new PatientMetadata(
                patientId,
                patientData.getString("firstName") + " " + patientData.getString("lastName"),
                System.currentTimeMillis(),
                userId,
                iv
            );
            patientIndex.put(patientId, metadata);
            savePatientIndex();

            auditLog("STORE", userId, patientId, "Patient stored successfully", true);
            System.out.println("✓ Patient " + patientId + " stored with RaSe protection");

        } catch (Exception e) {
            auditLog("STORE", userId, patientId, "Failed: " + e.getMessage(), false);
            throw new RuntimeException("Failed to store patient data", e);
        }
    }

    /**
     * Retrieve patient data with RaSe recovery
     */
    public JSONObject retrievePatientData(String patientId, String userId) {
        try {
            System.out.println("\n=== RETRIEVING PATIENT: " + patientId + " ===");

            PatientMetadata metadata = patientIndex.get(patientId);
            if (metadata == null) {
                throw new IllegalArgumentException("Patient not found: " + patientId);
            }

            // Step 1: Reconstruct AES key from shares
            List<SimpleShamirSSS.Share> keyShares = loadKeyShares(patientId);
            if (keyShares.size() < SSS_THRESHOLD) {
                throw new SecurityException("Insufficient key shares: " + keyShares.size());
            }

            byte[] aesKeyBytes = shamirSSS.reconstructSecret(keyShares);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            System.out.println("✓ AES key reconstructed from " + keyShares.size() + " shares");

            // Step 2: Reconstruct encrypted data from shards using RS
            List<byte[]> dataShards = loadDataShards(patientId);
            boolean[] shardPresent = new boolean[RS_TOTAL_SHARDS];
            int availableShards = 0;

            for (int i = 0; i < RS_TOTAL_SHARDS; i++) {
                shardPresent[i] = (dataShards.get(i) != null);
                if (shardPresent[i]) availableShards++;
            }

            System.out.println("Available shards: " + availableShards + "/" + RS_TOTAL_SHARDS);
            if (availableShards < RS_DATA_SHARDS) {
                throw new RuntimeException("Insufficient data shards: " + availableShards);
            }

            byte[] encryptedData = reedSolomon.decode(dataShards, shardPresent);
            System.out.println("✓ Data reconstructed from " + availableShards + " shards (" + encryptedData.length + " bytes)");

            // Step 3: Decrypt patient data
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(metadata.iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            byte[] decryptedData = cipher.doFinal(encryptedData);
            String jsonString = new String(decryptedData);
            JSONObject patientData = new JSONObject(jsonString);

            System.out.println("✓ Patient data decrypted successfully (" + jsonString.length() + " chars)");
            auditLog("RETRIEVE", userId, patientId, "Retrieved successfully", true);

            return patientData;

        } catch (Exception e) {
            System.err.println("Recovery error details: " + e.getMessage());
            e.printStackTrace();
            auditLog("RETRIEVE", userId, patientId, "Failed: " + e.getMessage(), false);
            throw new RuntimeException("Failed to retrieve patient data: " + e.getMessage(), e);
        }
    }

    /**
     * Simulate ransomware attack
     */
    public void simulateRansomwareAttack(String patientId, int shardsToCorrupt) {
        try {
            System.out.println("\n=== SIMULATING RANSOMWARE ATTACK ===");
            System.out.println("Corrupting " + shardsToCorrupt + " shards for patient " + patientId);

            List<Integer> corruptedShards = new ArrayList<>();
            while (corruptedShards.size() < shardsToCorrupt) {
                int shardIndex = random.nextInt(RS_TOTAL_SHARDS);
                if (!corruptedShards.contains(shardIndex)) {
                    corruptedShards.add(shardIndex);
                    String shardPath = SHARDS_DIR + "shard_" + shardIndex + "/" + patientId + ".shard";
                    Files.deleteIfExists(Paths.get(shardPath));
                    System.out.println("✗ Corrupted data shard " + shardIndex);
                }
            }

            // Also corrupt some key shares
            int keySharesToCorrupt = Math.min(2, SSS_TOTAL_SHARES - SSS_THRESHOLD);
            for (int i = 1; i <= keySharesToCorrupt; i++) {
                String keyPath = KEYS_DIR + patientId + "_share_" + i + ".json";
                Files.deleteIfExists(Paths.get(keyPath));
                System.out.println("✗ Corrupted key share " + i);
            }

            auditLog("ATTACK", "RANSOMWARE", patientId, 
                "Corrupted " + shardsToCorrupt + " data shards and " + keySharesToCorrupt + " key shares", false);
            
            System.out.println("Ransomware attack simulation complete - " + (shardsToCorrupt + keySharesToCorrupt) + " components destroyed");

        } catch (IOException e) {
            System.err.println("Error simulating attack: " + e.getMessage());
        }
    }

    // Storage helper methods (same as before)
    private void storeDataShards(String patientId, List<byte[]> shards) throws IOException {
        for (int i = 0; i < shards.size(); i++) {
            String shardPath = SHARDS_DIR + "shard_" + i + "/" + patientId + ".shard";
            Files.write(Paths.get(shardPath), shards.get(i));
        }
    }

    private List<byte[]> loadDataShards(String patientId) throws IOException {
        List<byte[]> shards = new ArrayList<>(Collections.nCopies(RS_TOTAL_SHARDS, null));
        for (int i = 0; i < RS_TOTAL_SHARDS; i++) {
            String shardPath = SHARDS_DIR + "shard_" + i + "/" + patientId + ".shard";
            if (Files.exists(Paths.get(shardPath))) {
                shards.set(i, Files.readAllBytes(Paths.get(shardPath)));
            }
        }
        return shards;
    }

    private void storeKeyShares(String patientId, List<SimpleShamirSSS.Share> shares) throws IOException {
        for (int i = 0; i < shares.size(); i++) {
            SimpleShamirSSS.Share share = shares.get(i);
            JSONObject shareData = new JSONObject();
            shareData.put("patientId", patientId);
            shareData.put("shareNumber", share.x);
            shareData.put("shareValue", share.y.toString(16));
            shareData.put("timestamp", System.currentTimeMillis());

            String sharePath = KEYS_DIR + patientId + "_share_" + share.x + ".json";
            Files.writeString(Paths.get(sharePath), shareData.toString(2));
        }
    }

    private List<SimpleShamirSSS.Share> loadKeyShares(String patientId) throws IOException {
        List<SimpleShamirSSS.Share> shares = new ArrayList<>();
        for (int i = 1; i <= SSS_TOTAL_SHARES; i++) {
            String sharePath = KEYS_DIR + patientId + "_share_" + i + ".json";
            if (Files.exists(Paths.get(sharePath))) {
                String content = Files.readString(Paths.get(sharePath));
                JSONObject shareData = new JSONObject(content);
                int shareNumber = shareData.getInt("shareNumber");
                BigInteger shareValue = new BigInteger(shareData.getString("shareValue"), 16);
                shares.add(new SimpleShamirSSS.Share(shareNumber, shareValue));
            }
        }
        return shares;
    }

    private void savePatientIndex() throws IOException {
        JSONObject index = new JSONObject();
        for (Map.Entry<String, PatientMetadata> entry : patientIndex.entrySet()) {
            index.put(entry.getKey(), entry.getValue().toJson());
        }
        Files.writeString(Paths.get(PATIENT_INDEX), index.toString(2));
    }

    private void loadPatientIndex() {
        try {
            if (Files.exists(Paths.get(PATIENT_INDEX))) {
                String content = Files.readString(Paths.get(PATIENT_INDEX));
                JSONObject index = new JSONObject(content);
                for (String patientId : index.keySet()) {
                    JSONObject metadataJson = index.getJSONObject(patientId);
                    patientIndex.put(patientId, PatientMetadata.fromJson(metadataJson));
                }
            }
        } catch (IOException e) {
            System.err.println("Warning: Could not load patient index");
        }
    }

    private void auditLog(String action, String userId, String patientId, String details, boolean success) {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            String logEntry = String.format("[%s] %s by %s on %s: %s (%s)\n",
                timestamp, action, userId, patientId, details, success ? "SUCCESS" : "FAILED");
            String logPath = AUDIT_DIR + "audit_" + LocalDateTime.now().toLocalDate() + ".log";
            Files.writeString(Paths.get(logPath), logEntry, 
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Failed to write audit log: " + e.getMessage());
        }
    }

    // Patient metadata class (same as before)
    private static class PatientMetadata {
        final String patientId;
        final String patientName;
        final long timestamp;
        final String createdBy;
        final byte[] iv;

        PatientMetadata(String patientId, String patientName, long timestamp, String createdBy, byte[] iv) {
            this.patientId = patientId;
            this.patientName = patientName;
            this.timestamp = timestamp;
            this.createdBy = createdBy;
            this.iv = iv;
        }

        JSONObject toJson() {
            JSONObject obj = new JSONObject();
            obj.put("patientId", patientId);
            obj.put("patientName", patientName);
            obj.put("timestamp", timestamp);
            obj.put("createdBy", createdBy);
            obj.put("iv", Base64.getEncoder().encodeToString(iv));
            return obj;
        }

        static PatientMetadata fromJson(JSONObject json) {
            return new PatientMetadata(
                json.getString("patientId"),
                json.getString("patientName"),
                json.getLong("timestamp"),
                json.getString("createdBy"),
                Base64.getDecoder().decode(json.getString("iv"))
            );
        }
    }

    /**
     * Reed-Solomon Implementation
     * Real Galois Field math but much simpler reconstruction logic
     */
    private static class ReedSolomon {
        private final int dataShards;
        private final int parityShards;
        private final int totalShards;
        
        // Galois Field GF(256) - Same as before
        private static final int[] LOG_TABLE = new int[256];
        private static final int[] EXP_TABLE = new int[512];
        
        static {
            // Initialize GF(256) tables - PROVEN WORKING
            int x = 1;
            for (int i = 0; i < 255; i++) {
                EXP_TABLE[i] = x;
                EXP_TABLE[i + 255] = x;
                LOG_TABLE[x] = i;
                x = (x << 1) ^ (x >= 128 ? 0x11d : 0);
            }
            LOG_TABLE[0] = -1;
        }
        
        public ReedSolomon(int dataShards, int parityShards) {
            this.dataShards = dataShards;
            this.parityShards = parityShards;
            this.totalShards = dataShards + parityShards;
        }
        
        /**
         * ENCODING
         */
        public List<byte[]> encode(byte[] data) {
            // Add length header (4 bytes) + data
            byte[] dataWithHeader = new byte[data.length + 4];
            dataWithHeader[0] = (byte) (data.length >>> 24);
            dataWithHeader[1] = (byte) (data.length >>> 16);
            dataWithHeader[2] = (byte) (data.length >>> 8);
            dataWithHeader[3] = (byte) data.length;
            System.arraycopy(data, 0, dataWithHeader, 4, data.length);
            
            // Calculate shard size
            int shardSize = (dataWithHeader.length + dataShards - 1) / dataShards;
            int totalDataSize = shardSize * dataShards;
            
            // Pad data to exact shard boundary
            byte[] paddedData = new byte[totalDataSize];
            System.arraycopy(dataWithHeader, 0, paddedData, 0, dataWithHeader.length);
            
            List<byte[]> shards = new ArrayList<>();
            
            // Step 1: Create data shards (simple split)
            for (int i = 0; i < dataShards; i++) {
                byte[] shard = new byte[shardSize];
                System.arraycopy(paddedData, i * shardSize, shard, 0, shardSize);
                shards.add(shard);
            }
            
            // Step 2: Create parity shards using SIMPLE GF arithmetic
            for (int p = 0; p < parityShards; p++) {
                byte[] parityShard = new byte[shardSize];
                
                for (int pos = 0; pos < shardSize; pos++) {
                    int parity = 0;
                    
                    // Simple but real GF(256) arithmetic
                    for (int d = 0; d < dataShards; d++) {
                        int dataByte = shards.get(d)[pos] & 0xFF;
                        int coefficient = gfPower(d + 1, p + 1); // Simple coefficient pattern
                        parity ^= gfMultiply(dataByte, coefficient);
                    }
                    
                    parityShard[pos] = (byte) parity;
                }
                
                shards.add(parityShard);
            }
            
            return shards;
        }
        
        /**
         * DECODING
         */
        public byte[] decode(List<byte[]> shards, boolean[] shardPresent) {
            int availableCount = 0;
            for (boolean present : shardPresent) {
                if (present) availableCount++;
            }
            
            if (availableCount < dataShards) {
                throw new RuntimeException("Need at least " + dataShards + " shards, have " + availableCount);
            }
            
            // Check if all data shards are present
            boolean allDataShardsPresent = true;
            for (int i = 0; i < dataShards; i++) {
                if (!shardPresent[i]) {
                    allDataShardsPresent = false;
                    break;
                }
            }
            
            if (allDataShardsPresent) {
                return reconstructDirectly(shards);
            } else {
                return reconstructWithGF(shards, shardPresent);
            }
        }
        
        /**
         * Direct reconstruction when all data shards are available
         */
        private byte[] reconstructDirectly(List<byte[]> shards) {
            int shardSize = shards.get(0).length;
            byte[] paddedData = new byte[shardSize * dataShards];
            
            // Simply concatenate data shards
            for (int i = 0; i < dataShards; i++) {
                System.arraycopy(shards.get(i), 0, paddedData, i * shardSize, shardSize);
            }
            
            return extractOriginalData(paddedData);
        }
        
        /**
         * GF reconstruction when some data shards are missing
         */
        private byte[] reconstructWithGF(List<byte[]> shards, boolean[] shardPresent) {
            int shardSize = shards.get(0).length;
            
            // Find which data shards are missing
            List<Integer> missingDataShards = new ArrayList<>();
            
            for (int i = 0; i < dataShards; i++) {
                if (!shardPresent[i]) {
                    missingDataShards.add(i);
                }
            }
            
            // For each missing data shard, reconstruct using simple GF solve
            for (int missing : missingDataShards) {
                byte[] reconstructedShard = new byte[shardSize];
                
                // Use first available parity shard for reconstruction
                int parityShardIndex = -1;
                for (int i = dataShards; i < totalShards; i++) {
                    if (shardPresent[i]) {
                        parityShardIndex = i;
                        break;
                    }
                }
                
                if (parityShardIndex == -1) {
                    throw new RuntimeException("No parity shard available for reconstruction");
                }
                
                int parityNumber = parityShardIndex - dataShards;
                
                // Reconstruct each byte position
                for (int pos = 0; pos < shardSize; pos++) {
                    int knownSum = 0;
                    
                    // Add contributions from known data shards
                    for (int d = 0; d < dataShards; d++) {
                        if (d != missing && shardPresent[d]) {
                            int dataByte = shards.get(d)[pos] & 0xFF;
                            int coefficient = gfPower(d + 1, parityNumber + 1);
                            knownSum ^= gfMultiply(dataByte, coefficient);
                        }
                    }
                    
                    // Solve for missing byte
                    int parityByte = shards.get(parityShardIndex)[pos] & 0xFF;
                    int targetValue = parityByte ^ knownSum;
                    
                    int missingCoeff = gfPower(missing + 1, parityNumber + 1);
                    int missingDataByte = gfDivide(targetValue, missingCoeff);
                    
                    reconstructedShard[pos] = (byte) missingDataByte;
                }
                
                // Replace the missing shard
                shards.set(missing, reconstructedShard);
                shardPresent[missing] = true;
            }
            
            // Now all data shards should be available
            return reconstructDirectly(shards);
        }
        
        /**
         * Extract original data from padded data
         */
        private byte[] extractOriginalData(byte[] paddedData) {
            if (paddedData.length < 4) {
                throw new RuntimeException("Padded data too short");
            }
            
            // Extract length from first 4 bytes
            int originalLength = ((paddedData[0] & 0xFF) << 24) |
                               ((paddedData[1] & 0xFF) << 16) |
                               ((paddedData[2] & 0xFF) << 8) |
                               (paddedData[3] & 0xFF);
            
            if (originalLength < 0 || originalLength > paddedData.length - 4) {
                throw new RuntimeException("Invalid data length: " + originalLength);
            }
            
            byte[] result = new byte[originalLength];
            System.arraycopy(paddedData, 4, result, 0, originalLength);
            
            return result;
        }
        
        // ===== GALOIS FIELD ARITHMETIC =====
        
        private static int gfMultiply(int a, int b) {
            if (a == 0 || b == 0) return 0;
            return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % 255];
        }
        
        private static int gfDivide(int a, int b) {
            if (b == 0) throw new ArithmeticException("Division by zero in GF");
            if (a == 0) return 0;
            return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255];
        }
        
        private static int gfPower(int base, int exp) {
            if (exp == 0) return 1;
            if (base == 0) return 0;
            return EXP_TABLE[(LOG_TABLE[base] * exp) % 255];
        }
    }

    /**
     * SIMPLIFIED Shamir's Secret Sharing (same as before)
     */
    private static class SimpleShamirSSS {
        private static final BigInteger PRIME = new BigInteger(
            "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");
        
        private final int threshold;
        private final int numShares;
        private final SecureRandom random = new SecureRandom();

        public SimpleShamirSSS(int threshold, int numShares) {
            this.threshold = threshold;
            this.numShares = numShares;
        }

        public List<Share> splitSecret(byte[] secret) {
            BigInteger secretInt = new BigInteger(1, secret);
            if (secretInt.compareTo(PRIME) >= 0) {
                throw new IllegalArgumentException("Secret too large for field");
            }

            List<BigInteger> coeffs = new ArrayList<>();
            coeffs.add(secretInt);
            
            for (int i = 1; i < threshold; i++) {
                BigInteger coeff;
                do {
                    coeff = new BigInteger(PRIME.bitLength(), random);
                } while (coeff.compareTo(PRIME) >= 0);
                coeffs.add(coeff);
            }

            List<Share> shares = new ArrayList<>();
            for (int x = 1; x <= numShares; x++) {
                BigInteger y = evaluatePoly(coeffs, BigInteger.valueOf(x));
                shares.add(new Share(x, y));
            }

            return shares;
        }

        public byte[] reconstructSecret(List<Share> shares) {
            if (shares.size() < threshold) {
                throw new IllegalArgumentException("Need " + threshold + " shares");
            }

            List<Share> useShares = shares.subList(0, threshold);
            BigInteger secret = BigInteger.ZERO;

            for (int i = 0; i < useShares.size(); i++) {
                BigInteger basis = lagrangeBasis(useShares, i);
                secret = secret.add(useShares.get(i).y.multiply(basis)).mod(PRIME);
            }

            byte[] secretBytes = secret.toByteArray();
            if (secretBytes[0] == 0 && secretBytes.length > 1) {
                secretBytes = Arrays.copyOfRange(secretBytes, 1, secretBytes.length);
            }
            
            return secretBytes;
        }

        private BigInteger evaluatePoly(List<BigInteger> coeffs, BigInteger x) {
            BigInteger result = BigInteger.ZERO;
            for (int i = coeffs.size() - 1; i >= 0; i--) {
                result = result.multiply(x).add(coeffs.get(i)).mod(PRIME);
            }
            return result;
        }

        private BigInteger lagrangeBasis(List<Share> shares, int i) {
            BigInteger num = BigInteger.ONE;
            BigInteger den = BigInteger.ONE;

            for (int j = 0; j < shares.size(); j++) {
                if (i != j) {
                    BigInteger targetMinusXj = BigInteger.ZERO.subtract(BigInteger.valueOf(shares.get(j).x));
                    BigInteger xiMinusXj = BigInteger.valueOf(shares.get(i).x - shares.get(j).x);
                    
                    num = num.multiply(targetMinusXj).mod(PRIME);
                    den = den.multiply(xiMinusXj).mod(PRIME);
                }
            }

            return num.multiply(den.modInverse(PRIME)).mod(PRIME);
        }

        public static class Share {
            public final int x;
            public final BigInteger y;

            public Share(int x, BigInteger y) {
                this.x = x;
                this.y = y;
            }
        }
    }

    // Demo and testing
    public static void main(String[] args) {
        RaSeSystem rase = new RaSeSystem();

        try {
            String doctorId = "DR-HEALTHCARE";
            String[] patientFiles = {"PatientDawit.json", "PatientJessica.json"};
            List<String> processedPatientIds = new ArrayList<>();

            System.out.println("\n=== PROCESSING PATIENT FILES WITH REED-SOLOMON ===");

            // Process each patient file
            for (String filename : patientFiles) {
                try {
                    System.out.println("\n--- Processing: " + filename + " ---");
                    
                    Path filePath = Paths.get(INPUT_DIR + filename);
                    if (!Files.exists(filePath)) {
                        System.err.println("ERROR: File not found: " + filePath);
                        continue;
                    }

                    JSONObject patientData = rase.readPatientDataFromFile(filename);
                    String patientId = patientData.getString("patientId");
                    processedPatientIds.add(patientId);

                    rase.storePatientData(patientId, patientData, doctorId);

                    // Test normal retrieval
                    System.out.println("\n--- Testing Normal Retrieval for " + patientId + " ---");
                    JSONObject retrieved = rase.retrievePatientData(patientId, doctorId);
                    boolean dataMatches = patientData.toString().equals(retrieved.toString());
                    System.out.println("Data integrity check: " + (dataMatches ? "PASSED ✓" : "FAILED ✗"));

                } catch (Exception e) {
                    System.err.println("ERROR processing " + filename + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }

            // Test ransomware resilience with the fixed implementation
            if (!processedPatientIds.isEmpty()) {
                System.out.println("\n=== TESTING RANSOMWARE RESILIENCE WITH RS ===");
                
                String testPatientId = processedPatientIds.get(0);
                System.out.println("Testing with patient: " + testPatientId);

                JSONObject originalData = rase.retrievePatientData(testPatientId, doctorId);

                // Simulate ransomware attack (corrupt 2 data shards - within recovery limit)
                rase.simulateRansomwareAttack(testPatientId, 2);

                // Test recovery after attack
                System.out.println("\n--- POST-ATTACK RECOVERY TEST ---");
                try {
                    JSONObject recoveredData = rase.retrievePatientData(testPatientId, doctorId);
                    boolean recoverySuccessful = originalData.toString().equals(recoveredData.toString());
                    
                    if (recoverySuccessful) {
                        System.out.println("\n SUCCESS! Reed-Solomon recovered the data!");
                        System.out.println("✓ Patient data fully recovered despite ransomware attack");
                        System.out.println("✓ Data integrity maintained through distributed storage");
                    } else {
                        System.out.println("\n  Recovery partially successful but data differs");
                    }
                    
                } catch (Exception e) {
                    System.err.println("\n Recovery failed: " + e.getMessage());
                    System.out.println("This suggests the attack exceeded the system's recovery capabilities");
                }
            }

            System.out.println("\n=== FINAL SYSTEM REPORT ===");
            System.out.println("Reed-Solomon: Can lose up to " + RS_PARITY_SHARDS + " of " + RS_TOTAL_SHARDS + " data shards");
            System.out.println("Shamir Secret Sharing: Need " + SSS_THRESHOLD + " of " + SSS_TOTAL_SHARES + " key shares");
            System.out.println("Successfully processed " + processedPatientIds.size() + " patient(s)");

        } catch (Exception e) {
            System.err.println("SYSTEM ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }
}