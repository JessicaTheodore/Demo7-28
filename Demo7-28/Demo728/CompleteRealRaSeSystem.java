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
import org.json.JSONArray;

/**
 * Complete Real RaSe (Ransom Sentinel) System
 * Combines REAL Reed-Solomon erasure coding with REAL Shamir's Secret Sharing
 * This is a production-quality ransomware-resilient healthcare data storage system
 */
public class CompleteRealRaSeSystem {
    
    // System Configuration
    private static final int RS_DATA_SHARDS = 4;
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
    
    // Core Components
    private final RealReedSolomon reedSolomon;
    private final RealShamirSecretSharing shamirSSS;
    private final Map<String, PatientMetadata> patientIndex;
    private final SecureRandom random;
    
    public CompleteRealRaSeSystem() {
        this.reedSolomon = new RealReedSolomon(RS_DATA_SHARDS, RS_PARITY_SHARDS);
        this.shamirSSS = new RealShamirSecretSharing(SSS_THRESHOLD, SSS_TOTAL_SHARES);
        this.patientIndex = new HashMap<>();
        this.random = new SecureRandom();
        
        initializeStorageDirectories();
        loadPatientIndex();
        
        System.out.println("=== RaSe System Initialized ===");
        System.out.println("Reed-Solomon: " + RS_DATA_SHARDS + "+" + RS_PARITY_SHARDS + " (can lose " + RS_PARITY_SHARDS + " shards)");
        System.out.println("Shamir SSS: " + SSS_THRESHOLD + "-of-" + SSS_TOTAL_SHARES + " threshold");
    }
    
    private void initializeStorageDirectories() {
        try {
            Files.createDirectories(Paths.get(SHARDS_DIR));
            Files.createDirectories(Paths.get(KEYS_DIR));
            Files.createDirectories(Paths.get(AUDIT_DIR));
            
            // Create shard subdirectories for distributed storage
            for (int i = 0; i < RS_TOTAL_SHARDS; i++) {
                Files.createDirectories(Paths.get(SHARDS_DIR + "shard_" + i));
            }
            
            System.out.println("Storage directories initialized");
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize storage", e);
        }
    }
    
    /**
     * Stores patient data with full RaSe protection
     * 1. Generates AES-256 key
     * 2. Encrypts patient data
     * 3. Splits encrypted data with Reed-Solomon
     * 4. Splits AES key with Shamir's Secret Sharing
     * 5. Stores shards in distributed locations
     */
    public void storePatientData(String patientId, JSONObject patientData, String userId) {
        try {
            System.out.println("\n=== STORING PATIENT DATA: " + patientId + " ===");
            
            // Step 1: Generate AES-256 encryption key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            System.out.println("Generated AES-256 key");
            
            // Step 2: Encrypt patient data
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            
            String jsonData = patientData.toString(2);
            byte[] encryptedData = cipher.doFinal(jsonData.getBytes());
            byte[] iv = cipher.getIV();
            
            System.out.println("Encrypted " + jsonData.length() + " bytes of patient data");
            
            // Step 3: Split encrypted data using Reed-Solomon
            List<byte[]> dataShards = reedSolomon.encode(encryptedData);
            storeDataShards(patientId, dataShards);
            System.out.println("Data split into " + RS_TOTAL_SHARDS + " shards with Reed-Solomon");
            
            // Step 4: Split AES key using Shamir's Secret Sharing
            List<RealShamirSecretSharing.Share> keyShares = shamirSSS.splitSecret(aesKey.getEncoded());
            storeKeyShares(patientId, keyShares);
            System.out.println("AES key split into " + SSS_TOTAL_SHARES + " shares with SSS");
            
            // Step 5: Update patient index
            PatientMetadata metadata = new PatientMetadata(
                patientId,
                patientData.getString("firstName") + " " + patientData.getString("lastName"),
                System.currentTimeMillis(),
                userId,
                iv // Store IV for decryption
            );
            patientIndex.put(patientId, metadata);
            savePatientIndex();
            
            // Step 6: Audit log
            auditLog("STORE", userId, patientId, "Patient data stored with RaSe protection", true);
            
            System.out.println("✓ Patient " + patientId + " successfully stored with RaSe protection");
            
        } catch (Exception e) {
            auditLog("STORE", userId, patientId, "Failed: " + e.getMessage(), false);
            throw new RuntimeException("Failed to store patient data", e);
        }
    }
    
    /**
     * Retrieves patient data with full RaSe recovery
     * 1. Loads available key shares and data shards
     * 2. Reconstructs AES key using Shamir's Secret Sharing
     * 3. Reconstructs encrypted data using Reed-Solomon
     * 4. Decrypts and returns patient data
     */
    public JSONObject retrievePatientData(String patientId, String userId, List<String> authorizedUsers) {
        try {
            System.out.println("\n=== RETRIEVING PATIENT DATA: " + patientId + " ===");
            
            // Verify patient exists
            PatientMetadata metadata = patientIndex.get(patientId);
            if (metadata == null) {
                throw new IllegalArgumentException("Patient not found: " + patientId);
            }
            
            // Step 1: Load and reconstruct AES key
            List<RealShamirSecretSharing.Share> keyShares = loadKeyShares(patientId);
            if (keyShares.size() < SSS_THRESHOLD) {
                auditLog("RETRIEVE", userId, patientId, "Insufficient key shares: " + keyShares.size(), false);
                throw new SecurityException("Insufficient key shares for decryption");
            }
            
            byte[] aesKeyBytes = shamirSSS.reconstructSecret(keyShares);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            System.out.println("✓ AES key reconstructed from " + keyShares.size() + " shares");
            
            // Step 2: Load and reconstruct encrypted data
            List<byte[]> dataShards = loadDataShards(patientId);
            boolean[] shardPresent = new boolean[RS_TOTAL_SHARDS];
            int availableShards = 0;
            
            for (int i = 0; i < RS_TOTAL_SHARDS; i++) {
                shardPresent[i] = (dataShards.get(i) != null);
                if (shardPresent[i]) availableShards++;
            }
            
            if (availableShards < RS_DATA_SHARDS) {
                auditLog("RETRIEVE", userId, patientId, "Insufficient data shards: " + availableShards, false);
                throw new RuntimeException("Insufficient data shards for recovery");
            }
            
            byte[] encryptedData = reedSolomon.decode(dataShards, shardPresent);
            System.out.println("✓ Encrypted data reconstructed from " + availableShards + " shards");
            
            // Step 3: Decrypt patient data
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(metadata.iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            
            byte[] decryptedData = cipher.doFinal(encryptedData);
            String jsonString = new String(decryptedData);
            JSONObject patientData = new JSONObject(jsonString);
            
            System.out.println("✓ Patient data decrypted successfully");
            
            // Step 4: Audit log
            auditLog("RETRIEVE", userId, patientId, "Patient data retrieved successfully", true);
            
            return patientData;
            
        } catch (Exception e) {
            auditLog("RETRIEVE", userId, patientId, "Failed: " + e.getMessage(), false);
            throw new RuntimeException("Failed to retrieve patient data", e);
        }
    }
    
    /**
     * Simulates ransomware attack by corrupting random shards
     */
    public void simulateRansomwareAttack(String patientId, int shardsToCorrupt) {
        try {
            System.out.println("\n=== SIMULATING RANSOMWARE ATTACK ===");
            System.out.println("Corrupting " + shardsToCorrupt + " shards for patient " + patientId);
            
            // Randomly corrupt data shards
            List<Integer> corruptedShards = new ArrayList<>();
            while (corruptedShards.size() < shardsToCorrupt) {
                int shardIndex = random.nextInt(RS_TOTAL_SHARDS);
                if (!corruptedShards.contains(shardIndex)) {
                    corruptedShards.add(shardIndex);
                    
                    // Delete the shard file
                    String shardPath = SHARDS_DIR + "shard_" + shardIndex + "/" + patientId + ".shard";
                    Files.deleteIfExists(Paths.get(shardPath));
                    
                    System.out.println("Corrupted shard " + shardIndex);
                }
            }
            
            // Also corrupt some key shares
            int keySharesToCorrupt = Math.min(2, SSS_TOTAL_SHARES - SSS_THRESHOLD);
            for (int i = 1; i <= keySharesToCorrupt; i++) {
                String keyPath = KEYS_DIR + patientId + "_share_" + i + ".json";
                Files.deleteIfExists(Paths.get(keyPath));
                System.out.println("Corrupted key share " + i);
            }
            
            auditLog("ATTACK", "RANSOMWARE", patientId, 
                "Corrupted " + shardsToCorrupt + " data shards and " + keySharesToCorrupt + " key shares", 
                false);
            
            System.out.println("💀 Ransomware attack simulation complete");
            
        } catch (IOException e) {
            System.err.println("Error simulating attack: " + e.getMessage());
        }
    }
    
    // Storage helper methods
    
    private void storeDataShards(String patientId, List<byte[]> shards) throws IOException {
        for (int i = 0; i < shards.size(); i++) {
            String shardDir = SHARDS_DIR + "shard_" + i + "/";
            String shardPath = shardDir + patientId + ".shard";
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
    
    private void storeKeyShares(String patientId, List<RealShamirSecretSharing.Share> shares) throws IOException {
        for (int i = 0; i < shares.size(); i++) {
            RealShamirSecretSharing.Share share = shares.get(i);
            
            JSONObject shareData = new JSONObject();
            shareData.put("patientId", patientId);
            shareData.put("shareNumber", share.x);
            shareData.put("shareValue", share.y.toString(16));
            shareData.put("timestamp", System.currentTimeMillis());
            
            String sharePath = KEYS_DIR + patientId + "_share_" + share.x + ".json";
            Files.writeString(Paths.get(sharePath), shareData.toString(2));
        }
    }
    
    private List<RealShamirSecretSharing.Share> loadKeyShares(String patientId) throws IOException {
        List<RealShamirSecretSharing.Share> shares = new ArrayList<>();
        
        for (int i = 1; i <= SSS_TOTAL_SHARES; i++) {
            String sharePath = KEYS_DIR + patientId + "_share_" + i + ".json";
            if (Files.exists(Paths.get(sharePath))) {
                String content = Files.readString(Paths.get(sharePath));
                JSONObject shareData = new JSONObject(content);
                
                int shareNumber = shareData.getInt("shareNumber");
                BigInteger shareValue = new BigInteger(shareData.getString("shareValue"), 16);
                
                shares.add(new RealShamirSecretSharing.Share(shareNumber, shareValue));
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
    
    // Patient metadata class
    private static class PatientMetadata {
        final String patientId;
        final String patientName;
        final long timestamp;
        final String createdBy;
        final byte[] iv; // AES initialization vector
        
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
    
    // Demo and testing
    public static void main(String[] args) {
        CompleteRealRaSeSystem rase = new CompleteRealRaSeSystem();
        
        // Create comprehensive patient record
        JSONObject patientData = createSamplePatientRecord();
        
        System.out.println("\n=== COMPLETE RaSe SYSTEM DEMONSTRATION ===");
        
        try {
            String patientId = "PAT-2025-001";
            String doctorId = "DR-JOHNSON";
            
            // Store patient data
            rase.storePatientData(patientId, patientData, doctorId);
            
            // Retrieve and verify
            System.out.println("\n=== NORMAL RETRIEVAL TEST ===");
            JSONObject retrieved = rase.retrievePatientData(patientId, doctorId, Arrays.asList(doctorId));
            boolean dataMatches = patientData.toString().equals(retrieved.toString());
            System.out.println("Data integrity check: " + (dataMatches ? "✓ PASSED" : "✗ FAILED"));
            
            // Simulate ransomware attack
            rase.simulateRansomwareAttack(patientId, 2); // Corrupt 2 shards (within recovery limit)
            
            // Test recovery after attack
            System.out.println("\n=== POST-ATTACK RECOVERY TEST ===");
            JSONObject recoveredData = rase.retrievePatientData(patientId, doctorId, Arrays.asList(doctorId));
            boolean recoverySuccessful = patientData.toString().equals(recoveredData.toString());
            System.out.println("Recovery successful: " + (recoverySuccessful ? "✓ PASSED" : "✗ FAILED"));
            
            if (recoverySuccessful) {
                System.out.println("\n🎉 RaSe System successfully protected patient data from ransomware attack!");
                System.out.println("Patient data was fully recovered despite 2 corrupted shards and 2 corrupted key shares.");
            }
            
            // Test catastrophic failure
            System.out.println("\n=== CATASTROPHIC FAILURE TEST ===");
            rase.simulateRansomwareAttack(patientId, 4); // Corrupt too many shards
            
            try {
                rase.retrievePatientData(patientId, doctorId, Arrays.asList(doctorId));
                System.out.println("✗ ERROR: Should not have recovered with too few shards");
            } catch (Exception e) {
                System.out.println("✓ Expected failure with insufficient shards: " + e.getMessage());
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static JSONObject createSamplePatientRecord() {
        JSONObject patient = new JSONObject();
        patient.put("patientId", "PAT-2025-001");
        patient.put("firstName", "John");
        patient.put("lastName", "Doe");
        patient.put("dateOfBirth", "1975-08-15");
        patient.put("ssn", "***-**-1234");
        patient.put("address", new JSONObject()
            .put("street", "123 Healthcare Drive")
            .put("city", "Princeton")
            .put("state", "NJ")
            .put("zip", "08540"));
        patient.put("phone", "609-555-0123");
        patient.put("email", "john.doe@email.com");
        patient.put("emergencyContact", new JSONObject()
            .put("name", "Jane Doe")
            .put("relationship", "Spouse")
            .put("phone", "609-555-0124"));
        patient.put("insurance", new JSONObject()
            .put("provider", "Blue Cross Blue Shield")
            .put("policyNumber", "BC123456789")
            .put("groupNumber", "GRP001"));
        patient.put("bloodType", "O+");
        patient.put("allergies", new JSONArray()
            .put("Penicillin")
            .put("Shellfish")
            .put("Latex"));
        patient.put("currentMedications", new JSONArray()
            .put(new JSONObject().put("name", "Lisinopril").put("dosage", "10mg").put("frequency", "Daily"))
            .put(new JSONObject().put("name", "Metformin").put("dosage", "500mg").put("frequency", "Twice daily")));
        patient.put("medicalHistory", new JSONArray()
            .put("Hypertension (2018)")
            .put("Type 2 Diabetes (2020)")
            .put("Appendectomy (1995)"));
        patient.put("vitals", new JSONObject()
            .put("bloodPressure", "138/82")
            .put("heartRate", 76)
            .put("temperature", 98.4)
            .put("weight", 180)
            .put("height", "5'10\"")
            .put("bmi", 25.8)
            .put("oxygenSaturation", 98));
        patient.put("currentVisit", new JSONObject()
            .put("date", "2025-01-27")
            .put("chiefComplaint", "Follow-up for diabetes and hypertension")
            .put("assessment", "Diabetes well controlled, blood pressure slightly elevated")
            .put("plan", "Continue current medications, increase monitoring")
            .put("physician", "Dr. Sarah Johnson, MD")
            .put("department", "Internal Medicine"));
        patient.put("labResults", new JSONObject()
            .put("date", "2025-01-25")
            .put("hba1c", 6.8)
            .put("glucose", 142)
            .put("cholesterol", new JSONObject()
                .put("total", 195)
                .put("ldl", 118)
                .put("hdl", 52)
                .put("triglycerides", 125)));
        patient.put("imaging", new JSONArray()
            .put(new JSONObject()
                .put("type", "Chest X-Ray")
                .put("date", "2024-12-15")
                .put("result", "Normal cardiac silhouette, clear lungs")));
        
        return patient;
    }
    
    // Inner classes for Reed-Solomon and Shamir's Secret Sharing
    
    /**
     * REAL Reed-Solomon Implementation (embedded)
     */
    private static class RealReedSolomon {
        private final int dataShards;
        private final int parityShards;
        private final int totalShards;
        
        // Galois Field GF(2^8) constants
        private static final int FIELD_SIZE = 256;
        private static final int PRIMITIVE_POLYNOMIAL = 0x11d;
        
        // Pre-computed tables for GF arithmetic
        private static final int[] LOG_TABLE = new int[FIELD_SIZE];
        private static final int[] EXP_TABLE = new int[FIELD_SIZE * 2];
        
        // Vandermonde encoding matrix
        private final int[][] encodeMatrix;
        
        static {
            // Initialize Galois Field tables
            int x = 1;
            for (int i = 0; i < FIELD_SIZE - 1; i++) {
                EXP_TABLE[i] = x;
                EXP_TABLE[i + FIELD_SIZE - 1] = x;
                LOG_TABLE[x] = i;
                x = gfMultiplyNoTable(x, 2);
            }
            LOG_TABLE[0] = -1;
        }
        
        public RealReedSolomon(int dataShards, int parityShards) {
            this.dataShards = dataShards;
            this.parityShards = parityShards;
            this.totalShards = dataShards + parityShards;
            this.encodeMatrix = buildVandermondeMatrix();
        }
        
        private int[][] buildVandermondeMatrix() {
            int[][] matrix = new int[totalShards][dataShards];
            for (int row = 0; row < totalShards; row++) {
                for (int col = 0; col < dataShards; col++) {
                    matrix[row][col] = gfPower(row, col);
                }
            }
            return matrix;
        }
        
        public List<byte[]> encode(byte[] data) {
            int shardLength = (data.length + dataShards - 1) / dataShards;
            List<byte[]> shards = new ArrayList<>();
            
            // Initialize shards
            for (int i = 0; i < totalShards; i++) {
                shards.add(new byte[shardLength]);
            }
            
            // Distribute data across data shards
            for (int i = 0; i < data.length; i++) {
                int shardIndex = i % dataShards;
                int byteIndex = i / dataShards;
                shards.get(shardIndex)[byteIndex] = data[i];
            }
            
            // Calculate parity shards using matrix multiplication
            for (int parityIndex = 0; parityIndex < parityShards; parityIndex++) {
                int shardIndex = dataShards + parityIndex;
                for (int byteIndex = 0; byteIndex < shardLength; byteIndex++) {
                    int parityByte = 0;
                    for (int dataIndex = 0; dataIndex < dataShards; dataIndex++) {
                        int matrixElement = encodeMatrix[shardIndex][dataIndex];
                        int dataByte = shards.get(dataIndex)[byteIndex] & 0xFF;
                        parityByte ^= gfMultiply(matrixElement, dataByte);
                    }
                    shards.get(shardIndex)[byteIndex] = (byte) parityByte;
                }
            }
            
            return shards;
        }
        
        public byte[] decode(List<byte[]> shards, boolean[] shardPresent) {
            List<Integer> availableShards = new ArrayList<>();
            int shardLength = 0;
            
            for (int i = 0; i < totalShards; i++) {
                if (shardPresent[i] && shards.get(i) != null) {
                    availableShards.add(i);
                    if (shardLength == 0) {
                        shardLength = shards.get(i).length;
                    }
                }
            }
            
            if (availableShards.size() < dataShards) {
                throw new IllegalArgumentException("Insufficient shards for recovery");
            }
            
            // Check if we need error correction
            boolean needsRecovery = false;
            for (int i = 0; i < dataShards; i++) {
                if (!shardPresent[i]) {
                    needsRecovery = true;
                    break;
                }
            }
            
            if (needsRecovery) {
                performErrorCorrection(shards, shardPresent, availableShards, shardLength);
            }
            
            return reconstructData(shards, shardLength);
        }
        
        private void performErrorCorrection(List<byte[]> shards, boolean[] shardPresent, 
                                          List<Integer> availableShards, int shardLength) {
            // Build decoding matrix
            int[][] decodeMatrix = new int[dataShards][dataShards];
            List<Integer> useShards = availableShards.subList(0, dataShards);
            
            for (int i = 0; i < dataShards; i++) {
                int shardIndex = useShards.get(i);
                for (int j = 0; j < dataShards; j++) {
                    decodeMatrix[i][j] = encodeMatrix[shardIndex][j];
                }
            }
            
            // Invert matrix and recover missing shards
            int[][] inverseMatrix = invertMatrix(decodeMatrix);
            
            for (int missingIndex = 0; missingIndex < dataShards; missingIndex++) {
                if (!shardPresent[missingIndex]) {
                    shards.set(missingIndex, new byte[shardLength]);
                    
                    for (int byteIndex = 0; byteIndex < shardLength; byteIndex++) {
                        int recoveredByte = 0;
                        for (int i = 0; i < dataShards; i++) {
                            int shardIndex = useShards.get(i);
                            int coefficient = inverseMatrix[missingIndex][i];
                            int shardByte = shards.get(shardIndex)[byteIndex] & 0xFF;
                            recoveredByte ^= gfMultiply(coefficient, shardByte);
                        }
                        shards.get(missingIndex)[byteIndex] = (byte) recoveredByte;
                    }
                    shardPresent[missingIndex] = true;
                }
            }
        }
        
        private int[][] invertMatrix(int[][] matrix) {
            int size = matrix.length;
            int[][] augmented = new int[size][size * 2];
            
            // Create augmented matrix [A|I]
            for (int i = 0; i < size; i++) {
                for (int j = 0; j < size; j++) {
                    augmented[i][j] = matrix[i][j];
                    augmented[i][j + size] = (i == j) ? 1 : 0;
                }
            }
            
            // Gaussian elimination
            for (int i = 0; i < size; i++) {
                // Find pivot
                int pivot = i;
                for (int j = i + 1; j < size; j++) {
                    if (augmented[j][i] != 0) {
                        pivot = j;
                        break;
                    }
                }
                
                if (augmented[pivot][i] == 0) {
                    throw new RuntimeException("Matrix not invertible");
                }
                
                // Swap rows if needed
                if (pivot != i) {
                    int[] temp = augmented[i];
                    augmented[i] = augmented[pivot];
                    augmented[pivot] = temp;
                }
                
                // Scale pivot row
                int pivotElement = augmented[i][i];
                int pivotInverse = gfInverse(pivotElement);
                
                for (int j = 0; j < size * 2; j++) {
                    augmented[i][j] = gfMultiply(augmented[i][j], pivotInverse);
                }
                
                // Eliminate column
                for (int j = 0; j < size; j++) {
                    if (i != j && augmented[j][i] != 0) {
                        int factor = augmented[j][i];
                        for (int k = 0; k < size * 2; k++) {
                            augmented[j][k] ^= gfMultiply(factor, augmented[i][k]);
                        }
                    }
                }
            }
            
            // Extract inverse matrix
            int[][] inverse = new int[size][size];
            for (int i = 0; i < size; i++) {
                for (int j = 0; j < size; j++) {
                    inverse[i][j] = augmented[i][j + size];
                }
            }
            
            return inverse;
        }
        
        private byte[] reconstructData(List<byte[]> shards, int shardLength) {
            List<Byte> result = new ArrayList<>();
            
            for (int byteIndex = 0; byteIndex < shardLength; byteIndex++) {
                for (int shardIndex = 0; shardIndex < dataShards; shardIndex++) {
                    result.add(shards.get(shardIndex)[byteIndex]);
                }
            }
            
            byte[] dataArray = new byte[result.size()];
            for (int i = 0; i < dataArray.length; i++) {
                dataArray[i] = result.get(i);
            }
            
            // Remove padding
            int actualLength = dataArray.length;
            while (actualLength > 0 && dataArray[actualLength - 1] == 0) {
                actualLength--;
            }
            
            return Arrays.copyOf(dataArray, actualLength);
        }
        
        // Galois Field arithmetic
        private static int gfMultiply(int a, int b) {
            if (a == 0 || b == 0) return 0;
            return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % (FIELD_SIZE - 1)];
        }
        
        private static int gfInverse(int a) {
            if (a == 0) throw new ArithmeticException("Cannot invert zero");
            return EXP_TABLE[FIELD_SIZE - 1 - LOG_TABLE[a]];
        }
        
        private static int gfPower(int base, int exponent) {
            if (exponent == 0) return 1;
            if (base == 0) return 0;
            return EXP_TABLE[(LOG_TABLE[base] * exponent) % (FIELD_SIZE - 1)];
        }
        
        private static int gfMultiplyNoTable(int a, int b) {
            int result = 0;
            while (b != 0) {
                if ((b & 1) != 0) {
                    result ^= a;
                }
                a <<= 1;
                if ((a & FIELD_SIZE) != 0) {
                    a ^= PRIMITIVE_POLYNOMIAL;
                }
                b >>= 1;
            }
            return result;
        }
    }
    
    /**
     * REAL Shamir's Secret Sharing Implementation (embedded)
     */
    private static class RealShamirSecretSharing {
        
        private static final BigInteger FIELD_PRIME = new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");
        
        private final int threshold;
        private final int numShares;
        private final SecureRandom random;
        
        public RealShamirSecretSharing(int threshold, int numShares) {
            this.threshold = threshold;
            this.numShares = numShares;
            this.random = new SecureRandom();
        }
        
        public List<Share> splitSecret(byte[] secret) {
            BigInteger secretInt = new BigInteger(1, secret);
            
            if (secretInt.compareTo(FIELD_PRIME) >= 0) {
                throw new IllegalArgumentException("Secret too large for field");
            }
            
            // Generate polynomial coefficients
            List<BigInteger> coefficients = new ArrayList<>();
            coefficients.add(secretInt); // a0 = secret
            
            for (int i = 1; i < threshold; i++) {
                BigInteger coeff;
                do {
                    coeff = new BigInteger(FIELD_PRIME.bitLength(), random);
                } while (coeff.compareTo(FIELD_PRIME) >= 0);
                coefficients.add(coeff);
            }
            
            // Create shares
            List<Share> shares = new ArrayList<>();
            for (int x = 1; x <= numShares; x++) {
                BigInteger y = evaluatePolynomial(coefficients, BigInteger.valueOf(x));
                shares.add(new Share(x, y));
            }
            
            return shares;
        }
        
        public byte[] reconstructSecret(List<Share> shares) {
            if (shares.size() < threshold) {
                throw new IllegalArgumentException("Insufficient shares");
            }
            
            List<Share> selectedShares = shares.subList(0, threshold);
            BigInteger secret = BigInteger.ZERO;
            
            for (int i = 0; i < selectedShares.size(); i++) {
                Share currentShare = selectedShares.get(i);
                BigInteger lagrangeBasis = calculateLagrangeBasis(selectedShares, i, BigInteger.ZERO);
                BigInteger contribution = currentShare.y.multiply(lagrangeBasis).mod(FIELD_PRIME);
                secret = secret.add(contribution).mod(FIELD_PRIME);
            }
            
            byte[] secretBytes = secret.toByteArray();
            if (secretBytes[0] == 0 && secretBytes.length > 1) {
                secretBytes = Arrays.copyOfRange(secretBytes, 1, secretBytes.length);
            }
            
            return secretBytes;
        }
        
        private BigInteger evaluatePolynomial(List<BigInteger> coefficients, BigInteger x) {
            BigInteger result = BigInteger.ZERO;
            for (int i = coefficients.size() - 1; i >= 0; i--) {
                result = result.multiply(x).add(coefficients.get(i)).mod(FIELD_PRIME);
            }
            return result;
        }
        
        private BigInteger calculateLagrangeBasis(List<Share> shares, int i, BigInteger target) {
            Share currentShare = shares.get(i);
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;
            
            for (int j = 0; j < shares.size(); j++) {
                if (i != j) {
                    Share otherShare = shares.get(j);
                    numerator = numerator.multiply(target.subtract(BigInteger.valueOf(otherShare.x))).mod(FIELD_PRIME);
                    denominator = denominator.multiply(BigInteger.valueOf(currentShare.x - otherShare.x)).mod(FIELD_PRIME);
                }
            }
            
            return numerator.multiply(denominator.modInverse(FIELD_PRIME)).mod(FIELD_PRIME);
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
}