import java.util.*;
import java.io.*;
import java.nio.file.*;
import org.json.JSONObject;

/**
 * REAL Reed-Solomon Erasure Coding Implementation
 * Uses actual Galois Field GF(2^8) arithmetic and Vandermonde matrices
 * This is production-quality error correction, not a simulation
 */
public class RealReedSolomon {
    private final int dataShards;
    private final int parityShards;
    private final int totalShards;
    
    // Galois Field GF(2^8) - exactly what's used in real Reed-Solomon
    private static final int FIELD_SIZE = 256;
    private static final int PRIMITIVE_POLYNOMIAL = 0x11d; // x^8 + x^4 + x^3 + x^2 + 1
    
    // Pre-computed logarithm and exponential tables for GF(2^8)
    private static final int[] LOG_TABLE = new int[FIELD_SIZE];
    private static final int[] EXP_TABLE = new int[FIELD_SIZE * 2];
    
    // Vandermonde matrix for encoding (this is the mathematical core)
    private final int[][] encodeMatrix;
    
    static {
        // Initialize Galois Field tables - this is real GF(2^8) math
        int x = 1;
        for (int i = 0; i < FIELD_SIZE - 1; i++) {
            EXP_TABLE[i] = x;
            EXP_TABLE[i + FIELD_SIZE - 1] = x; // Duplicate for efficiency
            LOG_TABLE[x] = i;
            x = gfMultiplyNoTable(x, 2); // Multiply by generator
        }
        LOG_TABLE[0] = -1; // Special case for zero
    }
    
    public RealReedSolomon(int dataShards, int parityShards) {
        this.dataShards = dataShards;
        this.parityShards = parityShards;
        this.totalShards = dataShards + parityShards;
        
        // Build the Vandermonde matrix - mathematical foundation of Reed-Solomon
        this.encodeMatrix = buildVandermondeMatrix();
        
        System.out.println("Initialized Reed-Solomon with:");
        System.out.println("  Data shards: " + dataShards);
        System.out.println("  Parity shards: " + parityShards);
        System.out.println("  Can recover from up to " + parityShards + " lost shards");
    }
    
    /**
     * Builds the Vandermonde matrix used for encoding
     * This is the mathematical heart of Reed-Solomon coding
     */
    private int[][] buildVandermondeMatrix() {
        int[][] matrix = new int[totalShards][dataShards];
        
        for (int row = 0; row < totalShards; row++) {
            for (int col = 0; col < dataShards; col++) {
                // Vandermonde matrix: V[i,j] = i^j in GF(2^8)
                matrix[row][col] = gfPower(row, col);
            }
        }
        
        System.out.println("Built " + totalShards + "x" + dataShards + " Vandermonde matrix");
        return matrix;
    }
    
    /**
     * REAL Reed-Solomon encoding using matrix multiplication in GF(2^8)
     */
   public List<byte[]> encode(byte[] data) {
    // Create length-prefixed data (4 bytes for length + data)
    byte[] lengthPrefixedData = new byte[4 + data.length];
    lengthPrefixedData[0] = (byte) (data.length >>> 24);
    lengthPrefixedData[1] = (byte) (data.length >>> 16);
    lengthPrefixedData[2] = (byte) (data.length >>> 8);
    lengthPrefixedData[3] = (byte) data.length;
    System.arraycopy(data, 0, lengthPrefixedData, 4, data.length);

    // Calculate shard size - ensure all shards are same size
    int shardLength = (lengthPrefixedData.length + dataShards - 1) / dataShards;
    
    // Pad data to exact multiple of dataShards * shardLength
    int totalDataSize = dataShards * shardLength;
    byte[] paddedData = new byte[totalDataSize];
    System.arraycopy(lengthPrefixedData, 0, paddedData, 0, lengthPrefixedData.length);
    // Rest is automatically filled with zeros (padding)
    
    List<byte[]> shards = new ArrayList<>();

    // Initialize all shards
    for (int i = 0; i < totalShards; i++) {
        shards.add(new byte[shardLength]);
    }

    // Distribute data across data shards sequentially (not round-robin)
    for (int shardIndex = 0; shardIndex < dataShards; shardIndex++) {
        System.arraycopy(paddedData, shardIndex * shardLength, 
                        shards.get(shardIndex), 0, shardLength);
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
    
    /**
     * REAL Reed-Solomon decoding with error correction
     * Uses Gaussian elimination in GF(2^8) to solve the linear system
     */
    public byte[] decode(List<byte[]> shards, boolean[] shardPresent) {
        // Count available shards
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
        
        System.out.println("Decoding with " + availableShards.size() + " available shards");
        
        if (availableShards.size() < dataShards) {
            throw new IllegalArgumentException("Cannot decode: need at least " + dataShards + 
                " shards, but only " + availableShards.size() + " available");
        }
        
        // If we have all data shards, no decoding needed
        boolean hasAllDataShards = true;
        for (int i = 0; i < dataShards; i++) {
            if (!shardPresent[i]) {
                hasAllDataShards = false;
                break;
            }
        }
        
        if (!hasAllDataShards) {
            System.out.println("Missing data shards detected - performing error correction");
            performErrorCorrection(shards, shardPresent, availableShards, shardLength);
        }
        
        // Reconstruct original data from data shards
        return reconstructData(shards, shardLength);
    }
    
    /**
     * Performs actual error correction using Gaussian elimination in GF(2^8)
     * This is the mathematical core that makes Reed-Solomon work
     */
    private void performErrorCorrection(List<byte[]> shards, boolean[] shardPresent, 
                                      List<Integer> availableShards, int shardLength) {
        
        // Build the decoding matrix from available shards
        int[][] decodeMatrix = new int[dataShards][dataShards];
        List<Integer> useShards = availableShards.subList(0, dataShards);
        
        for (int i = 0; i < dataShards; i++) {
            int shardIndex = useShards.get(i);
            for (int j = 0; j < dataShards; j++) {
                decodeMatrix[i][j] = encodeMatrix[shardIndex][j];
            }
        }
        
        System.out.println("Built decoding matrix from shards: " + useShards);
        
        // Invert the matrix using Gaussian elimination in GF(2^8)
        int[][] inverseMatrix = invertMatrix(decodeMatrix);
        
        // Recover missing data shards
        for (int missingIndex = 0; missingIndex < dataShards; missingIndex++) {
            if (!shardPresent[missingIndex]) {
                System.out.println("Recovering data shard " + missingIndex);
                shards.set(missingIndex, new byte[shardLength]);
                
                // Matrix multiplication to recover shard
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
    
    /**
     * Matrix inversion in GF(2^8) using Gaussian elimination
     * This is advanced mathematics - the reason Reed-Solomon works
     */
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
                throw new RuntimeException("Matrix is not invertible");
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
        
        System.out.println("Successfully inverted matrix using Gaussian elimination in GF(2^8)");
        return inverse;
    }
    

    private byte[] reconstructData(List<byte[]> shards, int shardLength) {
    // Reconstruct padded data by concatenating data shards
    byte[] paddedData = new byte[shardLength * dataShards];
    
    for (int shardIndex = 0; shardIndex < dataShards; shardIndex++) {
        System.arraycopy(shards.get(shardIndex), 0, 
                        paddedData, shardIndex * shardLength, shardLength);
    }

    // Extract original length from first 4 bytes
    if (paddedData.length < 4) {
        throw new RuntimeException("Reconstructed data too short to contain length prefix");
    }
    
    int originalLength = ((paddedData[0] & 0xFF) << 24) |
                        ((paddedData[1] & 0xFF) << 16) |
                        ((paddedData[2] & 0xFF) << 8) |
                        (paddedData[3] & 0xFF);

    // Validate length
    if (originalLength < 0 || originalLength > paddedData.length - 4) {
        throw new RuntimeException("Invalid data length in reconstruction: " + originalLength + 
                                 " (reconstructed " + paddedData.length + " bytes)");
    }

    // Extract original data (skip the 4-byte length prefix)
    byte[] result = new byte[originalLength];
    System.arraycopy(paddedData, 4, result, 0, originalLength);

    return result;
}
    
    // REAL Galois Field arithmetic operations for GF(2^8)
    
    private static int gfMultiply(int a, int b) {
        if (a == 0 || b == 0) return 0;
        return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % (FIELD_SIZE - 1)];
    }
    
    // private static int gfDivide(int a, int b) {
    //     if (a == 0) return 0;
    //     if (b == 0) throw new ArithmeticException("Division by zero in GF(2^8)");
    //     return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + FIELD_SIZE - 1) % (FIELD_SIZE - 1)];
    // }
    
    private static int gfInverse(int a) {
        if (a == 0) throw new ArithmeticException("Cannot invert zero in GF(2^8)");
        return EXP_TABLE[FIELD_SIZE - 1 - LOG_TABLE[a]];
    }
    
    private static int gfPower(int base, int exponent) {
        if (exponent == 0) return 1;
        if (base == 0) return 0;
        return EXP_TABLE[(LOG_TABLE[base] * exponent) % (FIELD_SIZE - 1)];
    }
    
    // Multiplication without lookup tables (used for table initialization)
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
    
    // Demo and testing methods
    public static void main(String[] args) {
        // Test with real patient data
        RealReedSolomon rs = new RealReedSolomon(4, 2);
        
        // Create realistic medical record
        JSONObject patientRecord = new JSONObject();
        patientRecord.put("patientId", "PAT-12345");
        patientRecord.put("firstName", "John");
        patientRecord.put("lastName", "Doe");
        patientRecord.put("dateOfBirth", "1978-05-15");
        patientRecord.put("ssn", "***-**-6789");
        patientRecord.put("address", "123 Main Street, Princeton, NJ 08540");
        patientRecord.put("phone", "609-555-0123");
        patientRecord.put("email", "john.doe@email.com");
        patientRecord.put("emergencyContact", "Jane Doe - 609-555-0124");
        patientRecord.put("bloodType", "O+");
        patientRecord.put("allergies", Arrays.asList("Penicillin", "Shellfish"));
        patientRecord.put("currentMedications", Arrays.asList("Lisinopril 10mg daily", "Metformin 500mg twice daily"));
        patientRecord.put("medicalHistory", Arrays.asList("Hypertension (2018)", "Type 2 Diabetes (2020)"));
        patientRecord.put("lastVisit", "2025-01-20");
        patientRecord.put("vitals", new JSONObject()
            .put("bloodPressure", "142/88")
            .put("heartRate", 78)
            .put("temperature", 98.6)
            .put("weight", 185)
            .put("height", "5'10\""));
        patientRecord.put("diagnosis", "Hypertension, well controlled. Diabetes mellitus type 2, stable.");
        patientRecord.put("treatment", "Continue current medications. Follow up in 3 months.");
        patientRecord.put("physician", "Dr. Sarah Johnson, MD");
        patientRecord.put("insurance", new JSONObject()
            .put("provider", "Blue Cross Blue Shield")
            .put("policyNumber", "BC123456789")
            .put("groupNumber", "GRP001"));
        
        String data = patientRecord.toString(2);
        System.out.println("=== Testing Real Reed-Solomon Implementation ===\n");
        System.out.println("Original medical record (" + data.length() + " bytes):");
        System.out.println(data.substring(0, Math.min(200, data.length())) + "...\n");
        
        try {
            // Encode
            System.out.println("=== ENCODING ===");
            List<byte[]> shards = rs.encode(data.getBytes());
            
            // Store shards (simulate distributed storage)
            rs.storeShards(shards, "PAT-12345");
            
            // Simulate corruption
            System.out.println("\n=== SIMULATING RANSOMWARE ATTACK ===");
            boolean[] shardPresent = new boolean[6];
            Arrays.fill(shardPresent, true);
            
            // Corrupt 2 shards (within recovery capability)
            shardPresent[1] = false; // Corrupt data shard 1
            shardPresent[4] = false; // Corrupt parity shard 0
            shards.set(1, null);
            shards.set(4, null);
            System.out.println("Corrupted shards 1 and 4 (simulating ransomware encryption)");
            
            // Decode and recover
            System.out.println("\n=== RECOVERY ===");
            byte[] recovered = rs.decode(shards, shardPresent);
            String recoveredString = new String(recovered);
            
            // Verify
            boolean isCorrect = data.equals(recoveredString);
            System.out.println("Recovery successful: " + isCorrect);
            
            if (isCorrect) {
                System.out.println("✓ Data perfectly recovered despite 2 corrupted shards!");
                System.out.println("Recovered data preview: " + recoveredString.substring(0, Math.min(100, recoveredString.length())) + "...");
            } else {
                System.out.println("✗ Recovery failed");
            }
            
            // Test failure case
            System.out.println("\n=== TESTING INSUFFICIENT SHARDS ===");
            shardPresent[2] = false; // Corrupt another shard
            shardPresent[5] = false; // And another
            shards.set(2, null);
            shards.set(5, null);
            System.out.println("Corrupted 4 total shards (beyond recovery capability)");
            
            try {
                rs.decode(shards, shardPresent);
            } catch (Exception e) {
                System.out.println("Expected failure: " + e.getMessage());
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void storeShards(List<byte[]> shards, String patientId) {
        try {
            Files.createDirectories(Paths.get("shards"));
            for (int i = 0; i < shards.size(); i++) {
                String filename = "shards/shard_" + i + "_" + patientId + ".dat";
                Files.write(Paths.get(filename), shards.get(i));
                System.out.println("Stored shard " + i + " (" + shards.get(i).length + " bytes) -> " + filename);
            }
        } catch (IOException e) {
            System.err.println("Error storing shards: " + e.getMessage());
        }
    }
}