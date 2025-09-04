import java.util.*;
import org.json.JSONObject;

/**
 * Reed-Solomon Demo - Extracted from SimplifiedRaSeSystem
 * Shows how the Reed-Solomon encoding/decoding works
 */
public class ReedSolomonDemo {
    
    /**
     * Extracted SimpleReedSolomon from SimplifiedRaSeSystem
     */
    public static class SimpleReedSolomon {
        private final int dataShards;
        private final int parityShards;
        private final int totalShards;
        
        // Galois Field GF(256) constants
        private static final int[] LOG_TABLE = new int[256];
        private static final int[] EXP_TABLE = new int[512];
        
        // Vandermonde encoding matrix
        private final int[][] encodeMatrix;
        
        static {
            // Initialize GF(256) tables
            int x = 1;
            for (int i = 0; i < 255; i++) {
                EXP_TABLE[i] = x;
                EXP_TABLE[i + 255] = x;
                LOG_TABLE[x] = i;
                x = (x << 1) ^ (x >= 128 ? 0x11d : 0);
            }
            LOG_TABLE[0] = -1;
        }
        
        public SimpleReedSolomon(int dataShards, int parityShards) {
            this.dataShards = dataShards;
            this.parityShards = parityShards;
            this.totalShards = dataShards + parityShards;
            this.encodeMatrix = buildMatrix();
        }
        
        private int[][] buildMatrix() {
            int[][] matrix = new int[totalShards][dataShards];
            for (int row = 0; row < totalShards; row++) {
                for (int col = 0; col < dataShards; col++) {
                    matrix[row][col] = gfPower(row, col);
                }
            }
            return matrix;
        }
        
        public List<byte[]> encode(byte[] data) {
            // Simple approach: pad data to be divisible by dataShards
            int shardSize = (data.length + dataShards - 1) / dataShards;
            int totalSize = shardSize * dataShards;
            
            // Create padded data with length prefix
            byte[] paddedData = new byte[totalSize + 4];
            paddedData[0] = (byte) (data.length >>> 24);
            paddedData[1] = (byte) (data.length >>> 16);
            paddedData[2] = (byte) (data.length >>> 8);
            paddedData[3] = (byte) data.length;
            System.arraycopy(data, 0, paddedData, 4, data.length);
            
            shardSize = paddedData.length / dataShards;
            
            List<byte[]> shards = new ArrayList<>();
            
            // Create data shards
            for (int i = 0; i < dataShards; i++) {
                byte[] shard = new byte[shardSize];
                System.arraycopy(paddedData, i * shardSize, shard, 0, shardSize);
                shards.add(shard);
            }
            
            // Create parity shards
            for (int p = 0; p < parityShards; p++) {
                byte[] parityShard = new byte[shardSize];
                int parityRow = dataShards + p;
                
                for (int pos = 0; pos < shardSize; pos++) {
                    int parity = 0;
                    for (int d = 0; d < dataShards; d++) {
                        parity ^= gfMultiply(encodeMatrix[parityRow][d], shards.get(d)[pos] & 0xFF);
                    }
                    parityShard[pos] = (byte) parity;
                }
                shards.add(parityShard);
            }
            
            return shards;
        }
        
        /**
         * Decode shards back to data - EXACT from RaSe system
         */
        public byte[] decode(List<byte[]> shards, boolean[] shardPresent) {
            int availableCount = 0;
            for (boolean present : shardPresent) {
                if (present) availableCount++;
            }
            
            if (availableCount < dataShards) {
                throw new RuntimeException("Need at least " + dataShards + " shards, have " + availableCount);
            }
            
            // Check if we have all data shards
            boolean hasAllDataShards = true;
            for (int i = 0; i < dataShards; i++) {
                if (!shardPresent[i]) {
                    hasAllDataShards = false;
                    break;
                }
            }
            
            // If missing data shards, reconstruct them
            if (!hasAllDataShards) {
                reconstructMissingShards(shards, shardPresent);
            }
            
            // Reconstruct original data from data shards
            int shardSize = shards.get(0).length;
            byte[] paddedData = new byte[shardSize * dataShards];
            
            for (int i = 0; i < dataShards; i++) {
                System.arraycopy(shards.get(i), 0, paddedData, i * shardSize, shardSize);
            }
            
            // Extract original length and data
            int originalLength = ((paddedData[0] & 0xFF) << 24) |
                               ((paddedData[1] & 0xFF) << 16) |
                               ((paddedData[2] & 0xFF) << 8) |
                               (paddedData[3] & 0xFF);
            
            // Debug: print the length bytes
            System.out.println("Length bytes: " + (paddedData[0] & 0xFF) + " " + 
                             (paddedData[1] & 0xFF) + " " + 
                             (paddedData[2] & 0xFF) + " " + 
                             (paddedData[3] & 0xFF) + 
                             " -> Length: " + originalLength);
            
            if (originalLength < 0 || originalLength > paddedData.length - 4) {
                throw new RuntimeException("Invalid data length: " + originalLength);
            }
            
            byte[] result = new byte[originalLength];
            System.arraycopy(paddedData, 4, result, 0, originalLength);
            return result;
        }
        
        private void reconstructMissingShards(List<byte[]> shards, boolean[] shardPresent) {
            // Find available shards for reconstruction
            List<Integer> availableIndices = new ArrayList<>();
            for (int i = 0; i < totalShards; i++) {
                if (shardPresent[i]) {
                    availableIndices.add(i);
                }
            }
            
            // Use first dataShards available shards
            List<Integer> useIndices = availableIndices.subList(0, dataShards);
            
            // Build decode matrix
            int[][] decodeMatrix = new int[dataShards][dataShards];
            for (int i = 0; i < dataShards; i++) {
                for (int j = 0; j < dataShards; j++) {
                    decodeMatrix[i][j] = encodeMatrix[useIndices.get(i)][j];
                }
            }
            
            // Invert matrix
            int[][] inverse = invertMatrix(decodeMatrix);
            
            // Reconstruct missing data shards
            int shardSize = shards.get(useIndices.get(0)).length;
            for (int missing = 0; missing < dataShards; missing++) {
                if (!shardPresent[missing]) {
                    byte[] newShard = new byte[shardSize];
                    
                    for (int pos = 0; pos < shardSize; pos++) {
                        int value = 0;
                        for (int i = 0; i < dataShards; i++) {
                            int coeff = inverse[missing][i];
                            int shardByte = shards.get(useIndices.get(i))[pos] & 0xFF;
                            value ^= gfMultiply(coeff, shardByte);
                        }
                        newShard[pos] = (byte) value;
                    }
                    
                    shards.set(missing, newShard);
                    shardPresent[missing] = true;
                }
            }
        }
        
        private int[][] invertMatrix(int[][] matrix) {
            int size = matrix.length;
            int[][] aug = new int[size][size * 2];
            
            // Create [A|I]
            for (int i = 0; i < size; i++) {
                for (int j = 0; j < size; j++) {
                    aug[i][j] = matrix[i][j];
                    aug[i][j + size] = (i == j) ? 1 : 0;
                }
            }
            
            // Gaussian elimination
            for (int i = 0; i < size; i++) {
                // Find pivot
                int pivot = -1;
                for (int j = i; j < size; j++) {
                    if (aug[j][i] != 0) {
                        pivot = j;
                        break;
                    }
                }
                
                if (pivot == -1) throw new RuntimeException("Matrix not invertible");
                
                // Swap rows
                if (pivot != i) {
                    int[] temp = aug[i];
                    aug[i] = aug[pivot];
                    aug[pivot] = temp;
                }
                
                // Scale row
                int inv = gfInverse(aug[i][i]);
                for (int j = 0; j < size * 2; j++) {
                    aug[i][j] = gfMultiply(aug[i][j], inv);
                }
                
                // Eliminate
                for (int j = 0; j < size; j++) {
                    if (i != j && aug[j][i] != 0) {
                        int factor = aug[j][i];
                        for (int k = 0; k < size * 2; k++) {
                            aug[j][k] ^= gfMultiply(factor, aug[i][k]);
                        }
                    }
                }
            }
            
            // Extract inverse
            int[][] result = new int[size][size];
            for (int i = 0; i < size; i++) {
                for (int j = 0; j < size; j++) {
                    result[i][j] = aug[i][j + size];
                }
            }
            return result;
        }
        
        // GF(256) arithmetic
        private static int gfMultiply(int a, int b) {
            if (a == 0 || b == 0) return 0;
            return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % 255];
        }
        
        private static int gfInverse(int a) {
            if (a == 0) throw new ArithmeticException("Cannot invert zero");
            return EXP_TABLE[255 - LOG_TABLE[a]];
        }
        
        private static int gfPower(int base, int exp) {
            if (exp == 0) return 1;
            if (base == 0) return 0;
            return EXP_TABLE[(LOG_TABLE[base] * exp) % 255];
        }
    }
    
    // Demo showing Reed-Solomon capabilities
    public static void main(String[] args) {
        System.out.println("=== Reed-Solomon Demo (From SimplifiedRaSeSystem) ===\n");
        
        // Use same configuration as RaSe system
        SimpleReedSolomon rs = new SimpleReedSolomon(3, 2);
        
        // Create simple test data instead of JSON
        String originalData = "This is a simple test for Reed-Solomon encoding and decoding verification.";
        System.out.println("Original medical data (" + originalData.length() + " bytes):");
        System.out.println(originalData.substring(0, Math.min(150, originalData.length())) + "...\n");
        
        try {
            // Step 1: Encode into shards
            System.out.println("=== ENCODING ===");
            List<byte[]> shards = rs.encode(originalData.getBytes());
            System.out.println("Created " + shards.size() + " shards (3 data + 2 parity)");
            for (int i = 0; i < shards.size(); i++) {
                System.out.println("  Shard " + i + ": " + shards.get(i).length + " bytes");
            }
            
            // Step 2: Test normal recovery (all shards available)
            System.out.println("\n=== NORMAL RECOVERY ===");
            boolean[] allAvailable = new boolean[5];
            Arrays.fill(allAvailable, true);
            
            byte[] recovered = rs.decode(new ArrayList<>(shards), allAvailable);
            String recoveredData = new String(recovered);
            boolean normalSuccess = originalData.equals(recoveredData);
            System.out.println("Normal recovery: " + (normalSuccess ? "SUCCESS" : "FAILED"));
            
            // Step 3: Simulate data corruption (lose 1 data shard)
            System.out.println("\n=== CORRUPTION TEST 1: Lose 1 Data Shard ===");
            boolean[] oneCorrupted = new boolean[5];
            Arrays.fill(oneCorrupted, true);
            oneCorrupted[1] = false; // Lose data shard 1
            System.out.println("Lost data shard 1");
            
            // Make deep copy of shards
            List<byte[]> shardsCopy1 = new ArrayList<>();
            for (byte[] shard : shards) {
                shardsCopy1.add(shard.clone());
            }
            
            byte[] recovered1 = rs.decode(shardsCopy1, oneCorrupted);
            boolean recovery1Success = originalData.equals(new String(recovered1));
            System.out.println("Recovery from 1 lost shard: " + (recovery1Success ? "SUCCESS" : "FAILED"));
            
            // Step 4: Simulate worse corruption (lose 2 shards - maximum recoverable)
            System.out.println("\n=== CORRUPTION TEST 2: Lose 2 Shards (Maximum) ===");
            boolean[] twoCorrupted = new boolean[5];
            Arrays.fill(twoCorrupted, true);
            twoCorrupted[0] = false; // Lose data shard 0
            twoCorrupted[4] = false; // Lose parity shard 1
            System.out.println("Lost data shard 0 and parity shard 4");
            
            // Make deep copy of shards
            List<byte[]> shardsCopy2 = new ArrayList<>();
            for (byte[] shard : shards) {
                shardsCopy2.add(shard.clone());
            }
            
            byte[] recovered2 = rs.decode(shardsCopy2, twoCorrupted);
            boolean recovery2Success = originalData.equals(new String(recovered2));
            System.out.println("Recovery from 2 lost shards: " + (recovery2Success ? "SUCCESS" : "FAILED"));
            
            // Step 5: Test beyond recovery capability
            System.out.println("\n=== CORRUPTION TEST 3: Beyond Recovery (3+ shards lost) ===");
            boolean[] beyondRecovery = new boolean[5];
            Arrays.fill(beyondRecovery, true);
            beyondRecovery[0] = false; // Lose data shard 0
            beyondRecovery[1] = false; // Lose data shard 1
            beyondRecovery[2] = false; // Lose data shard 2
            System.out.println("Lost 3 data shards (beyond recovery capability)");
            
            // Make deep copy of shards
            List<byte[]> shardsCopy3 = new ArrayList<>();
            for (byte[] shard : shards) {
                shardsCopy3.add(shard.clone());
            }
            
            try {
                rs.decode(shardsCopy3, beyondRecovery);
                System.out.println("Should have failed but didn't!");
            } catch (RuntimeException e) {
                System.out.println("Expected failure: " + e.getMessage());
            }
            
            // Summary
            System.out.println("\n=== SUMMARY ===");
            System.out.println("Reed-Solomon (3+2 configuration) can:");
            System.out.println("  - Lose up to 2 out of 5 total shards");
            System.out.println("  - Recover any combination of lost shards");
            System.out.println("  - Perfect data recovery when within limits");
            System.out.println("  - Fails gracefully when beyond recovery capability");
            
            if (normalSuccess && recovery1Success && recovery2Success) {
                System.out.println("\nAll recovery tests PASSED - Reed-Solomon working correctly!");
            }
            
        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}