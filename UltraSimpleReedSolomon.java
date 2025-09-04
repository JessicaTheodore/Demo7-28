/**
 * Ultra-Simplified Reed-Solomon for RaSe System
 * Real Galois Field arithmetic but much simpler reconstruction logic
 * Designed for proof-of-concept and debugging
 */
import java.util.*;

public class UltraSimpleReedSolomon {
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
    
    public UltraSimpleReedSolomon(int dataShards, int parityShards) {
        this.dataShards = dataShards;
        this.parityShards = parityShards;
        this.totalShards = dataShards + parityShards;
        
        System.out.println("Ultra-Simple RS initialized: " + dataShards + "+" + parityShards);
    }
    
    /**
     * ULTRA-SIMPLE ENCODING
     * Just XOR-based parity for simplicity while keeping GF arithmetic
     */
    public List<byte[]> encode(byte[] data) {
        System.out.println("Encoding " + data.length + " bytes");
        
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
            System.out.println("  Data shard " + i + ": " + shardSize + " bytes");
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
            System.out.println("  Parity shard " + (dataShards + p) + ": " + shardSize + " bytes");
        }
        
        return shards;
    }
    
    /**
     * ULTRA-SIMPLE DECODING
     * If we have all data shards, just reconstruct directly
     * If missing data shards, use simple GF solve
     */
    public byte[] decode(List<byte[]> shards, boolean[] shardPresent) {
        System.out.println("Decoding with shard availability: " + Arrays.toString(shardPresent));
        
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
                System.out.println("Missing data shard: " + i);
                break;
            }
        }
        
        if (allDataShardsPresent) {
            System.out.println("All data shards present - direct reconstruction");
            return reconstructDirectly(shards);
        } else {
            System.out.println("Missing data shards - attempting GF reconstruction");
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
     * ULTRA-SIMPLIFIED approach
     */
    private byte[] reconstructWithGF(List<byte[]> shards, boolean[] shardPresent) {
        int shardSize = shards.get(0).length;
        
        // Find which data shards are missing
        List<Integer> missingDataShards = new ArrayList<>();
        List<Integer> availableShards = new ArrayList<>();
        
        for (int i = 0; i < dataShards; i++) {
            if (!shardPresent[i]) {
                missingDataShards.add(i);
            }
        }
        
        for (int i = 0; i < totalShards; i++) {
            if (shardPresent[i]) {
                availableShards.add(i);
            }
        }
        
        System.out.println("Missing data shards: " + missingDataShards);
        System.out.println("Available shards: " + availableShards);
        
        // For each missing data shard, reconstruct using simple GF solve
        for (int missing : missingDataShards) {
            System.out.println("Reconstructing missing shard: " + missing);
            
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
            System.out.println("Using parity shard " + parityShardIndex + " (parity #" + parityNumber + ")");
            
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
                
                // The parity equation is:
                // parity = sum(data[i] * coeff[i]) for all i
                // So: data[missing] * coeff[missing] = parity ^ knownSum
                
                int parityByte = shards.get(parityShardIndex)[pos] & 0xFF;
                int targetValue = parityByte ^ knownSum;
                
                int missingCoeff = gfPower(missing + 1, parityNumber + 1);
                int missingDataByte = gfDivide(targetValue, missingCoeff);
                
                reconstructedShard[pos] = (byte) missingDataByte;
            }
            
            // Replace the missing shard
            shards.set(missing, reconstructedShard);
            shardPresent[missing] = true;
            
            System.out.println("Successfully reconstructed shard " + missing);
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
        
        System.out.println("Extracted length: " + originalLength + " (max: " + (paddedData.length - 4) + ")");
        
        if (originalLength < 0 || originalLength > paddedData.length - 4) {
            System.err.println("Invalid length detected: " + originalLength);
            System.err.println("Length bytes: " + 
                (paddedData[0] & 0xFF) + " " + 
                (paddedData[1] & 0xFF) + " " + 
                (paddedData[2] & 0xFF) + " " + 
                (paddedData[3] & 0xFF));
            throw new RuntimeException("Invalid data length: " + originalLength);
        }
        
        byte[] result = new byte[originalLength];
        System.arraycopy(paddedData, 4, result, 0, originalLength);
        
        System.out.println("Successfully extracted " + originalLength + " bytes of original data");
        return result;
    }
    
    // ===== GALOIS FIELD ARITHMETIC (PROVEN WORKING) =====
    
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
    
    // ===== TEST =====
    
    public static void main(String[] args) {
        System.out.println("=== Reed-Solomon Test ===");
        
        UltraSimpleReedSolomon rs = new UltraSimpleReedSolomon(3, 2);
        
        String testData = "Hello, this is a simple test for ultra-simple Reed-Solomon!";
        System.out.println("Original: " + testData);
        
        try {
            // Encode
            List<byte[]> shards = rs.encode(testData.getBytes());
            System.out.println("Encoded into " + shards.size() + " shards");
            
            // Test 1: All shards present
            System.out.println("\n--- Test 1: All shards present ---");
            boolean[] allPresent = new boolean[5];
            Arrays.fill(allPresent, true);
            
            byte[] recovered1 = rs.decode(new ArrayList<>(shards), allPresent);
            String result1 = new String(recovered1);
            System.out.println("Recovered: " + result1);
            System.out.println("Match: " + testData.equals(result1));
            
            // Test 2: One data shard missing
            System.out.println("\n--- Test 2: Missing data shard 1 ---");
            boolean[] oneMissing = new boolean[5];
            Arrays.fill(oneMissing, true);
            oneMissing[1] = false; // Missing data shard 1
            
            List<byte[]> shardsCopy = new ArrayList<>();
            for (byte[] shard : shards) {
                shardsCopy.add(shard.clone());
            }
            
            byte[] recovered2 = rs.decode(shardsCopy, oneMissing);
            String result2 = new String(recovered2);
            System.out.println("Recovered: " + result2);
            System.out.println("Match: " + testData.equals(result2));
            
        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}