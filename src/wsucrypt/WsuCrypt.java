package wsucrypt;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;


public class WsuCrypt {
	
	private String key;
	private String originalKey;
	private String mode;
	private final int blockSize = 64;
	private final int hexSize = 4;
	private ArrayList<String> blocks;
	public final static String keyFile = "src/wsucrypt/assets/key.txt";
	public final static String pTextFile = "src/wsucrypt/assets/plaintext.txt";
	public final static String cTextFile = "src/wsucrypt/assets/ciphertext.txt";
	private final static String ftable[][] = {
		{"a3", "d7", "09", "83", "f8", "48", "f6", "f4", "b3", "21", "15", "78", "99", "b1", "af", "f9"}, 
		{"e7", "2d", "4d", "8a", "ce", "4c", "ca", "2e", "52", "95", "d9", "1e", "4e", "38", "44", "28"}, 
		{"0a", "df", "02", "a0", "17", "f1", "60", "68", "12", "b7", "7a", "c3", "e9", "fa", "3d", "53"}, 
		{"96", "84", "6b", "ba", "f2", "63", "9a", "19", "7c", "ae", "e5", "f5", "f7", "16", "6a", "a2"}, 
		{"39", "b6", "7b", "0f", "c1", "93", "81", "1b", "ee", "b4", "1a", "ea", "d0", "91", "2f", "b8"}, 
		{"55", "b9", "da", "85", "3f", "41", "bf", "e0", "5a", "58", "80", "5f", "66", "0b", "d8", "90"}, 
		{"35", "d5", "c0", "a7", "33", "06", "65", "69", "45", "00", "94", "56", "6d", "98", "9b", "76"}, 
		{"97", "fc", "b2", "c2", "b0", "fe", "db", "20", "e1", "eb", "d6", "e4", "dd", "47", "4a", "1d"}, 
		{"42", "ed", "9e", "6e", "49", "3c", "cd", "43", "27", "d2", "07", "d4", "de", "c7", "67", "18"}, 
		{"89", "cb", "30", "1f", "8d", "c6", "8f", "aa", "c8", "74", "dc", "c9", "5d", "5c", "31", "a4"}, 
		{"70", "88", "61", "2c", "9f", "0d", "2b", "87", "50", "82", "54", "64", "26", "7d", "03", "40"}, 
		{"34", "4b", "1c", "73", "d1", "c4", "fd", "3b", "cc", "fb", "7f", "ab", "e6", "3e", "5b", "a5"}, 
		{"ad", "04", "23", "9c", "14", "51", "22", "f0", "29", "79", "71", "7e", "ff", "8c", "0e", "e2"}, 
		{"0c", "ef", "bc", "72", "75", "6f", "37", "a1", "ec", "d3", "8e", "62", "8b", "86", "10", "e8"},
		{"08", "77", "11", "be", "92", "4f", "24", "c5", "32", "36", "9d", "cf", "f3", "a6", "bb", "ac"}, 
		{"5e", "6c", "a9", "13", "57", "25", "b5", "e3", "bd", "a8", "3a", "01", "05", "59", "2a", "46"}
	};
	
	/**
	 * Pad zeros to the start of a string until its
	 * length is equal to len
	 * @param s. The string to pad
	 * @param len. How long the string should be.
	 */
	private static String zFill(String s, int len) {
		int initialLen = s.length();
		if (initialLen != len) {
			for (int i = 0; i < len  - initialLen; i++) {
				s = "0" + s;
			}
		}
		return s;
	}
	
	/**
	 * Write contents to the filename provided
	 * @param filename
	 * @return
	 */
	private static void writeFileContents(ArrayList<String> blocks, String filename, boolean convert) {
		BufferedWriter writer;
		StringBuilder contentBuilder = new StringBuilder();
		System.out.printf("Saving contents to %s\n", filename);
		for (String i: blocks) {
			contentBuilder.append(i);
		}
		String contents = contentBuilder.toString();
		if (convert) {
			contents = WsuCrypt.convertHexToAscii(contents);
		}
		try {
			writer = new BufferedWriter(new FileWriter(filename));
			writer.write(contents);
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.printf("Saving to %s completed\n", filename);
		
	}
 	
	/**
	 * Helper method to read file contents.
	 * @param filename. The file to read
	 * @return file contents
	 */
	private static String readFileContents(String filename) {
		FileInputStream fstream;
		
		System.out.printf("Reading %s\n", filename);
		StringBuilder fileContents = new StringBuilder();
		try {
			fstream = new FileInputStream(filename);
			BufferedReader buf = new BufferedReader(new InputStreamReader(fstream));
			
			String line;
			while ((line = buf.readLine()) != null)   {
				fileContents.append(line);
			}
			buf.close();
			fstream.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.printf("Reading %s completed.\n", filename);
		return fileContents.toString();
	}
	
	private static BigInteger allOnes(int bits) {
	    return BigInteger.ZERO.setBit(bits).subtract(BigInteger.ONE);
	}
	
	private static String convertHexToAscii(String hexStr) {
		StringBuilder output = new StringBuilder();
	    for (int i = 0; i < hexStr.length(); i += 2) {
	        String str = hexStr.substring(i, i + 2);
	        output.append((char) Integer.parseInt(str, 16));
	    }
	     
	    return output.toString();
	}
	
	
	private static String xor(String a, String b, int len) {
		int hexA = Integer.parseInt(a, 16);
		int hexB = Integer.parseInt(b, 16);
		int hexC = hexA ^ hexB;
		String hexNew = String.format("%h", hexC);
		hexNew = WsuCrypt.zFill(hexNew, len);
		return hexNew;
	}
	
	
	private static String convertAsciiToHex(String asciiText) {
		char[] ch = asciiText.toCharArray();
		StringBuilder hex = new StringBuilder();
		
		for (char c: ch) {
			String hexCode = String.format("%h", c);
			hex.append(hexCode);
		}
		
		return hex.toString();
	}
	
	private String leftCircularRotate(String hex, int rotateVal, int keyBits) {
		BigInteger num = new BigInteger(hex, 16);
		num  = num.shiftLeft(rotateVal)
				.or(num.shiftRight(keyBits - rotateVal))
				.and(WsuCrypt.allOnes(keyBits));
		String hexNew = num.toString(16);
		hexNew = WsuCrypt.zFill(hexNew, keyBits / this.hexSize);
		return hexNew; 
	}
	
	private String rightCircularRotate(String hex, int rotateVal, int keyBits) {
		BigInteger num = new BigInteger(hex, 16);
		num  = num.shiftRight(rotateVal)
				.or(num.shiftLeft(keyBits - rotateVal))
				.and(WsuCrypt.allOnes(keyBits));
		String hexNew = num.toString(16);
		hexNew = WsuCrypt.zFill(hexNew, keyBits / this.hexSize);
		return hexNew; 
	}

	/*
	 * mode attribute setter
	 */
	private void setMode(String mode) throws Exception {
		System.out.printf("Mode: %s\n", mode);
		if (!mode.equals("encrypt") && !mode.equals("decrypt")) {
			throw new Exception("Ensure the mode is either 'encrypt' or 'decrypt'.");
		}
		this.mode = mode;
	}

	/*
	 * key attr setter
	 */
	private void setKey(String keyContents) throws Exception {
		if (keyContents.length() != 16 && keyContents.length() != 20) {
			throw new Exception("Ensure the key length is equal to 64bits or 80bits.");
		}
		this.key = keyContents;
		this.originalKey = keyContents;
		
	}
	
	/*
	 * Takes a hex string and converts it to 64bit blocks
	 */
	private void getBlock(String hex) {
		ArrayList<String> blocks = new ArrayList<String>();
		int hexLen = hex.length();
		hexLen = hexLen * hexSize;
		if (hexLen % blockSize != 0) {
			// append zeros.
			int rem = hexLen % blockSize;
			rem = blockSize - rem;
			for (int i = 0; i < rem / hexSize; i++) {
				hex += "0";
			}
		}
		hexLen = hex.length();
		for (int i = 0; i < (hexLen / (hexSize * hexSize)); i++) {
			int startIdx = i * hexSize * hexSize;
			int endIdx = (i + 1) * hexSize * hexSize;
			blocks.add(hex.substring(startIdx, endIdx));
		}
		this.blocks = blocks;
	}
	
	/**
	 * Returns the hex value in the position described by
	 * the hex. The lower 4 bits are used for the column 
	 * and the higher four bits are used for the row.
	 * @param hex. Hex containing the row and column
	 * @return
	 */
	private String ftableSub(String hex) {
		int row = Integer.parseInt(hex.substring(0, 1), 16);
		int column = Integer.parseInt(hex.substring(1, 2), 16);
		return WsuCrypt.ftable[row][column];
	}
	
	 
	/**
	 * Performs the substitution using the Ftable.
	 * 
	 * @return
	 */
	private String G(String hex, int round) {
		String resp;
		String g1 = hex.substring(0, 2);
		String g2 = hex.substring(2, 4);
		if (this.mode.equals("encrypt")) {
			String g3 = WsuCrypt.xor(
				this.ftableSub(WsuCrypt.xor(g2, this.getKey(4 * round), 2)), g1, 2);
			String g4 = WsuCrypt.xor(
					this.ftableSub(WsuCrypt.xor(g3, this.getKey(4 * round + 1), 2)), g2, 2);
			String g5 = WsuCrypt.xor(
					this.ftableSub(WsuCrypt.xor(g4, this.getKey(4 * round + 2), 2)), g3, 2);
			String g6 = WsuCrypt.xor(
					this.ftableSub(WsuCrypt.xor(g5, this.getKey(4 * round + 3), 2)), g4, 2);
			resp = g5 + g6;
		} else {
			String k1 = this.getKey(4 * round + 3);
			String k2 = this.getKey(4 * round + 2);
			String k3 = this.getKey(4 * round + 1);
			String k4 = this.getKey(4 * round);
			String g3 = WsuCrypt.xor(
					this.ftableSub(WsuCrypt.xor(g2, k4, 2)), g1, 2);
			String g4 = WsuCrypt.xor(
					this.ftableSub(WsuCrypt.xor(g3, k3, 2)), g2, 2);
			String g5 = WsuCrypt.xor(
					this.ftableSub(WsuCrypt.xor(g4, k2, 2)), g3, 2);
			String g6 = WsuCrypt.xor(
					this.ftableSub(WsuCrypt.xor(g5, k1, 2)), g4, 2);
			resp = g5 + g6;
		}
		
		return resp;
	}
	
	private ArrayList<String> F(String R0, String R1, int round) {
		ArrayList<String> resp = new ArrayList<String>();
		if (this.mode.equals("encrypt")) {
			String T0 = G(R0, round);
			String T1 = G(R1, round);
			int t0Int = Integer.parseInt(T0, 16);
			int t1Int = Integer.parseInt(T1, 16);
			String key1 = this.getKey(4 * round) + this.getKey(4 * round + 1);
			String key2 = this.getKey(4 * round + 2) + this.getKey(4 * round + 3);
			int k1Int = Integer.parseInt(key1, 16);
			int k2Int = Integer.parseInt(key2, 16);
			int F0 = (t0Int + (2 * t1Int) + k1Int) % 65536;
			int F1 = ((2 *t0Int) + t1Int + k2Int) % 65536;
			resp.add(String.format("%h", F0));
			resp.add(String.format("%h", F1));
		} else {
			String k1 = this.getKey(4 * round + 3);
			String k2 = this.getKey(4 * round + 2);
			String k3 = this.getKey(4 * round + 1);
			String k4 = this.getKey(4 * round);
			String key1 = k4 + k3;
			String key2 = k2 + k1;	
			String T1 = G(R1, round);
			String T0 = G(R0, round);
			int t0Int = Integer.parseInt(T0, 16);
			int t1Int = Integer.parseInt(T1, 16);
			int k1Int = Integer.parseInt(key1, 16);
			int k2Int = Integer.parseInt(key2, 16);
			int F0 = (t0Int + (2 * t1Int) + k1Int) % 65536;
			int F1 = ((2 *t0Int) + t1Int + k2Int) % 65536;
			resp.add(String.format("%h", F0));
			resp.add(String.format("%h", F1));
		}
		
		return resp;
	}
	
	private ArrayList<String> inputWhitening(String block, String key) {
		ArrayList<String> whitened = new ArrayList<String>();
		for (int i = 0; i < block.length() / hexSize; i++) {
			int startIdx = i * hexSize;
			int endIdx = (i + 1) * hexSize;
			String blockStr = block.substring(startIdx, endIdx);
			String keyStr = key.substring(startIdx, endIdx);
			String xorVal = xor(blockStr, keyStr, 4);
			whitened.add(xorVal);
		}
		return whitened;
	}
	
	/**
	 * Returns the byte key to use.
	 * @param round. The current round number
	 * @return hex. Key to use
	 */
	private String getKey(int round) {
		String subKey;
		int startIdx = round % 8;//(this.originalKey.length() / 2);
		startIdx = startIdx * 2;
		int endIdx = startIdx + 2;
		if (this.mode.equals("encrypt")) {
			this.key = this.leftCircularRotate(
				this.key, 1, this.originalKey.length() * this.hexSize);
			subKey = this.key.substring(startIdx, endIdx);
		} else {
			subKey = this.key.substring(startIdx, endIdx);
			this.key = this.rightCircularRotate(
				this.key, 1, this.originalKey.length() * this.hexSize);
		}
		return subKey;
	}
	
	/**
	 * Performs encryption
	 */
	private void encrypt() {
		String R0, R1, R2, R3, F0, F1;
		System.out.println("Encrypting.... Please wait");
		int totalRounds = this.originalKey.length();
		
		for (int i = 0; i < this.blocks.size(); i++) {
			ArrayList<String> whitened = this.inputWhitening(
					this.blocks.get(i), this.originalKey);
			R0 = whitened.get(0);
			R1 = whitened.get(1);
			R2 = whitened.get(2);
			R3 = whitened.get(3);
			for (int j = 0; j < totalRounds; j++) {
				ArrayList<String> afterF = F(R0, R1, j);
				String tempR0 = R0;
				String tempR1 = R1;
				F0 = afterF.get(0);
				F1 = afterF.get(1);
				R0 = WsuCrypt.xor(R2, F0, 4);
				R0 = this.rightCircularRotate(R0, 1, 16);
				R3 = this.leftCircularRotate(R3, 1, 16);
				R1 = WsuCrypt.xor(R3, F1, 4);
				R2 = tempR0;
				R3 = tempR1;
			}
			String y = R2 + R3 + R0 + R1;
			whitened = this.inputWhitening(
					y, this.originalKey);
			R0 = whitened.get(0);
			R1 = whitened.get(1);
			R2 = whitened.get(2);
			R3 = whitened.get(3);
			this.blocks.set(i, R0 + R1 + R2 + R3);
		}
		System.out.println("Encryption Complete.");
	}
	
	/**
	 * Performs decryption.
	 */
	private void decrypt() {
		String R0, R1, R2, R3, F0, F1;
		System.out.println("Decrypting.... Please wait");
		int totalRounds = this.originalKey.length();
		for (int i = 0; i < this.blocks.size(); i++) {
			ArrayList<String> whitened = this.inputWhitening(
					this.blocks.get(i), this.originalKey);
			R0 = whitened.get(0);
			R1 = whitened.get(1);
			R2 = whitened.get(2);
			R3 = whitened.get(3);
			for (int j = 1; j < totalRounds + 1; j++) {
				ArrayList<String> afterF = F(R0, R1, j);
				String tempR0 = R0;
				String tempR1 = R1;
				F0 = afterF.get(0);
				F1 = afterF.get(1);
				R2 = this.leftCircularRotate(R2, 1, 16);
				R0 = WsuCrypt.xor(R2, F0, 4);
				R1 = WsuCrypt.xor(R3, F1, 4);
				R1 = this.rightCircularRotate(R1, 1, 16);
				R2 = tempR0;
				R3 = tempR1;
			}
			String y = R2 + R3 + R0 + R1;
			whitened = this.inputWhitening(
					y, this.originalKey);
			R0 = whitened.get(0);
			R1 = whitened.get(1);
			R2 = whitened.get(2);
			R3 = whitened.get(3);
			this.blocks.set(i, R0 + R1 + R2 + R3);
		}
		System.out.println("Decryption Complete.");
	}
	
	public static void main(String[] args) throws Exception {
		
		if (args.length != 1) {
			throw new Exception("Ensure you provide the mode to run the algorithm in.");
		}
		
		WsuCrypt cryptoObj = new WsuCrypt();
		cryptoObj.setMode(args[0]);
		String keyContents = WsuCrypt.readFileContents(WsuCrypt.keyFile);
		cryptoObj.setKey(keyContents);
		
		if (cryptoObj.mode.equals("encrypt")) {
			String plainText = WsuCrypt.readFileContents(WsuCrypt.pTextFile);
			String hex = WsuCrypt.convertAsciiToHex(plainText);
			cryptoObj.getBlock(hex);
			cryptoObj.encrypt();
			WsuCrypt.writeFileContents(cryptoObj.blocks, WsuCrypt.cTextFile, false);
		} else {
			String cipherText = WsuCrypt.readFileContents(WsuCrypt.cTextFile);
			cryptoObj.getBlock(cipherText);
			cryptoObj.decrypt();
			WsuCrypt.writeFileContents(cryptoObj.blocks, WsuCrypt.pTextFile, false);
		}
		
	}
}
