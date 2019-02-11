package wsucrypt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;


public class WsuCrypt {
	// xor
	// covertAsciiToHex
	// convertHexToAscii
	private String key;
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
	 * Helper method to read file contents.
	 * @param filename. The file to read
	 * @return file contents
	 */
	private static String readFileContents(String filename) {
		FileInputStream fstream;
		
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
		return fileContents.toString();
	}
	
	static BigInteger allOnes(int bits) {
	    return BigInteger.ZERO.setBit(bits).subtract(BigInteger.ONE);
	}
	
	private static String convertAsciiToHex(String asciiText) {
		char[] ch = asciiText.toCharArray();
		StringBuilder hex = new StringBuilder();
		
		for (char c: ch) {
			String hexCode = String.format("%H", c);
			hex.append(hexCode);
		}
		
		return hex.toString();
	}
	
	public String leftCircularRotate(String hex, int rotateVal) {
		int keyBits = this.hexSize * this.key.length();
		BigInteger num = new BigInteger(hex, 16);
		num  = num.shiftLeft(rotateVal)
				.or(num.shiftRight(keyBits - rotateVal))
				.and(WsuCrypt.allOnes(keyBits));
		return num.toString(16);
	}
	
	public String rightCircularRotate(String hex, int rotateVal) {
		int keyBits = this.hexSize * this.key.length();
		BigInteger num = new BigInteger(hex, 16);
		num  = num.shiftRight(rotateVal)
				.or(num.shiftLeft(keyBits - rotateVal))
				.and(WsuCrypt.allOnes(keyBits));
		return num.toString(16);
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
		} else {
			String cipherText = WsuCrypt.readFileContents(WsuCrypt.cTextFile);
			cryptoObj.getBlock(cipherText);
		}
		
//		System.out.println(cryptoObj.getKey(4*0));
//		System.out.println(cryptoObj.getKey(4*0 + 1));
//		System.out.println(cryptoObj.getKey(4*0 + 2));
//		System.out.println(cryptoObj.getKey(4*0 + 3));
//		System.out.println(cryptoObj.getKey(4*0));
//		System.out.println(cryptoObj.getKey(4*0 + 1));
//		System.out.println(cryptoObj.getKey(4*0 + 2));
//		System.out.println(cryptoObj.getKey(4*0 + 3));
//		System.out.println(cryptoObj.getKey(4*0));
//		System.out.println(cryptoObj.getKey(4*0 + 1));
//		System.out.println(cryptoObj.getKey(4*0 + 2));
//		System.out.println(cryptoObj.getKey(4*0 + 3));
		cryptoObj.setMode("decrypt");
		System.out.println(cryptoObj.getKey(4*0 + 3));
		System.out.println(cryptoObj.getKey(4*0 + 2));
		System.out.println(cryptoObj.getKey(4*0 + 1));
		System.out.println(cryptoObj.getKey(4*0));
		System.out.println(cryptoObj.getKey(4*0 + 3));
		System.out.println(cryptoObj.getKey(4*0 + 2));
		System.out.println(cryptoObj.getKey(4*0 + 1));
		System.out.println(cryptoObj.getKey(4*0));
		System.out.println(cryptoObj.getKey(4*0 + 3));
		System.out.println(cryptoObj.getKey(4*0 + 2));
		System.out.println(cryptoObj.getKey(4*0 + 1));
		System.out.println(cryptoObj.getKey(4*0));
		
	}
	
	private static String xor(String a, String b) {
		int hexA = Integer.parseInt(a, 16);
		int hexB = Integer.parseInt(b, 16);
		int hexC = hexA ^ hexB;
		return String.format("%H", hexC);
	}
	
	/*
	 * mode attribute setter
	 */
	private void setMode(String mode) throws Exception {
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
		for (int i = 0; i < (hexLen / hexSize); i++) {
			int startIdx = i * hexSize;
			int endIdx = (i + 1) * hexSize;
			blocks.add(hex.substring(startIdx, endIdx));
		}
		this.blocks = blocks;
	}
	
	private ArrayList<String> inputWhitening(String block, String key) {
		ArrayList<String> whitened = new ArrayList<String>();
		
		for (int i = 0; i < block.length() / hexSize; i++) {
			int startIdx = i * hexSize;
			int endIdx = (i + 1) * hexSize;
			String blockStr = block.substring(startIdx, endIdx);
			String keyStr = key.substring(startIdx, endIdx);
			String xorVal = xor(blockStr, keyStr);
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
		int startIdx = round % (key.length() / 2);
		startIdx = startIdx * 2;
		int endIdx = startIdx + 2;
		if (this.mode.equals("encrypt")) {
			this.key = this.leftCircularRotate(this.key, 1);
			subKey = this.key.substring(startIdx, endIdx);
		} else {
			subKey = this.key.substring(startIdx, endIdx);
			this.key = this.rightCircularRotate(this.key, 1);
		}
		System.out.println(this.key);
		return subKey;
	}
}
