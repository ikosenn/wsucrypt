package wsucrypt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
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
	
	private static String convertAsciiToHex(String asciiText) {
		char[] ch = asciiText.toCharArray();
		StringBuilder hex = new StringBuilder();
		
		for (char c: ch) {
			String hexCode = String.format("%H", c);
			hex.append(hexCode);
		}
		
		return hex.toString();
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

}
