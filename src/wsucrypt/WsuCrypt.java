package wsucrypt;

public class WsuCrypt {
	// xor
	// covertAsciiToHex
	// convertHexToAscii
	
	public static void main(String[] args) throws Exception {
		
		if (args.length != 2) {
			throw new Exception("Ensure you have passed the plaintext file and key.");
		}
		System.out.println(args[0]);
		System.out.println(args[1]);
	}

}
