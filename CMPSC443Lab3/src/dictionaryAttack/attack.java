package dictionaryAttack;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;

import javax.xml.bind.DatatypeConverter;

/**
 * Main class for this assignment
 */
public class attack 
{
	static final String output_file_path = "output.txt";
	static final String NOT_FOUND = "not_found";
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	static PrintWriter writer;
	
	static ArrayList<String> dictionaryList;
	static ArrayList<Cipher> ciphers;
	static HashMap<String, Cipher> cipheredData;
	static HashMap<String, String> encryptedDictionary;
	
	/**
	 * Main function
	 * We initialize all the data structures first, and read in any data in text files that are used 
	 * Then we iterate over the dictionary and add all of the hashed versions of the words and their 
	 * manipulated versions to a hashmap so we can do quick comparisons
	 * Then we quickly check the hashed-dictionary for the non-salt hashes
	 * And finally we generate each salted hash for each word until the hash is found for each salted 
	 * hash
	 */
	public static void main(String argz[])
	{
		
		// Initialization
		dictionaryList = new ArrayList<>();
		ciphers = new ArrayList<>();
		cipheredData = new HashMap<>();
		encryptedDictionary = new HashMap<>();
		
		// File initialization, and instantiation of the various hashmaps/lists
		try 
		{
			// Init the file output
			writer = new PrintWriter(output_file_path, "UTF-8");
			
			// Initialize a stringbuilder for string processring
			StringBuilder sb = new StringBuilder();
			
			// Read in the dictionary, and add them to a list to use later
			for (String word : Files.readAllLines(Paths.get("assets/english.0"))) 
			{
				// Add the word to a list
				dictionaryList.add(word);
				// Add the reverse of the current word to the list
				dictionaryList.add(sb.append(word).reverse().toString());
				// Remove vowels
				word = word.replace("a", "");
				word = word.replace("e", "");
				word = word.replace("i", "");
				word = word.replace("o", "");
				word = word.replace("u", "");
				word = word.replace("A", "");
				word = word.replace("E", "");
				word = word.replace("I", "");
				word = word.replace("O", "");
				word = word.replace("U", "");
				// Add the voweless version of the word to the list
				dictionaryList.add(word);
				// Remove the word from the stringbuilder so we're ready for the next word
				sb.delete(0, sb.length());
			}
			
			// Read in the encrypted passwords, and add each to a list/hashmap
			for (String word : Files.readAllLines(Paths.get("assets/eula.1028.txt"))) 
			{
				// Split the line into its parts
				String entryData[] = word.split(" ");
				// Separate the line's data
				String username = entryData[0];
				String isSalty = entryData[1];
				// Assume the salt doesn't exist
				boolean salty = false;
				String salt = "";
				String ciphertext;
				
				// Check that it's not salty
				if(isSalty.equals("0"))
				{
					ciphertext = entryData[2];
				}
				else
				{
					// If the hash is salty, initialize it's salt data
					salty = true;
					salt = entryData[2];
					ciphertext = entryData[3];
				}
				
				// Make a new object for the hash
				Cipher newCipher =  new Cipher(ciphertext.toUpperCase(), NOT_FOUND, salt, username, salty);
				// Put the cipher into a hash
				cipheredData.put(ciphertext.toUpperCase(), newCipher);
				// Place the encrypted passwords into a list containing the ciphertext and the corresponding data
				ciphers.add(newCipher);
			}
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		
		// Generate hashes for the entire dictionary
		java.security.MessageDigest d = null;
		try 
		{
			// Initialize the digest for generating the hash
			d = java.security.MessageDigest.getInstance("SHA-1");
			// Iterate over every word in the dictionary and add it to a hashmap of hashed words
			for(String word : dictionaryList)
			{
				// Add word to digest
				d.update(word.getBytes());
				// Get the hashed String version of the bytes
				String encryption = bytesToHex(d.digest());
				// Add it to the hashmap
				encryptedDictionary.put(encryption, word);
			}
		} 
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		// Iterate over all the "ciphers" in the cipher list
		// If it's non-salted, check the dictionary hashmap
		// If it's salted, generate every possible hash with the salt until the hash is found 
		// or the dictionary ends
		for(Cipher cipher : ciphers)
		{
			// If the cipher has a salt
			if(cipher.isSalty())
			{
				// Get the salt into byte form
				byte[] salt = DatatypeConverter.parseHexBinary(cipher.getSalt());
				
				// Iterate over every word in the dictionary
				for(String word : dictionaryList)
				{
					// Get the byte form of the word
					byte[] word_b = word.getBytes();
					// Create a new byte array for the salt and word to be in
					byte[] combined = new byte[salt.length+word_b.length];
					
					// Combine the byte arrays 
					int j=0;
					for(int i = 0; i<combined.length; i++)
					{
						// Iterate across the salt
						if(i<salt.length)
						{
							combined[i] = salt[i];
						}
						else
						{
							// Iterate across the word
							combined[i] = word_b[j];
							j++;
						}
					}
					// Update the digest 
					d.update(combined);
					// Make the cipher
					String encryption = bytesToHex(d.digest());
					
					// No point adding the cipher to a hashmap since salts are different for all ciphers here
					// If a match is found, output the data
					if(cipher.getCipherText().equals(encryption))
					{
						String cipherText = cipher.getCipherText();
						System.out.println(cipher.getUsername()+": Ciphertext:"+cipherText+" Password:"+word);
						writer.println(cipher.getUsername()+": Ciphertext:"+cipherText+" Password:"+word);
					}
				}
			}
			// If the cipher doesn't have a salt
			else
			{
				// If a match is found, output the data
				if(encryptedDictionary.containsKey(cipher.getCipherText()))
				{
					String ptext = encryptedDictionary.get(cipher.getCipherText());
					System.out.println(cipher.getUsername()+": Ciphertext:"+cipher.getCipherText()+" Password:"+ptext);
					writer.println(cipher.getUsername()+": Ciphertext:"+cipher.getCipherText()+" Password:"+ptext);
					cipheredData.remove(cipher.getCipherText());
				}
			}
		}
		
		writer.close();
	}
	
	/**
	 * Takes a byte array and translates it into a hexadecimal string 
	 */
	public static String bytesToHex(byte[] bytes) 
	{
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) 
	    {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
}
