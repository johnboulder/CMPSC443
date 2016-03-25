package dictionaryAttack;

public class Cipher 
{
	private String mCipherText;
	private String mKey;
	private String mSalt;
	private String mUsername;
	private boolean mSalty;
	
	Cipher()
	{
		mCipherText = null;
		mKey = null;
		mSalt = null;
		mUsername = null;
		mSalty = false;
	}
	
	Cipher(String cipherText, String key, String salt, String username, boolean isSalty)
	{
		mCipherText = cipherText;
		mKey = key;
		mSalt = salt;
		mUsername = username;
		mSalty = isSalty;
	}
	
	public String getCipherText()
	{
		return mCipherText;
	}
	
	public String getKey()
	{
		return mKey;
	}
	
	public String getSalt()
	{
		return mSalt;
	}
	
	public String getUsername()
	{
		return mUsername;
	}
	
	public boolean isSalty()
	{
		return mSalty;
	}
}
