import massive.munit.Assert;

class SimpleTest 
{
	public static function main()
	{
		try 
		{
			passOfficialTestVectors();	
			trace ("PASSED");
		}
		catch (e:Dynamic)
		{
			trace ("FAILED");
			trace (e);
		}
	}

	static function passOfficialTestVectors()
	{
		var str1 = PBKDF2.encode("password", "salt", 1, 20);
		var expected1 = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
		Assert.areEqual(expected1, str1);             

		var str2 = PBKDF2.encode("password", "salt", 2, 20);
		var expected2 = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
		Assert.areEqual(expected2, str2);             

		var str3 = PBKDF2.encode("password", "salt", 4096, 20);
		var expected3 = "4b007901b765489abead49d926f721d065a429c1";
		Assert.areEqual(expected3, str3);             

		// var str4 = PBKDF2.encode("password", "salt", 16777216, 20);
		// var expected4 = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
		// Assert.areEqual(expected4, str4);             

		var str5 = PBKDF2.encode("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25);
		var expected5 = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
		Assert.areEqual(expected5, str5);                      

		var n = String.fromCharCode(0);
		var str6 = PBKDF2.encode("pass" + n + "word", "sa" + n + "lt", 4096, 16);
		var expected6 = "56fa6aa75548099dcc37d7f03425e0c3";
		Assert.areEqual(expected6, str6); 
	}
}