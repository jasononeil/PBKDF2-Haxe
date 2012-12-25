package;

import massive.munit.util.Timer;
import massive.munit.Assert;
import massive.munit.async.AsyncFactory;

class PBKDF2Test 
{
  public function new() 
  {
      
  }
  
  @BeforeClass
  public function beforeClass():Void
  {
  }
  
  @AfterClass
  public function afterClass():Void
  {
  }
  
  @Before
  public function setup():Void
  {
  }
  
  @After
  public function tearDown():Void
  {
  }

  // Hashes used here are also checked against implementation at http://anandam.name/pbkdf2/
  // (which the Haxe version was originally derived from, via the AS3 version)

  @Test 
  public function oneIteration()
  {
    var str = PBKDF2.encode("password", "salt", 1, 20);
    Assert.areEqual("0c60c80f961f0e71f3a9b524af6012062fe037a6", str);
  }

  @Test 
  public function manyIterations()
  {
    var str = PBKDF2.encode("password", "salt", 1000, 20);
    Assert.areEqual("6e88be8bad7eae9d9e10aa061224034fed48d03f", str);
  }

  @Test 
  public function changePassword()
  {
    var str1 = PBKDF2.encode("password1", "salt", 1000, 20);
    var str2 = PBKDF2.encode("password2", "salt", 1000, 20);
    Assert.areEqual("613d9f9fc9e395a3678dfc5a69c7f7cb5323621f", str1);
    Assert.areEqual("f9c41cc6d15cf4d3517cc0e29b73de45f867b06c", str2);
  }

  @Test 
  public function changeSalt()
  {
    var str1 = PBKDF2.encode("password", "salt1", 1000, 20);
    var str2 = PBKDF2.encode("password", "salt2", 1000, 20);
    Assert.areEqual("944601fa3001aba4d19d4b7b0a0b3f924422ebc8", str1);
    Assert.areEqual("8850932d5091291a26733b7835d9f88ef9893776", str2);
  }

  @Test 
  public function changeNumIterations()
  {
    var str1 = PBKDF2.encode("password", "salt", 1, 20);
    var str2 = PBKDF2.encode("password", "salt", 10, 20);
    var str3 = PBKDF2.encode("password", "salt", 100, 20);
    var str4 = PBKDF2.encode("password", "salt", 1000, 20);
    var str5 = PBKDF2.encode("password", "salt", 10000, 20);
    Assert.areEqual("0c60c80f961f0e71f3a9b524af6012062fe037a6", str1);
    Assert.areEqual("ae3fe5f5707e07f3e7c117fb885cd052a6fcd77a", str2);
    Assert.areEqual("8595d7aea0e7c952a35af9a838cc6b393449307c", str3);
    Assert.areEqual("6e88be8bad7eae9d9e10aa061224034fed48d03f", str4);
    Assert.areEqual("a2c2646186828474b754591a547c18f132d88d74", str5);
  }

  @Test 
  public function changeLength()
  {
    var str1 = PBKDF2.encode("password", "salt", 1000, 2);
    var str2 = PBKDF2.encode("password", "salt", 1000, 20);
    var str3 = PBKDF2.encode("password", "salt", 1000, 100);
    var str4 = PBKDF2.encode("password", "salt", 1000, 200);
    Assert.areEqual("6e88", str1);
    Assert.areEqual("6e88be8bad7eae9d9e10aa061224034fed48d03f", str2);
    Assert.areEqual("6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214ce970d912ec2049b04231d47c2eb88506945b26b2325e6adfeeba08895ff9587a30b79968d7c300921db460902c9e1838b09462351a549a1f1d84e47a4e521b839224cf3", str3);
    Assert.areEqual("6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214ce970d912ec2049b04231d47c2eb88506945b26b2325e6adfeeba08895ff9587a30b79968d7c300921db460902c9e1838b09462351a549a1f1d84e47a4e521b839224cf347c3a09ea223e344955cd659813e6a80ef11fda1ca2b5749311501bac5d99474b3725ff440dc71deac3ff80a20748911a1d55a5de4283a7820da3a21015fd5721b3adada046620c9e88b45b96a95dc319ab0304245779cc7fd69794dc8312ad9073682a7", str4);
  }
  
  // Tests against the official test vectors for the standard: 
  // See https://www.ietf.org/rfc/rfc6070.txt

  @Test
  public function passOfficialTestVectors1()
  {
    var str1 = PBKDF2.encode("password", "salt", 1, 20);
    var expected1 = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
    Assert.areEqual(expected1, str1);             
  }

  @Test
  public function passOfficialTestVectors2()
  {
    var str2 = PBKDF2.encode("password", "salt", 2, 20);
    var expected2 = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
    Assert.areEqual(expected2, str2);             
  }

  @Test
  public function passOfficialTestVectors3()
  {
    var str3 = PBKDF2.encode("password", "salt", 4096, 20);
    var expected3 = "4b007901b765489abead49d926f721d065a429c1";
    Assert.areEqual(expected3, str3);             
  }

  @Test @Ignore("Fails to run on most targets - too much recursion, segfaults, etc.")
  public function passOfficialTestVectors4()
  {
    var str4 = PBKDF2.encode("password", "salt", 16777216, 20);
    var expected4 = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
    Assert.areEqual(expected4, str4);             
  }

  @Test
  public function passOfficialTestVectors5()
  {
    var str5 = PBKDF2.encode("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25);
    var expected5 = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
    Assert.areEqual(expected5, str5);                      
  }

  @Test
  public function passOfficialTestVectors6()
  {
    var n = String.fromCharCode(0);
    var str6 = PBKDF2.encode("pass" + n + "word", "sa" + n + "lt", 4096, 16);
    var expected6 = "56fa6aa75548099dcc37d7f03425e0c3";
    Assert.areEqual(expected6, str6); 
  }
  
  // Async is only available on platforms that support haxe.Timer

  #if (flash8 || flash || js || cs || java)
    @AsyncTest
    public function asyncPBKDF2Result(factory:AsyncFactory):Void
    {
      var handler:Dynamic = factory.createHandler(this, onAsyncPBKDF2Complete, 5000);
      // timer = Timer.delay(handler, 200);
      PBKDF2.encodeAsync("password", "salt", 1000, 20, handler);
    }
    
    private function onAsyncPBKDF2Complete(str:String):Void
    {
      Assert.areEqual("6e88be8bad7eae9d9e10aa061224034fed48d03f", str);
    }
  #end

}