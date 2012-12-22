/*
 * Haxe implementation of Password-Based Key Derivation Function 2
 * (PBKDF2) as defined in RFC 2898.
 * Version 1.1
 * 
 * Jason O'Neil
 *
 * Distributed under the BSD license
 * 
 * Derivations / Attribution:
 * 
 * Derived from http://code.google.com/p/as3-pbkdf2/
 * jeesmon@gmail.com
 * 
 * Which in turn, was derived from: 
 * 
 * Copyright (c) 2007, Parvez Anandam
 * parvez.anandam@cern.ch
 * http://anandam.name/pbkdf2
 *
 * (Uses Paul Johnston's excellent SHA-1 JavaScript library sha1.js)
 * Thanks to Felix Gartsman for pointing out a bug in version 1.0
 */

class PBKDF2
{
  #if !flash8

    public static function encode(value:String, salt:String, iterations:Int = 1000, ?numBytes:Int = 512)
    {
      var pbkdf2 = new PBKDF2(value, salt, iterations, numBytes);
      return pbkdf2.deriveKey();
    }

    // Async is only available on platforms that support haxe.Timer
    #if (flash8 || flash || js || cs || java)
      public static function encodeAsync(value:String, salt:String, iterations:Int = 1000, ?numBytes:Int = 512, resultFn:String->Void, ?updateFn:Float->Void)
      {
        var pbkdf2 = new PBKDF2(value, salt, iterations, numBytes);
        haxe.Timer.delay(function() { pbkdf2.deriveKey(resultFn, updateFn); }, 0);
      }
    #end
    
    // Remember the password and salt
    var m_bpassword:Array<Int>;
    var m_salt:String;
    // Total number of iterations
    var m_total_iterations:Int;
    // Run iterations in chunks instead of all at once, so as to not block.
    // Define size of chunk here; adjust for slower or faster machines if necessary.
    var m_iterations_in_chunk:Int;
    // Iteration counter
    var m_iterations_done:Int;
    // Key length, as number of bytes
    var m_key_length:Int;
    // The length (number of bytes) of the output of the pseudo-random function.
    // Since HMAC-SHA1 is the standard, and what is used here, it's 20 bytes.
    var m_hash_length:Int;
    // Number of hash-sized blocks in the derived key (called 'l' in RFC2898)
    var m_total_blocks:Int;
    // Start computation with the first block
    var m_current_block:Int;
    // Used in the HMAC-SHA1 computations
    var m_ipad:Array<Int>;
    var m_opad:Array<Int>;

    // This is where the result of the iterations gets sotred
    var m_buffer:Array<Int>;

    // The result
    var m_key:String;

    // The function to call with the result
    var m_result_func:String->Void;

    // The function to call with status after computing every chunk
    var m_status_func:Float->Void;

    var m_hash:Array<Int>;


    /*
      * The four arguments to the constructor of the PBKDF2 object are
      * the password, salt, number of iterations and number of bytes in
      * generated key. This follows the RFC 2898 definition: PBKDF2 (P, S, c, dkLen)
      *
      * The method deriveKey takes two parameters, both callback functions:
      * the first is used to provide status on the computation, the second
      * is called with the result of the computation (the generated key in hex).
      *
      * Example of use:
      *
      *    <script src="sha1.js"></script>
      *    <script src="pbkdf2.js"></script>
      *    <script>
      *    var mypbkdf2 = new PBKDF2("mypassword", "saltines", 1000, 16);
      *    var status_callback = function(percent_done) {
      *        document.getElementById("status").innerHTML = "Computed " + percent_done + "%"};
      *    var result_callback = function(key) {
      *        document.getElementById("status").innerHTML = "The derived key is: " + key};
      *    mypbkdf2.deriveKey(status_callback, result_callback);
      *    </script>
      *    <div id="status"></div>
      *
    */
    public function new(password:String, salt:String, num_iterations:Int, num_bytes:Int)
    {
      m_bpassword = SHA1Helpers.str2binb(password);
      m_salt = salt;
      m_total_iterations = num_iterations;
      m_iterations_in_chunk = 10;
      m_iterations_done = 0;
      m_key_length = num_bytes;
      m_hash_length = 20;
      m_total_blocks = Math.ceil(m_key_length/m_hash_length);
      m_current_block = 1;
      m_ipad = new Array();
      m_opad = new Array();
      m_buffer = [0x0,0x0,0x0,0x0,0x0];
      m_key = "";
      m_hash = new Array();

      // Set up the HMAC-SHA1 computations
      if (m_bpassword.length > 16) m_bpassword = SHA1Helpers.core_sha1(m_bpassword, password.length * SHA1Helpers.chrsz);

      //for(var i:Int = 0; i < 16; ++i)
      var i = 0;
      while (i < 16)
      {
        m_ipad[i] = m_bpassword[i] ^ 0x36363636;
        m_opad[i] = m_bpassword[i] ^ 0x5C5C5C5C;
        ++i;
      }
    }

    // Starts the computation
    public function deriveKey(?result_callback:String->Void, ?status_callback:Float->Void)
    {
      m_status_func = status_callback;
      m_result_func = result_callback;
      var result = do_PBKDF2_iterations();
      return result;
    }


    // The workhorse
    function do_PBKDF2_iterations()
    {
      var iterations:Int = m_iterations_in_chunk;
      if (m_total_iterations - m_iterations_done < m_iterations_in_chunk)
      { 
        iterations = m_total_iterations - m_iterations_done; 
      }
      
      //for(var i:Int=0; i<iterations; ++i)
      var i = 0;
      while (i < iterations)
      {
        // compute HMAC-SHA1
        if (m_iterations_done == 0)
        {
          var salt_block:String = m_salt +
                String.fromCharCode(m_current_block >> 24 & 0xF) +
                String.fromCharCode(m_current_block >> 16 & 0xF) +
                String.fromCharCode(m_current_block >>  8 & 0xF) +
                String.fromCharCode(m_current_block       & 0xF);
          m_hash = SHA1Helpers.core_sha1(m_ipad.concat(SHA1Helpers.str2binb(salt_block)),
                                          512 + salt_block.length * 8);
          m_hash = SHA1Helpers.core_sha1(m_opad.concat(m_hash), 512 + 160);
        }
        else
        {
          m_hash = SHA1Helpers.core_sha1(m_ipad.concat(m_hash),
            512 + m_hash.length * 32);
          m_hash = SHA1Helpers.core_sha1(m_opad.concat(m_hash), 512 + 160);
        }
        //for(var j:Int=0; j<m_hash.length; ++j)
        var j = 0;
        while (j < m_hash.length)
        {
          m_buffer[j] ^= m_hash[j];
          ++j;
        }
        m_iterations_done++;
        ++i;
      }
    
      // Call the status callback function
      if (m_status_func != null)
      {
        m_status_func( (m_current_block - 1 + m_iterations_done/m_total_iterations) / m_total_blocks * 100);
      }

      if (m_iterations_done < m_total_iterations)
      {
        var result = do_PBKDF2_iterations();
        return result;
      }
      else
      {
        if (m_current_block < m_total_blocks)
        {
          // Compute the next block (T_i in RFC 2898)
          m_key += SHA1Helpers.binb2hex(m_buffer);
          m_current_block++;
          m_buffer = [0x0,0x0,0x0,0x0,0x0];
          m_iterations_done = 0;
          var result = do_PBKDF2_iterations();
          return result;
        }
        else
        {
          // We've computed the final block T_l; we're done.
          var tmp:String = SHA1Helpers.binb2hex(m_buffer);
          m_key += tmp.substr(0, (m_key_length - (m_total_blocks - 1) * m_hash_length) * 2 );
          
          // Call the result callback function
          if (m_result_func != null)
          {
            m_result_func(m_key);
          }
          return m_key;
        }
      }
    }
  #end
}

private class SHA1Helpers
{
  /*
   * Configurable variables. You may need to tweak these to be compatible with
   * the server-side, but the defaults work in most cases.
   */
  public static var hexcase:Int   = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
  public static var b64pad:String  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
  public static var chrsz:Int     = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

  /*
   * These are the functions you'll usually want to call
   * They take string arguments and return either hex or base-64 encoded strings
   */
  public static function hex_sha1(s:String):String{return binb2hex(core_sha1(str2binb(s),s.length * chrsz));}
  public static function b64_sha1(s:String):String{return binb2b64(core_sha1(str2binb(s),s.length * chrsz));}
  public static function str_sha1(s:String):String{return binb2str(core_sha1(str2binb(s),s.length * chrsz));}
  public static function hex_hmac_sha1(key:String, data:String):String{ return binb2hex(core_hmac_sha1(key, data));}
  public static function b64_hmac_sha1(key:String, data:String):String{ return binb2b64(core_hmac_sha1(key, data));}
  public static function str_hmac_sha1(key:String, data:String):String{ return binb2str(core_hmac_sha1(key, data));}

  /*
   * Perform a simple self-test to see if the VM is working
   */
  public static function sha1_vm_test():Bool
  {
    return hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
  }

  /*
   * Calculate the SHA-1 of an array of big-endian words, and a bit length
   */
  public static function core_sha1(x:Array<Int>, len:Int):Array<Int>
  {
    /* append padding */
    x[len >> 5] |= 0x80 << (24 - len % 32);
    x[((len + 64 >> 9) << 4) + 15] = len;
   
    var w:Array<Int> = new Array();
    var a:Int =  1732584193;
    var b:Int = -271733879;
    var c:Int = -1732584194;
    var d:Int =  271733878;
    var e:Int = -1009589776;
   
    //for(var i:Int = 0; i < x.length; i += 16)
    var i = 0;
    while (i < x.length)
    {
      var olda:Int = a;
      var oldb:Int = b;
      var oldc:Int = c;
      var oldd:Int = d;
      var olde:Int = e;
     
      //for(var j:Int = 0; j < 80; j++)
      for (j in 0...80)
      {
        if(j < 16) w[j] = x[i + j];
        else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
        var t:Int = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                 safe_add(safe_add(e, w[j]), sha1_kt(j)));
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
      }

      a = safe_add(a, olda);
      b = safe_add(b, oldb);
      c = safe_add(c, oldc);
      d = safe_add(d, oldd);
      e = safe_add(e, olde);
      i = i+16;
    }
   
    return [a, b, c, d, e];              
  }
   
  /*
   * Perform the appropriate triplet combination function for the current
   * iteration
   */
  public static function sha1_ft(t:Int, b:Int, c:Int, d:Int):Int
  {
    if(t < 20) return (b & c) | ((~b) & d);
    if(t < 40) return b ^ c ^ d;
    if(t < 60) return (b & c) | (b & d) | (c & d);
    return b ^ c ^ d;
  }
   
  /*
   * Determine the appropriate additive constant for the current iteration
   */
  public static function sha1_kt(t:Int):Int
  {
    return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
       (t < 60) ? -1894007588 : -899497514;
  }
   
  /*
   * Calculate the HMAC-SHA1 of a key and some data
   */
  public static function core_hmac_sha1(key:String, data:String):Array<Int>
  {
    var bkey = str2binb(key);
    if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);
   
    var ipad:Array<Int> = new Array();
    var opad:Array<Int> = new Array();

    //for(var i:Int = 0; i < 16; i++)
    for (i in 0...16)
    {
      ipad[i] = bkey[i] ^ 0x36363636;
      opad[i] = bkey[i] ^ 0x5C5C5C5C;
    }
   
    var hash:Array<Int> = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
    return core_sha1(opad.concat(hash), 512 + 160);
  }
   
  /*
   * Add integers, wrapping at 2^32. This uses 16-bit operations internally
   * to work around bugs in some JS interpreters.
   */
  public static function safe_add(x:Int, y:Int):Int
  {
    var lsw:Int = (x & 0xFFFF) + (y & 0xFFFF);
    var msw:Int = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }
   
  /*
   * Bitwise rotate a 32-bit number to the left.
   */
  public static function rol(num:Int, cnt:Int):Int
  {
    return (num << cnt) | (num >>> (32 - cnt));
  }
   
  /*
   * Convert an 8-bit or 16-bit string to an array of big-endian words
   * In 8-bit function, characters >255 have their hi-byte silently ignored.
   */
  public static function str2binb(str:String):Array<Int>
  {
    var bin:Array<Int> = new Array();
    var mask:Int = (1 << chrsz) - 1;
    //for(var i:Int = 0; i < str.length * chrsz; i += chrsz)
    var i = 0;
    while (i < str.length * chrsz)
    {
      bin[i>>5] |= (str.charCodeAt(Std.int(i / chrsz)) & mask) << (32 - chrsz - i%32);
      i = i + chrsz;
    }
    return bin;
  }
   
  /*
   * Convert an array of big-endian words to a string
   */
  public static function binb2str(bin:Array<Int>):String
  {
    var str:String = "";
    var mask:Int = (1 << chrsz) - 1;
    //for(var i:Int = 0; i < bin.length * 32; i += chrsz)
    var i = 0;
    while (i < bin.length * 32)
    {
      str += String.fromCharCode((bin[i>>5] >>> (32 - chrsz - i%32)) & mask);
      i = i + chrsz;
    }
    return str;
  }
   
  /*
   * Convert an array of big-endian words to a hex string.
   */
  public static function binb2hex(binarray:Array<Int>):String
  {
    var hex_tab:String = (hexcase == 1) ? "0123456789ABCDEF" : "0123456789abcdef";
    var str:String = "";
    //for(var i:Int = 0; i < binarray.length * 4; i++)
    for (i in 0...(binarray.length * 4))
    {
      str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
         hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
    }
    return str;
  }
   
  /*
   * Convert an array of big-endian words to a base-64 string
   */
  public static function binb2b64(binarray:Array<Int>):String
  {
    var tab:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var str:String = "";
    //for(var i:Int = 0; i < binarray.length * 4; i += 3)
    var i = 0;
    while (i < binarray.length * 4)
    {
      var triplet:Int = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
            | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
            |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
      //for(var j:Int = 0; j < 4; j++)
      for (j in 0...4)
      {
        if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
        else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
      }
      i = i + 3;
    }
    return str;
  }
}