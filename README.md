PBKDF2 for Haxe
===============

PBKDF2 (Password-Based Key Derivation Function 2) is a key derivation function that you can read all about [on Wikipedia](http://en.wikipedia.org/wiki/PBKDF2).

Basically, it lets you do a hash similar to MD5 or SHA1, but with a salt, and it can repeat thousands of times to make it harder to crack - the longer it takes to generate the key the longer it will take to crack.  Anyway, it is a good way to store user passwords.  Even big names like DJango use it by default.

Platform Support
----------------

Currently tested on Flash9, JS, CPP.  Probably also works on Java, C# and PHP though I haven't checked.

Does not work on Flash8 (generates different numbers, have not debugged).  

Does not work on Neko yet (31bit Integer issue...)

Installation
------------

To install on haxelib:

	haxelib install pbkdf2

And then in your project's hxml build file, add

    -lib pbkdf2

To install from the latest GIT, or from a fork:    

Usage
-----

```
var str = PBKDF2.encode(pass, salt, numIterations, numBytes);
```

It's best to use a different salt for each unique password... Here I use the helper from the [Random](https://github.com/jasononeil/hxrandom) haxelib.

```
user = new User();
user.username = "jason";
user.salt = Random.string(20);
user.password = PBKDF2.encode("password", user.salt, 1000, 20);
```

### Asynchronous Usage

On targets that support haxe.Timer (flash8, flash, js, cs, java) you can use the Async version:

```
var onComplete = function(str:String) {
	trace ("Hash is " + str);
}

PBKDF2.encodeAsync("password", "salt", 1000, 20, onComplete);
```

Attribution & Licence
---------------------

This is a copy-of-a-copy-of-a-derivative, combined with an extern:

1. The Javascript version: Copyright (c) 2007, Parvez Anandam  
parvez.anandam@cern.ch  
http://anandam.name/pbkdf2  
(Uses Paul Johnston's excellent SHA-1 JavaScript library sha1.js)  
Thanks to Felix Gartsman for pointing out a bug in version 1.0  
BSD License

2.  The AS3 version: http://code.google.com/p/as3-pbkdf2/  
jeesmon@gmail.com  
BSD License

2. Haxe implementation by Jason O'Neil  
https://github.com/jasononeil/PBKDF2-Haxe  
BSD license

3. The PHP implementation uses a simple extern which was derived from:  
https://defuse.ca/php-pbkdf2.htm havoc AT defuse.ca  
Released under Public Domain.  Haxe externs written by Jason O'Neil.

See the LICENSE.txt file for the full license.

Making Changes
--------------

 * Edit src/PBKDF2.hx
 * Add unit tests to test/PBKDF2Test.hx
 * `haxelib run munit t` - run unit tests, check all are passing
 * `haxelib run mlib v` - increment version number
 * `haxelib run mlib submit` - submit to Haxelib