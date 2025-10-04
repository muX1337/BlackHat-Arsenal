# ParseAndC 4.0 - The Final Cut

## Description
This is the 4.0 (and Final) version of the ParseAndC tool (whose 1.0, 2.0 and 3.0 versions were presented in the Black Hat Arsenal 2021/2022/2023 (SecTor) and DEFCON 2021). The 1.0 version was capable of mapping any C structure(s) to any datastream, and then visually displaying the 1:1 correspondence between the variables and the data in a very colorful, intuitive display so that it was very easy to understand which field had what value.  In 2.0 version, we introduced dynamic structures which essentially expanded the C language semantics (not syntax) so that now C structures alone had the same power as full-fledged C programs. In 3.0 version, we completed the parsing part of the tool by adding a ton of new or missing features that cover various quirks of C language so that the tool now worked on ANY production C code.

What problems are we solving in this new 4.0 version?

The main problem we solve is that often there is a huge gap between the way any data is stored, and the way it needs to be displayed to make sense to the end-users. While writing a parser, after you "parse" (read in) the data, for "simple" kind of data you can display the data just like that without any manipulation (for example, the integer variable "PacketSizeBytes" can be displayed just like that, and people will immediately understand its value. However, often there are other type of not-so-simple data where just by displaying the data in the native format, it does not convey the real measure of what the data represents. For example, suppose an integer stores the number of seconds since a certain event. Just seeing 465827 sec doesn't give a proper sense of how long the time is, but converting it to a human-readable 5 days 9 hrs 23 min 47 sec does. So, for such cases, merely proper "parsing" (reading in) the data is not enough - we also need to write additional code (either within the Parser itself, or pipe the native format into yet another shell script) to display the value in a custom format. In C, the only two native ways to store data are integer and float, but we need this custom format for many other cases. Some examples:

- Suppose an int represents a memory address, and you would rather see its value displayed in Hex format.

- Suppose an int represents a mask, and you would rather see its value in the binary format.

- Support an int stores the Unix timestamp of a certain event. Just seeing how many seconds have passed since 1/1/1970 is not very telling, it would make far more sense if we convert it to a human-readable YYYY-MM-DD HH-MM-SS or something like that.

- Suppose a float contains the temperature of the chip in Kelvin, but the user of the tool would rather see the unit in Fahrenheit.

- Suppose an int contain the # of days since a particular Sunday, and instead of knowing the day count, the user would rather want to know which day of the week (Sun/Mon/Tue etc.) it is because that's all he/she cares about.

- Suppose an int contains the IPv4 protocol number, but instead of just displaying the numeric protocol numbers like 1/6/17/46, , you would rather display the corresponding protocol names like ICMP/TCP/UDP/RSVP etc.

- Suppose an int actually represents the 4 octets of an IP address, and the user rather see it in the A.B.C.D format.

- It is a char array, and instead of seeing their numeric values, the user would rather see their corresponding ASCII chars.

- The number(s) are coded in certain encoding (say Binary-Coded-Decimal or Base-64), and the user would want to see the decoded values.

C offers printf for doing certain limited manipulations while displaying the data via format string, but that's it. For example, it cannot automatically display the #sec into day:HH:MM:SS format. For each of those custom display manipulation, one would need to write extra code in the Parser, or pipe the parsed data (in native format) to yet another shell script that will manipulate the native data into custom display format. This process is laborious and error prone. Why? Since the code for manipulating the variable value is located in a different place than where the variable is declared, chances are high that coders will make cut-and-paste errors (use wrong variable names or attributes etc.).

Here, we CO-LOCATE the output display format of the data in the same place where they are declared, and the beauty is that, we do it without breaking the C syntax. We optionally annotate every variable declaration with a "format" or "TAG", where the TAG tells how the variable will be displayed. And since we are not allowed to break the existing C syntax, we put this TAG  within the C comment that starts on same line of the variable declaration. A C preprocessor usually discards the comments, but our tool also parses the comments, and if it finds any custom display tag annotation, it will display it accordingly.

To recap on the new capabilities of this tool, earlier the tool used to display the data in the native C formats (integers and floating points), but in current version 4.0 we now have the ability to display the internally stored data into ANY output format we like. For most common type of display formats, this tool gives builtin formats, and for others, it gives the users a way specify it dynamically. You will no longer need to pipe the output to yet another Python/Perl/SED/TR/AWK/Shell script to display the data in the intended format. In other words, this tool is now your ONE-STOP-SHOP for parsing and interpreting the data you are getting from your testing. ANY AND ALL KIND OF TESTING - SW, FW OR HW, Security- or non-Security testing.

The output formats (TAG) that have been added are:

(Reviewer - please note that in this submission, I am using {FORMAT} and {/FORMAT} while in real-life the "{" and "}" would be replaced by "less-than-symbol" and "greater-than-symbol" for this tool. The reason I am forced to do this is because this Black Hat submission website has input sanitization rules which treats them as valid HTML tags and starts interpreting it.

1)	Built-in formats: HEX, OCT, BIN, DEC, PERCENT – to display the data as Hexadecimal, Octal, Binary, Decimal, and Percent. So, if you declare a variable like int I; /* {FORMAT} BIN {/FORMAT}*/, then in the output its value would get displayed in binary.

2)	Built-in Time formats: MILLISECONDS, SECONDS, UNIXDATETIME, EXCELDATETIME – to display the time into a human readable format involving year, month, day, hour, minute, second etc. (fully customizable). For example, if we have a declaration like int TS; /*  {FORMAT} UNIXDATETIME {/FORMAT} */, then the tool will treat this TS variable as a unix timestamp and display its value as YYYY-MM-DD HH:mm:SS. It is extremely flexible, for example, if you give {FORMAT} UNIXDATETIME("Date is MM/DD/YY, and time is HH-mm-SS"){/FORMAT}, for TS=1741977744, your output will be "Date is 03/14/25, and time is 18-42-24" (basically exactly the supplied argument string, with its various tokens like MM, DD, YY etc. replaced with the corresponding values.). Please note that Microsoft Excel stores the timestamp in a different way (a float representing the number of full and fractional days since Dec 31, 1899), and we handle it.

3)	BCD format: To decode data encoded in Binary-Coded-Decimal. This tool provides built-in support for ALL varieties of BCD (viz. "8 4 2 1 (XS-0)" ,"7 4 2 1" ,"Aiken (2 4 2 1)" ,"Excess-3 (XS-3)" ,"Excess-6 (XS-6)" ,"Jump-at-2 (2 4 2 1)" ,"Jump-at-8 (2 4 2 1)" ,"4 2 2 1 (I)" ,"4 2 2 1 (II)" ,"5 4 2 1" ,"5 2 2 1" ,"5 1 2 1" ,"5 3 1 1" ,"White (5 2 1 1)" ,"5 2 1 1" ,"Magnetic tape" ,"Paul" ,"Gray" ,"Glixon" ,"Ledley" ,"4 3 1 1" ,"LARC" ,"Klar" ,"Petherick (RAE)" ,"O'Brien I (Watts)" ,"5-cyclic" ,"Tompkins I" ,"Lippel" ,"O'Brien II" ,"Tompkins II" ,"Excess-3 Gray" ,"6 3  2  1 (I)" ,"6 3  2  1 (II)" ,"8 4  2  1" ,"Lucal" ,"Kautz I" ,"Kautz II" ,"Susskind I" ,"Susskind II")

4)	BASE64 format: To decode data encoded in Base-64 format. Obviously, this only works on array because we are talking about converting 8-bits into 6-bits.

5)	PRINTF format: Basically, giving the user the full power of the C function printf(), and much more. We have also incorporated the more powerful features from other languages in this. For example, Python allows "+" to concatenate strings, and "*" to repeat strings, which we allow here in printf format string specification.

6)	ENUM format: If the code has enum in it, the tool automatically displays the corresponding enum literals instead of the variable values (this is massively helpful). In addition, even if the C struct did not have any enum declared, here we can allow an display enum to be declared specifically for that variable. Combining the C enum and C switch statements, where we depending on the value of the data, we display a certain literal instead. For example. Suppose we store the privilege level of a device driver in an integer called Ring, and instead of displaying 0 and 3, we want display "KMD" and "UMD". In our tool, we just declare it as int Ring; /* {FORMAT} ENUM("KMD"=0, "UMD"=3) {/FORMAT} */, it will display it accordingly.

7)	POSTPROCESS format: This is the most powerful where you can pretty much write any code based on the stored value. You no longer need to pipe the output to yet another script. For example, if variable temp stores the temperature in Kelvin but we want to display it in Fahrenheit, then int tempKelvin; /* {FORMAT} POSTPROCESS((tempKelvin-273.15)*1.8+32) {/FORMAT}*/ will do the job.

We also introduce the "_X_" operator within these formats. Most of the errors in parser writing happens due to cut-and-paste error (if a C struct has 20 fields, there is no way the coder is going to freshly type the 20 printf statements to display their values - the coder is going to type it once for one variable, and then for the rest 19 variables he/she is going to simply copy  the first printf statement, and do the necessary changes. However, many a times the coders forget to make the necessary changes. For example, suppose a very simple struct has two int variables "height" and "weight", two words that differ by a single character. While printing their values, a coder can easily make the following mistake:

printf("height is %d", height);

printf("weight is %d", height);

To avoid these kind of errors, in this 4.0 version, we introduce the "_X_" operator. During runtime, this _X_ will get substituted with the corresponding variable name. For example, look at the struct below which our tool will understand just fine:

struct S {

int height; // {FORMAT} PRINTF("%d",_X_) {/FORMAT}

int weight; // {FORMAT} PRINTF("%d",_X_) {/FORMAT}

};

Another great feature we add is that all these TAGs or formats can be applied one after another on the same variable. So, suppose a variable contains a unix timestamp, and we are only interested in knowing how many days were in that month, and we want the display that many "=" symbols. For example, suppose we know that the timestamp corresponds to a day in the month of December. Since December has 31 days, we want to display "===============================". We can achieve this very elegantly here:

int TimeStamp; /* {FORMAT} UNIXDATETIME("MM") {/FORMAT}

{FORMAT} POSTPROCESS(int(_X_)) {/FORMAT}

{FORMAT} ENUM(31=1,28,31,30,31,30,31,31,30,31,30,31) {/FORMAT}

{FORMAT} PRINTF(_X_*"=") {/FORMAT} */

The first {FORMAT} UNIXDATETIME("MM") {/FORMAT} extracts the date in the MM form (two-digit numeric string).

The second {FORMAT} POSTPROCESS(int(_X_)) {/FORMAT} converts that two-digit numeric string to a number (for example, converting a "09" to 9)

The third {FORMAT} ENUM(31=1,28,31,30,31,30,31,31,30,31,30,31) {/FORMAT} tells how many days to display for that month (observe that month starts from 1, not 0).

The fourth {FORMAT} PRINTF{_X_*"="}  simply prints that many "=" symbols.

This is essentially equivalent of writing sequential code, line after line. The output from previous format gets fed into the next format. This way, you can pretty much write ANY code to custom display your variable RIGHT where the variable declaration is happening. So, the chances of messing it up is indeed very low. And, it is Turing-complete.

Last but not the least, whenever we print a custom display value, we display BOTH the original (native) value and the manipulated (formatted) value. You can see it on the console and in the CSV file. So, we are actually not changing the internal value.

Just click on the "Run Demo" button and see for yourself.

This tool is extremely portable – it's a single Python 2MB text file, is cross-platform (Windows/Mac/Unix), and also works in the terminal /batch mode without GUI or Internet connection. The tool is self-contained - it doesn't import anything, to the extent that it implements its own C compiler (front-end) from scratch!!

This tool is useful for both security- and non-security testing alike (reverse engineering, network traffic analyzing, packet processing etc.). It is currently being used at Intel widely. The author of this tool led many security hackathons at Intel and there this tool was found to be very useful.

## Code
https://github.com/intel/ParseAndC
