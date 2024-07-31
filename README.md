# IDARustler
IDA plugin helping reverse-engineering rust binaries. It is worked under IDA Pro 8.4.

For more Rust Reversing Basics, please visit [my note](https://hackmd.io/@r3dhun9/rJho8OwY0).

## Files

/plugin/core_function_fixer.py:

> Function name fixer fixed by known function hashes.

/plugin/function_hash_downloader.py:

> Function hashes downloader to dump function hashes through a rust binary which has fully symbols.

/plugin/string_function_detector.py:

> Function name fixer fixed by known strings in the binary.

/example/main.rs:

> Source file provided to compile a rust binary.

/example/func_sha1:

> Function hashes downloaded from the binary compiled from /example/main.rs.

## Usage

1. Use **/plugin/function_hash_downloader.py** to download the function hashes. If you don't want to compile a rust binary, just use **/example/func_sha1** for the next step. ***The output file will stay in the folder which you opened the compiled binary.***

> Open IDA Pro -> File -> Script file -> choose /plugin/function_hash_downloader.py

![](/screenshot/function_hash_downloader.png)

2. Use **/plugin/core_function_fixer.py** to fix the function name by known hashes ***Please put the **func_sha1** file into the folder which you opened the malware or binary.***
This step may take a long time if you're trying to fix a big malware, please wait for it or just drop this step and go to the next step.

> Open IDA Pro -> File -> Script file -> choose /plugin/core_function_fixer.py

![](/screenshot/core_function_fixer.png)

3. Use **/plugin/string_function_detector.py** to fix the function name by known strings in the binary. Once you fixed the malware/binary, please look at the function names, the longer function name means more useful or suspicious in the malware/binary. And you can also identify some utilities from the fixed names.

> Open IDA Pro -> File -> Script file -> choose /plugin/string_function_detector.py

![](/screenshot/string_function_detector.png)

## Limitation

The fixer is worked based on the known strings and hashes, if the rust binary wipes its strings during the compile time (E.g. Obfuscated or encrypted.) the fixer might not be worked.