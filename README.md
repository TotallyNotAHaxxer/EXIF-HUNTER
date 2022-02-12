```
 ______     __  __     __     ______   __  __     __  __     __   __     ______   ______     ______    
/\  ___\   /\_\_\_\   /\ \   /\  ___\ /\ \_\ \   /\ \/\ \   /\ "-.\ \   /\__  _\ /\  ___\   /\  == \   
\ \  __\   \/_/\_\/_  \ \ \  \ \  __\ \ \  __ \  \ \ \_\ \  \ \ \-.  \  \/_/\ \/ \ \  __\   \ \  __<   
 \ \_____\   /\_\/\_\  \ \_\  \ \_\    \ \_\ \_\  \ \_____\  \ \_\\"\_\    \ \_\  \ \_____\  \ \_\ \_\ 
  \/_____/   \/_/\/_/   \/_/   \/_/     \/_/\/_/   \/_____/   \/_/ \/_/     \/_/   \/_____/   \/_/ /_/ 
                                    Author -> ArkAngeL43

                     Exif Hunter: A Framework for image injection with Go and Perl
-------------------------------------------------------------------------------------------------------------
```

This is a simple script that is still in beta mode rn, the concept of this script is to just inject an image, find data on the image and inject it with certian data. The idea of this script was to improove a image injection module to give the user more information like the Offset of the IEND tags. there isnt much to this right now as this script is still in beta (v .1) and will be further looked into and be another project to finish!

```
Requirements -> Perl, go, 
```

```
Installs: - git clone https://github.com/ArkAngeL43/EXIF-HUNTER.git ; cd EXIT-HUNTER ; chmod +x ./install.sh ; ./install.sh
```

# options

```
Example Usage: /tmp/go-build3698929840/b001/exe/main -i in.png -o out.png --inject --offset 0x85258 --payload 1234
Example Encode Usage: /tmp/go-build3698929840/b001/exe/main -i in.png -o encode.png --inject --offset 0x85258 --payload 1234 --encode --key secret
Example Decode Usage: /tmp/go-build3698929840/b001/exe/main -i encode.png -o decode.png --offset 0x85258 --decode --key secret
Flags: /tmp/go-build3698929840/b001/exe/main {OPTION]...
  -i, --input string           Path to the original image file
  -o, --output string          Path to output the new image file
  -m, --meta                   Display the actual image meta details
  -s, --suppress               Suppress the chunk hex data (can be large)
      --offset string          The offset location to initiate data injection
      --inject                 Enable this to inject data at the offset location specified
      --payload string         Payload is data that will be read as a byte stream
      --type string[="rNDm"]   Type is the name of the Chunk header to inject (default "rNDm")
      --key string             The enryption key for payload
      --encode                 XOR encode the payload
      --decode                 XOR decode the payload
      --compare                Call a function to compare the previous IEND OFFSET to the new IEND OFFSET of the injected image (default true)
```

# Example outputs

<h3> Example of using go run main.go -i image.png --meta tags </h3>

```
 [INFO]   12:03:31   -> File Exists 	 img/main.png
 [INFO]   12:03:31   -> Opening file   	 img/main.png
 [INFO]   12:03:31   ->  img/main.png 	 Successfully opened

=== EXIF Table ===
┌─────────────╥───────────────────┬─────────────────────────┐
│ Data Number ║ Data              │After DATA EXIF          │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileType           │           PNG           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║MIMEType           │        image/png        │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ColorType          │     RGB with Alpha      │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ImageHeight        │           633           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ExifToolVersion    │          12.30          │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileInodeChangeDate│2022:02:10 15:40:16-05:00│
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Compression        │     Deflate/Inflate     │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Interlace          │      Noninterlaced      │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileSize           │         533 KiB         │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Directory          │           img           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ImageSize          │         741x633         │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileAccessDate     │2022:02:10 15:08:38-05:00│
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Megapixels         │          0.469          │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║Filter             │        Adaptive         │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileName           │        main.png         │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FilePermissions    │       -rw-r--r--        │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║BitDepth           │            8            │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileModifyDate     │2022:02:10 15:08:38-05:00│
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║ImageWidth         │           741           │
├─────────────╫───────────────────┼─────────────────────────┤
│1            ║FileTypeExtension  │           png           │
└─────────────╨───────────────────┴─────────────────────────┘
=== END of EXIF Table === 


 [INFO]   12:03:31   ->  [80 78 71]  Came back as a VALID HEADER

Would you like to locate just the IEND chunk? and injectable offset <y/n > 
 
[!] If you wanted to you can type -> chunk_finish to get all data chunks in the image as well
y

 Found IEND chunk -> 
 +---------------+-------------------------------+--------------------------------------+
|    Chunk Type |    Location Injectable OFFSET |    Injectable OFFSET HEX Translation |
+===============+===============================+======================================+
|          IEND |                        545368 |                              0x85258 |
+---------------+-------------------------------+--------------------------------------+

 [INFO]   12:03:31   -> This data seems to be the actuall injectable point, would you like to hex dump the file to be sure this IEND tag is at the direct OFFSET of  ->  545368
 
 [INFO]   12:03:31 Yes/NO > 

```
